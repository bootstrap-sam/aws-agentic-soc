"""Probe which Bedrock features each emulator really implements, for agent testing.

    uv run python -m lab.probe                    # both emulators, side by side
    uv run python -m lab.probe --targets floci

Each check is graded:
  REAL   behaves like AWS (a real completion, a tool call, a guardrail that blocks)
  STUB   answers in the right shape but the content is canned / not acted on
  NONE   501 / unknown operation / service not served
  ERR    something else went wrong (shown in the detail column)
"""
from __future__ import annotations

import argparse
import json
import time
import uuid
from pathlib import Path

from botocore.exceptions import ClientError, EndpointConnectionError, SSLError

from lab.agent import DEFAULT_MODEL, TOOLS
from lab.targets import client

ROLE = "arn:aws:iam::000000000000:role/lab-agent-role"
CHECKS = []


def check(name):
    def deco(fn):
        CHECKS.append((name, fn))
        return fn
    return deco


class Ctx(dict):
    """Per-target scratch space so later checks can reuse ids made by earlier ones."""


# ---------------------------------------------------------------- bedrock (control plane)

@check("ListFoundationModels")
def _(t, ctx):
    ms = client(t, "bedrock").list_foundation_models()["modelSummaries"]
    return ("REAL" if ms else "STUB"), f"{len(ms)} models"


@check("CreateGuardrail (word filter)")
def _(t, ctx):
    g = client(t, "bedrock").create_guardrail(
        name=f"lab-{uuid.uuid4().hex[:6]}",
        blockedInputMessaging="BLOCKED-IN", blockedOutputsMessaging="BLOCKED-OUT",
        wordPolicyConfig={"wordsConfig": [{"text": "pineapple"}]},
    )
    ctx["guardrail"] = {"guardrailIdentifier": g["guardrailId"], "guardrailVersion": "DRAFT"}
    return "REAL", g["guardrailId"]


# ---------------------------------------------------------------- bedrock-runtime

def _converse(t, **kw):
    return client(t, "bedrock-runtime").converse(
        modelId=DEFAULT_MODEL, inferenceConfig={"maxTokens": 256, "temperature": 0}, **kw)


@check("Converse (real completion?)")
def _(t, ctx):
    r = _converse(t, messages=[{"role": "user", "content": [{"text": "What is 7*6? Reply with only the number."}]}])
    text = "".join(b.get("text", "") for b in r["output"]["message"]["content"])
    return ("REAL" if "42" in text else "STUB"), text.strip()[:60]


@check("Converse + toolConfig (tool_use)")
def _(t, ctx):
    tools = [{"toolSpec": {"name": n, **s}} for n, (_, s) in TOOLS.items()]
    r = _converse(t, toolConfig={"tools": tools},
                  messages=[{"role": "user", "content": [{"text": "What's the weather in Oslo? Use the tool."}]}])
    uses = [b["toolUse"] for b in r["output"]["message"]["content"] if "toolUse" in b]
    if not uses:
        return "STUB", f"stopReason={r['stopReason']}"
    call = f"{uses[0]['name']}({json.dumps(uses[0]['input'])})"
    # A stub can fabricate a tool call from the schema; a model picks the right tool + args.
    sensible = uses[0]["name"] == "get_weather" and "oslo" in json.dumps(uses[0]["input"]).lower()
    return ("REAL" if sensible else "STUB"), call


@check("ConverseStream")
def _(t, ctx):
    r = client(t, "bedrock-runtime").converse_stream(
        modelId=DEFAULT_MODEL,
        messages=[{"role": "user", "content": [{"text": "What is 7*6? Reply with only the number."}]}])
    events, text = [], ""
    for e in r["stream"]:
        events.append(next(iter(e)))
        text += e.get("contentBlockDelta", {}).get("delta", {}).get("text", "")
    if "contentBlockDelta" not in events or "messageStop" not in events:
        return "ERR", f"malformed stream: {events[:4]}"
    return ("REAL" if "42" in text else "STUB"), f"{len(events)} events: {text.strip()[:30]}"


@check("InvokeModel (Anthropic body)")
def _(t, ctx):
    body = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 64,
            "messages": [{"role": "user", "content": "What is 7*6? Reply with only the number."}]}
    r = client(t, "bedrock-runtime").invoke_model(modelId=DEFAULT_MODEL, body=json.dumps(body))
    out = r["body"].read().decode()
    return ("REAL" if "42" in out else "STUB"), out[:60]


@check("Converse + guardrailConfig (blocks?)")
def _(t, ctx):
    if "guardrail" not in ctx:
        return "NONE", "no guardrail created"
    r = _converse(t, guardrailConfig={**ctx["guardrail"], "trace": "enabled"},
                  messages=[{"role": "user", "content": [{"text": "Tell me about pineapple."}]}])
    if r["stopReason"] == "guardrail_intervened":
        return "REAL", "guardrail_intervened"
    return "STUB", f"not enforced (stopReason={r['stopReason']})"


@check("ApplyGuardrail")
def _(t, ctx):
    if "guardrail" not in ctx:
        return "NONE", "no guardrail created"
    r = client(t, "bedrock-runtime").apply_guardrail(
        **ctx["guardrail"], source="INPUT", content=[{"text": {"text": "pineapple pizza"}}])
    return ("REAL" if r["action"] == "GUARDRAIL_INTERVENED" else "STUB"), r["action"]


# ---------------------------------------------------------------- Bedrock Agents (managed)

@check("bedrock-agent CreateAgent + action group")
def _(t, ctx):
    ba = client(t, "bedrock-agent")
    a = ba.create_agent(agentName=f"lab-{uuid.uuid4().hex[:6]}", foundationModel=DEFAULT_MODEL,
                        agentResourceRoleArn=ROLE,
                        instruction="You answer weather questions using the get_weather action. Be brief.")
    aid = a["agent"]["agentId"]
    ba.create_agent_action_group(
        agentId=aid, agentVersion="DRAFT", actionGroupName="weather",
        actionGroupExecutor={"customControl": "RETURN_CONTROL"},
        functionSchema={"functions": [{"name": "get_weather",
                                       "parameters": {"city": {"type": "string", "required": True}}}]})
    ba.prepare_agent(agentId=aid)
    alias = ba.create_agent_alias(agentId=aid, agentAliasName="live")["agentAlias"]["agentAliasId"]
    ctx["agent"] = (aid, alias)
    return "REAL", f"agent {aid} alias {alias}"


@check("bedrock-agent-runtime InvokeAgent")
def _(t, ctx):
    aid, alias = ctx.get("agent", ("AAAAAAAAAA", "TSTALIASID"))
    r = client(t, "bedrock-agent-runtime").invoke_agent(
        agentId=aid, agentAliasId=alias, sessionId=uuid.uuid4().hex, inputText="Weather in Oslo?")
    kinds = [next(iter(e)) for e in r["completion"]]
    if "returnControl" in kinds:
        return "REAL", "returnControl (agent asked for the tool)"
    return "STUB", f"events={kinds[:4]}"


@check("bedrock-agent-runtime Retrieve (KB)")
def _(t, ctx):
    r = client(t, "bedrock-agent-runtime").retrieve(
        knowledgeBaseId="KB12345678", retrievalQuery={"text": "hello"})
    return "STUB", f"{len(r.get('retrievalResults', []))} results"


# ---------------------------------------------------------------- AgentCore

@check("agentcore-control ListAgentRuntimes")
def _(t, ctx):
    r = client(t, "bedrock-agentcore-control").list_agent_runtimes()
    return "REAL", f"{len(r.get('agentRuntimes', []))} runtimes"


@check("agentcore InvokeAgentRuntime")
def _(t, ctx):
    arn = "arn:aws:bedrock-agentcore:us-east-1:000000000000:runtime/lab-agent-abc123"
    r = client(t, "bedrock-agentcore").invoke_agent_runtime(
        agentRuntimeArn=arn, runtimeSessionId=uuid.uuid4().hex + "x",
        payload=json.dumps({"prompt": "What is 7*6?"}).encode())
    out = r["response"].read().decode()
    # Neither emulator runs your container; any answer is canned.
    return "STUB", out[:60]


# ---------------------------------------------------------------- runner

def grade(fn, t, ctx):
    t0 = time.monotonic()
    try:
        status, detail = fn(t, ctx)
    except ClientError as e:
        code = e.response["Error"].get("Code", "")
        http = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        msg = e.response["Error"].get("Message", "")[:70]
        if http in (404, 501) and ("NotImplemented" in code or "Unsupported" in code or "UnknownOperation" in code
                                   or http == 501 or not code):
            status, detail = "NONE", f"{http} {code}"
        elif code in ("ResourceNotFoundException", "ValidationException"):
            # The op is served (it validated our request), just not with this data.
            status, detail = "STUB", f"served: {code}: {msg}"
        else:
            status, detail = "ERR", f"{http} {code}: {msg}"
    except (EndpointConnectionError, SSLError) as e:
        status, detail = "ERR", f"unreachable: {type(e).__name__}"
    except Exception as e:  # noqa: BLE001
        status, detail = "ERR", f"{type(e).__name__}: {str(e)[:70]}"
    return {"status": status, "detail": detail, "ms": int((time.monotonic() - t0) * 1000)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--targets", nargs="+", default=["floci", "aws-emulator"])
    p.add_argument("--out", default="results/probe.json")
    a = p.parse_args()

    results = {}
    for t in a.targets:
        ctx = Ctx()
        results[t] = {name: grade(fn, t, ctx) for name, fn in CHECKS}

    w = max(len(n) for n, _ in CHECKS)
    print(f"{'check':<{w}}  " + "  ".join(f"{t:<44}" for t in a.targets))
    for name, _ in CHECKS:
        cells = [f"{results[t][name]['status']:<5} {results[t][name]['detail'][:38]:<38}" for t in a.targets]
        print(f"{name:<{w}}  " + "  ".join(cells))

    Path(a.out).parent.mkdir(exist_ok=True)
    Path(a.out).write_text(json.dumps(results, indent=2))
    print(f"\nfull results: {a.out}")


if __name__ == "__main__":
    main()
