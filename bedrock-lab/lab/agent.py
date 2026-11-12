"""A minimal custom agent: a Converse tool-use loop with local Python tools.

This is the code you'd actually ship; the emulators let you run it without AWS.

    uv run python -m lab.agent --target floci "What is 17.5% of 2340, and is it warmer in Paris or Oslo?"
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from typing import Any, Callable

from lab.targets import TARGETS, client

DEFAULT_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
SYSTEM = "You are a helpful assistant. Use the tools when they help. Be brief."


def calculator(expression: str) -> dict:
    allowed = set("0123456789+-*/(). %")
    if not set(expression) <= allowed:
        return {"error": "only arithmetic is allowed"}
    return {"result": eval(expression.replace("%", "/100"), {"__builtins__": {}})}  # noqa: S307


def get_weather(city: str) -> dict:
    fake = {"paris": 14, "oslo": 3, "london": 11}
    return {"city": city, "temp_c": fake.get(city.lower(), 20)}


TOOLS: dict[str, tuple[Callable[..., dict], dict]] = {
    "calculator": (calculator, {
        "description": "Evaluate an arithmetic expression, e.g. '2340 * 0.175'.",
        "inputSchema": {"json": {"type": "object", "properties": {"expression": {"type": "string"}},
                                 "required": ["expression"]}},
    }),
    "get_weather": (get_weather, {
        "description": "Current temperature in Celsius for a city.",
        "inputSchema": {"json": {"type": "object", "properties": {"city": {"type": "string"}},
                                 "required": ["city"]}},
    }),
}


@dataclass
class Run:
    answer: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    turns: int = 0
    stop_reason: str = ""


def run_agent(prompt: str, target: str = "floci", model_id: str = DEFAULT_MODEL,
              max_turns: int = 8, guardrail: dict | None = None) -> Run:
    brt = client(target, "bedrock-runtime")
    tool_config = {"tools": [{"toolSpec": {"name": n, **spec}} for n, (_, spec) in TOOLS.items()]}
    messages: list[dict] = [{"role": "user", "content": [{"text": prompt}]}]
    run = Run()

    while run.turns < max_turns:
        run.turns += 1
        kwargs = dict(modelId=model_id, system=[{"text": SYSTEM}], messages=messages,
                      toolConfig=tool_config, inferenceConfig={"maxTokens": 1024, "temperature": 0})
        if guardrail:
            kwargs["guardrailConfig"] = guardrail
        resp = brt.converse(**kwargs)
        msg = resp["output"]["message"]
        messages.append(msg)
        run.stop_reason = resp["stopReason"]

        if run.stop_reason != "tool_use":
            run.answer = "".join(b.get("text", "") for b in msg["content"])
            return run

        results = []
        for block in msg["content"]:
            if "toolUse" not in block:
                continue
            use = block["toolUse"]
            fn = TOOLS.get(use["name"], (None,))[0]
            out = fn(**use["input"]) if fn else {"error": f"unknown tool {use['name']}"}
            run.tool_calls.append({"name": use["name"], "input": use["input"], "output": out})
            results.append({"toolResult": {"toolUseId": use["toolUseId"], "content": [{"json": out}]}})
        messages.append({"role": "user", "content": results})

    run.answer = "(max turns reached)"
    return run


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("prompt")
    p.add_argument("--target", choices=TARGETS, default="floci")
    p.add_argument("--model", default=DEFAULT_MODEL)
    a = p.parse_args()
    r = run_agent(a.prompt, a.target, a.model)
    for c in r.tool_calls:
        print(f"  tool {c['name']}({json.dumps(c['input'])}) -> {json.dumps(c['output'])}")
    print(f"[{r.turns} turns, stop={r.stop_reason}]\n{r.answer}")
