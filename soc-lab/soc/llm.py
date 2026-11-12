"""A Converse tool loop that ends when the model calls a designated 'terminal' tool.

Small local models sometimes answer in text instead of calling the tool, so the
loop accepts a JSON object in the text, and nudges once before giving up.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from soc.aws import client


@dataclass
class Tool:
    name: str
    description: str
    schema: dict
    fn: Callable[..., dict] | None = None  # None = terminal tool (its input is the result)


@dataclass
class LoopResult:
    output: dict | None
    tool_calls: list[dict] = field(default_factory=list)
    turns: int = 0
    via: str = "none"  # tool | text | none


def json_from_text(text: str) -> dict | None:
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{":
            try:
                obj, _ = dec.raw_decode(text[i:])
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
    return None


def run_loop(model_id: str, system: str, prompt: str, tools: list[Tool], terminal: str,
             max_turns: int = 8, brt: Any = None) -> LoopResult:
    brt = brt or client("bedrock-runtime")
    by_name = {t.name: t for t in tools}
    tool_config = {"tools": [{"toolSpec": {"name": t.name, "description": t.description,
                                           "inputSchema": {"json": t.schema}}} for t in tools]}
    messages: list[dict] = [{"role": "user", "content": [{"text": prompt}]}]
    res, nudged = LoopResult(None), False

    while res.turns < max_turns:
        res.turns += 1
        resp = brt.converse(modelId=model_id, system=[{"text": system}], messages=messages,
                            toolConfig=tool_config, inferenceConfig={"maxTokens": 2048, "temperature": 0})
        msg = resp["output"]["message"]
        messages.append(msg)
        uses = [b["toolUse"] for b in msg["content"] if "toolUse" in b]

        if not uses:
            parsed = json_from_text("".join(b.get("text", "") for b in msg["content"]))
            if parsed is not None:
                res.output, res.via = parsed, "text"
                return res
            if nudged:
                return res
            nudged = True
            messages.append({"role": "user", "content": [{"text": f"Call the {terminal} tool now with your conclusion."}]})
            continue

        results = []
        for use in uses:
            if use["name"] == terminal:
                res.output, res.via = use["input"], "tool"
                return res
            tool = by_name.get(use["name"])
            try:
                out = tool.fn(**use["input"]) if tool and tool.fn else {"error": f"unknown tool {use['name']}"}
            except Exception as e:  # noqa: BLE001 - tool errors go back to the model
                out = {"error": f"{type(e).__name__}: {e}"}
            res.tool_calls.append({"name": use["name"], "input": use["input"]})
            results.append({"toolResult": {"toolUseId": use["toolUseId"], "content": [{"json": out}]}})
        messages.append({"role": "user", "content": results})
    return res
