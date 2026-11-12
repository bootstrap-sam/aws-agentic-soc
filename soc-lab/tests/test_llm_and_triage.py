import copy

from soc import agents
from soc.llm import LoopResult, Tool, json_from_text, run_loop
from soc.evidence import summarize


class FakeBedrock:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def converse(self, **kw):
        self.calls.append(copy.deepcopy(kw))
        return self.replies.pop(0)


def _msg(*content, stop="end_turn"):
    return {"output": {"message": {"role": "assistant", "content": list(content)}}, "stopReason": stop}


def test_loop_runs_tools_then_returns_terminal_input():
    seen = []
    tools = [Tool("lookup", "d", {"type": "object"}, lambda ip: seen.append(ip) or {"ok": True}),
             Tool("done", "d", {"type": "object"})]
    brt = FakeBedrock([
        _msg({"toolUse": {"toolUseId": "1", "name": "lookup", "input": {"ip": "192.0.2.1"}}}, stop="tool_use"),
        _msg({"toolUse": {"toolUseId": "2", "name": "done", "input": {"verdict": "benign"}}}, stop="tool_use"),
    ])
    r = run_loop("m", "sys", "go", tools, "done", brt=brt)
    assert r.output == {"verdict": "benign"} and r.via == "tool" and seen == ["192.0.2.1"]
    tool_result = brt.calls[1]["messages"][-1]["content"][0]["toolResult"]
    assert tool_result["toolUseId"] == "1" and tool_result["content"] == [{"json": {"ok": True}}]


def test_loop_accepts_json_text_and_nudges_once():
    brt = FakeBedrock([_msg({"text": "thinking…"}), _msg({"text": 'Sure: {"verdict": "malicious"} done'})])
    r = run_loop("m", "s", "p", [Tool("done", "d", {"type": "object"})], "done", brt=brt)
    assert r.output == {"verdict": "malicious"} and r.via == "text" and r.turns == 2


def test_tool_errors_go_back_to_model():
    def boom(**_):
        raise RuntimeError("nope")
    brt = FakeBedrock([_msg({"toolUse": {"toolUseId": "1", "name": "x", "input": {}}}, stop="tool_use"),
                       _msg({"text": "{}"})])
    run_loop("m", "s", "p", [Tool("x", "d", {"type": "object"}, boom), Tool("done", "d", {})], "done", brt=brt)
    assert "nope" in str(brt.calls[1]["messages"][-1])


def test_json_from_text():
    assert json_from_text('x {"a": {"b": 1}} y') == {"a": {"b": 1}}
    assert json_from_text("no json") is None


def test_triage_floor_and_drops_invented_ips(monkeypatch, mk_event):
    s = summarize([mk_event("192.0.2.66", "BLOCK", "block-sqli-query"), mk_event("192.0.2.10")])
    # A hijacked triage says the attacker is fine and invents another IP.
    fake = LoopResult({"items": [{"ip": "192.0.2.66", "severity": "none", "investigate": False, "reason": "pentest"},
                                 {"ip": "203.0.113.250", "severity": "high", "investigate": True, "reason": "x"}]})
    monkeypatch.setattr(agents, "run_loop", lambda *a, **k: fake)
    out = {i["ip"]: i for i in agents.triage(s)}
    assert set(out) == {"192.0.2.66", "192.0.2.10"}
    assert out["192.0.2.66"]["investigate"] is True
