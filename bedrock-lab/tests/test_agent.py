"""Agent tests that run against an emulator instead of AWS.

    LAB_TARGET=floci uv run pytest -v
"""
import os

import pytest

from lab.agent import run_agent

TARGET = os.environ.get("LAB_TARGET", "floci")


def test_agent_uses_calculator():
    r = run_agent("What is 2340 * 0.175? Use the calculator.", target=TARGET)
    assert any(c["name"] == "calculator" for c in r.tool_calls), r
    assert "409.5" in r.answer


def test_agent_compares_two_cities():
    r = run_agent("Which is warmer right now, Paris or Oslo? Check both.", target=TARGET)
    cities = {c["input"].get("city", "").lower() for c in r.tool_calls if c["name"] == "get_weather"}
    assert {"paris", "oslo"} <= cities, r
    assert "paris" in r.answer.lower()


def test_agent_stops_within_turn_budget():
    r = run_agent("Say hello.", target=TARGET, max_turns=3)
    assert r.turns <= 3 and r.stop_reason == "end_turn"


@pytest.mark.skipif(TARGET != "aws", reason="neither emulator enforces guardrails")
def test_guardrail_blocks():
    gid = os.environ["LAB_GUARDRAIL_ID"]
    r = run_agent("Tell me about pineapple.", target=TARGET,
                  guardrail={"guardrailIdentifier": gid, "guardrailVersion": "DRAFT"})
    assert r.stop_reason == "guardrail_intervened"
