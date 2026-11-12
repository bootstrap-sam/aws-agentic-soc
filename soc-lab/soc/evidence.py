"""Read WAF logs and turn them into evidence the agents can see.

Everything copied out of an HTTP request (URI, query, headers) is attacker-controlled.
It is cleaned, truncated, and kept under an `untrusted` key so prompts can say exactly
which fields are data. Counts, actions and rule names come from the WAF, not the attacker.
"""
from __future__ import annotations

import json
import re
import urllib.request
from collections import Counter, defaultdict

from soc import config

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩]")


def clean(value, limit: int = 120) -> str:
    s = _CTRL.sub(" ", str(value))
    return s if len(s) <= limit else s[:limit] + "…[truncated]"


def fetch_events(since_ms: int = 0) -> list[dict]:
    with urllib.request.urlopen(f"{config.WAF_URL}/__waf/logs", timeout=10) as r:
        events = json.load(r)
    return [e for e in events if e.get("timestamp", 0) >= since_ms]


def waf_status() -> dict:
    with urllib.request.urlopen(f"{config.WAF_URL}/__waf/status", timeout=10) as r:
        return json.load(r)


def _header(e: dict, name: str) -> str:
    for h in e["httpRequest"].get("headers", []):
        if h["name"].lower() == name:
            return h["value"]
    return ""


def _request_line(e: dict) -> str:
    r = e["httpRequest"]
    return f"{r.get('httpMethod', '?')} {r.get('uri', '')}" + (f"?{r['args']}" if r.get("args") else "")


def event_view(e: dict) -> dict:
    return {
        "time_ms": e["timestamp"],
        "action": e["action"],
        "terminating_rule": e["terminatingRuleId"],
        "counted_rules": list(e.get("nonTerminatingMatchingRules") or []),
        "labels": list(e.get("labels") or []),
        "untrusted": {"request": clean(_request_line(e), 160), "user_agent": clean(_header(e, "user-agent"), 160)},
    }


def summarize(events: list[dict]) -> dict[str, dict]:
    """One summary per client IP. Keys are IPs exactly as the WAF saw them."""
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_ip[e["httpRequest"]["clientIp"]].append(e)

    out = {}
    for ip, evs in by_ip.items():
        actions = Counter(e["action"] for e in evs)
        rules = Counter(e["terminatingRuleId"] for e in evs if e["action"] != "ALLOW")
        counted = Counter(r for e in evs for r in (e.get("nonTerminatingMatchingRules") or []))
        uris = list(dict.fromkeys(clean(_request_line(e), 100) for e in evs))
        uas = list(dict.fromkeys(clean(_header(e, "user-agent"), 120) for e in evs))
        out[ip] = {
            "ip": ip,
            "country": evs[0]["httpRequest"].get("country"),
            "requests": len(evs),
            "actions": dict(actions),
            "blocking_rules": dict(rules),
            "counted_rules": dict(counted),
            "labels": sorted({lbl for e in evs for lbl in (e.get("labels") or [])}),
            "first_seen_ms": min(e["timestamp"] for e in evs),
            "last_seen_ms": max(e["timestamp"] for e in evs),
            "untrusted": {"sample_requests": uris[:6], "user_agents": uas[:3]},
        }
    return out


def has_waf_evidence(summary: dict) -> bool:
    """Independent signal: the WAF itself blocked or counted something from this IP."""
    return bool(summary["blocking_rules"] or summary["counted_rules"])


def ip_events(events: list[dict], ip: str, limit: int = 25) -> list[dict]:
    return [event_view(e) for e in events if e["httpRequest"]["clientIp"] == ip][-limit:]
