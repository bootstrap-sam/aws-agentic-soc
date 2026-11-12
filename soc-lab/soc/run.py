"""Run the SOC pipeline once over recent WAF traffic.

    uv run python -m soc.run                    # ask before every block
    uv run python -m soc.run --mode dry-run     # recommend only
    uv run python -m soc.run --mode auto        # block when policy allows and confidence is high
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

from soc import agents, cases, config, evidence, policy, respond


def _approve(mode: str, finding: dict, log) -> tuple[bool, str]:
    if mode == "dry-run":
        return False, "dry-run"
    if mode == "auto":
        ok = policy.auto_approvable(finding)
        return ok, "auto-approved" if ok else "auto: verdict/confidence below threshold"
    if not sys.stdin.isatty():
        return False, "no terminal to ask on; declined"
    log(f"\n  >> Block {finding['ip']}?  {finding.get('verdict')} ({finding.get('confidence')}): {finding.get('summary')}")
    return input("     approve? [y/N] ").strip().lower() == "y", "human"


def run_pipeline(since_ms: int, mode: str = "ask", log=print) -> dict:
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    events = evidence.fetch_events(since_ms)
    summaries = evidence.summarize(events)
    report = {"run_id": run_id, "mode": mode, "events": len(events), "cases": []}
    if not summaries:
        log("no WAF events in the window")
        return report

    cases.ensure_table()
    allowlisted = [c for s in config.ALLOWLIST_IP_SETS for c in respond.ip_set_addresses(s)]
    blocklist = respond.ip_set_addresses(config.BLOCKLIST_IP_SET)
    tools = agents.investigation_tools(events, allowlisted)

    log(f"[{run_id}] {len(events)} events from {len(summaries)} IPs, triaging…")
    triaged = agents.triage(summaries)
    blocks = 0
    for item in triaged:
        ip = item["ip"]
        case = {"case_id": f"{run_id}/{ip}", "ip": ip, "triage": item, "summary": summaries[ip]}
        if not item.get("investigate"):
            case["outcome"] = "closed-at-triage"
            log(f"  {ip:<16} {item.get('severity', '?'):<6} closed at triage: {item.get('reason', '')[:70]}")
        else:
            finding, trace = agents.investigate(ip, summaries[ip], item, tools)
            case |= {"finding": finding, "trace": trace}
            decision = policy.check_block(finding, ip, summaries, allowlisted, blocklist, blocks)
            case["policy"] = {"allowed": decision.allowed, "reasons": decision.reasons}
            if finding.get("recommended_action") != "block":
                case["outcome"] = finding.get("recommended_action", "none")
            elif not decision.allowed:
                case["outcome"] = "block-refused-by-policy"
            else:
                approved, how = _approve(mode, finding, log)
                case["approval"] = how
                if approved:
                    respond.block_ip(ip)
                    blocks += 1
                    case["verified"] = respond.verify_blocked(ip)
                    case["outcome"] = "blocked" if case["verified"] else "blocked-unverified"
                else:
                    case["outcome"] = "block-not-approved"
            extra = f" [{'; '.join(decision.reasons)}]" if case["outcome"] == "block-refused-by-policy" else ""
            log(f"  {ip:<16} {item.get('severity', '?'):<6} {finding.get('verdict', '?'):<10} "
                f"-> {case['outcome']}{extra}  ({trace['turns']} turns)")
        cases.put_case(case)
        report["cases"].append(case)

    out = Path(__file__).resolve().parent.parent / "reports" / f"{run_id}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    log(f"report: {out}")
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--since-minutes", type=float, default=15)
    p.add_argument("--mode", choices=["ask", "auto", "dry-run"], default="ask")
    a = p.parse_args()
    run_pipeline(int((time.time() - a.since_minutes * 60) * 1000), a.mode)


if __name__ == "__main__":
    main()
