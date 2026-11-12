"""The gate between what an agent recommends and what actually happens.

Agents never get a write tool. A block only happens if this code agrees, so a
prompt-injected or confused model can at worst recommend something that is refused.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from soc import config
from soc.evidence import has_waf_evidence


@dataclass
class Decision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


def _net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def protected_reason(ip: str, allowlisted_cidrs: list[str]) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid IP address"
    for cidr in config.PROTECTED_CIDRS:
        if addr in _net(cidr):
            return f"inside protected range {cidr}"
    for cidr in allowlisted_cidrs:
        if addr in _net(cidr):
            return f"on a WAF allowlist IP set ({cidr})"
    return None


def already_blocked(ip: str, blocklist_cidrs: list[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in _net(c) for c in blocklist_cidrs)


def check_block(finding: dict, investigated_ip: str, observed: dict[str, dict],
                allowlisted_cidrs: list[str], blocklist_cidrs: list[str], blocks_so_far: int) -> Decision:
    if finding.get("recommended_action") != "block":
        return Decision(False, ["agent did not recommend a block"])
    ip = str(finding.get("ip", "")).strip()
    reasons = []
    if ip != investigated_ip:
        reasons.append(f"finding names {ip!r}, but the case was about {investigated_ip}")
    if ip not in observed:
        reasons.append("IP never appeared as a client in the WAF logs")
    elif not has_waf_evidence(observed[ip]):
        reasons.append("no WAF rule blocked or counted this IP: no independent evidence")
    if (why := protected_reason(ip, allowlisted_cidrs)):
        reasons.append(f"protected: {why}")
    elif ip in observed and already_blocked(ip, blocklist_cidrs):
        reasons.append("already covered by the blocklist")
    if blocks_so_far >= config.MAX_BLOCKS_PER_RUN:
        reasons.append(f"block budget for this run used up ({config.MAX_BLOCKS_PER_RUN})")
    return Decision(not reasons, reasons)


def auto_approvable(finding: dict) -> bool:
    try:
        conf = float(finding.get("confidence", 0))
    except (TypeError, ValueError):
        conf = 0.0
    return finding.get("verdict") == "malicious" and conf >= config.AUTO_APPROVE_MIN_CONFIDENCE
