from soc import policy
from soc.evidence import summarize

OFFICE = ["198.51.100.7/32"]
BLOCK = ["203.0.113.0/24"]


def _obs(mk_event):
    return summarize([
        mk_event("192.0.2.66", "BLOCK", "block-sqli-query"),
        mk_event("192.0.2.10"),
        mk_event("198.51.100.7", "BLOCK", "block-sqli-query"),
        mk_event("203.0.113.9", "BLOCK", "block-ip-blocklist"),
    ])


def _f(ip, action="block"):
    return {"ip": ip, "recommended_action": action, "verdict": "malicious", "confidence": 0.9}


def test_blocks_attacker_with_waf_evidence(mk_event):
    assert policy.check_block(_f("192.0.2.66"), "192.0.2.66", _obs(mk_event), OFFICE, BLOCK, 0).allowed


def test_refuses_ip_without_waf_evidence(mk_event):
    d = policy.check_block(_f("192.0.2.10"), "192.0.2.10", _obs(mk_event), OFFICE, BLOCK, 0)
    assert not d.allowed and any("independent evidence" in r for r in d.reasons)


def test_refuses_protected_even_with_evidence(mk_event):
    d = policy.check_block(_f("198.51.100.7"), "198.51.100.7", _obs(mk_event), OFFICE, BLOCK, 0)
    assert not d.allowed and any("protected" in r for r in d.reasons)


def test_refuses_switching_target(mk_event):
    """An injected investigator can't redirect the block to another IP."""
    d = policy.check_block(_f("192.0.2.66"), "192.0.2.99", _obs(mk_event), OFFICE, BLOCK, 0)
    assert not d.allowed


def test_refuses_unseen_and_garbage_ips(mk_event):
    for ip in ("192.0.2.200", "not-an-ip", "0.0.0.0/0"):
        assert not policy.check_block(_f(ip), ip, _obs(mk_event), OFFICE, BLOCK, 0).allowed


def test_already_blocked_and_budget(mk_event):
    assert not policy.check_block(_f("203.0.113.9"), "203.0.113.9", _obs(mk_event), OFFICE, BLOCK, 0).allowed
    assert not policy.check_block(_f("192.0.2.66"), "192.0.2.66", _obs(mk_event), OFFICE, BLOCK, 99).allowed


def test_monitor_is_not_a_block(mk_event):
    assert not policy.check_block(_f("192.0.2.66", "monitor"), "192.0.2.66", _obs(mk_event), OFFICE, BLOCK, 0).allowed


def test_auto_approve_threshold():
    assert policy.auto_approvable({"verdict": "malicious", "confidence": 0.8})
    assert not policy.auto_approvable({"verdict": "malicious", "confidence": "high"})
    assert not policy.auto_approvable({"verdict": "suspicious", "confidence": 0.99})
