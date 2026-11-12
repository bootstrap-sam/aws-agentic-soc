"""The only code that changes anything: add a /32 to the WAF blocklist, then prove it took."""
from __future__ import annotations

import ipaddress
import time
import urllib.error
import urllib.request

from soc import config
from soc.aws import client


def _find_ip_set(name: str) -> dict:
    waf = client("wafv2")
    for s in waf.list_ip_sets(Scope="REGIONAL")["IPSets"]:
        if s["Name"] == name:
            return waf.get_ip_set(Name=name, Scope="REGIONAL", Id=s["Id"]) | {"Id": s["Id"]}
    raise LookupError(f"IP set {name!r} not found (did you terraform apply the network lab?)")


def ip_set_addresses(name: str) -> list[str]:
    return list(_find_ip_set(name)["IPSet"]["Addresses"])


def _host_cidr(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    return f"{a}/{32 if a.version == 4 else 128}"


def _write(name: str, addresses: list[str]) -> None:
    cur = _find_ip_set(name)
    client("wafv2").update_ip_set(Name=name, Scope="REGIONAL", Id=cur["Id"],
                                  Addresses=addresses, LockToken=cur["LockToken"])


def block_ip(ip: str) -> None:
    addrs = ip_set_addresses(config.BLOCKLIST_IP_SET)
    if _host_cidr(ip) not in addrs:
        _write(config.BLOCKLIST_IP_SET, addrs + [_host_cidr(ip)])


def unblock_ips(ips: list[str]) -> None:
    """Used by the eval to put the lab back the way it was."""
    drop = {_host_cidr(i) for i in ips}
    addrs = ip_set_addresses(config.BLOCKLIST_IP_SET)
    if drop & set(addrs):
        _write(config.BLOCKLIST_IP_SET, [a for a in addrs if a not in drop])


def verify_blocked(ip: str, timeout_s: float = 20) -> bool:
    """Send a harmless request as that IP through the WAF; expect the blocklist rule to stop it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        req = urllib.request.Request(f"{config.WAF_URL}/", headers={"X-Lab-Source-IP": ip,
                                                                     "User-Agent": "soc-lab-verifier/1"})
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            if e.code == 403 and e.headers.get("x-lab-waf-rule") == config.BLOCKLIST_RULE:
                return True
        time.sleep(2)  # the enforcer reloads IP sets every few seconds
    return False
