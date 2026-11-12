"""
Local WAFv2 enforcer for Floci.

Floci stores WAFv2 web ACLs but never applies them to traffic. This proxy sits
where AWS WAF sits in front of an ALB: it looks up the web ACL associated with
the load balancer (via the real WAFv2 API on Floci), evaluates each request
against it, and either blocks it or forwards it to the ALB listener.

Supported statements: ByteMatch, RegexMatch, RegexPatternSetReference,
SizeConstraint, IPSetReference, GeoMatch (via X-Lab-Country), RateBased,
LabelMatch, And/Or/Not, RuleGroupReference, and rough SqliMatch/XssMatch
heuristics. ManagedRuleGroupStatement is not emulated (logged and skipped).

Lab-only request headers (stripped before forwarding):
  X-Lab-Source-IP   pretend the TCP connection came from this IP
  X-Lab-Country     pretend GeoIP resolved the client to this country code
"""

import base64
import html
import http.client
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3

ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://floci:4566")
ALB_NAME = os.environ.get("ALB_NAME", "lab-alb")
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "floci")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "80"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
REFRESH_SECONDS = float(os.environ.get("REFRESH_SECONDS", "5"))
BODY_INSPECTION_LIMIT = 8 * 1024  # ALB-associated web ACLs inspect the first 8 KB

LAB_HEADERS = ("x-lab-source-ip", "x-lab-country")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade"}

session = boto3.session.Session(region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
wafv2 = session.client("wafv2", endpoint_url=ENDPOINT)
elbv2 = session.client("elbv2", endpoint_url=ENDPOINT)


def log(msg, **fields):
    print(json.dumps({"msg": msg, **fields}), flush=True)


# --------------------------------------------------------------------------
# Loading the web ACL from Floci
# --------------------------------------------------------------------------

def parse_waf_arn(arn):
    # arn:aws:wafv2:us-east-1:000000000000:regional/ipset/NAME/ID
    _, _, _, _, account, resource = arn.split(":", 5)
    scope, _kind, name, rid = resource.split("/")
    return account, ("CLOUDFRONT" if scope == "global" else "REGIONAL"), name, rid


class Loaded:
    """Snapshot of the active web ACL with every referenced set resolved."""

    def __init__(self, acl=None, alb_arn=None):
        self.acl = acl
        self.alb_arn = alb_arn
        self.ip_sets = {}       # arn -> [ip_network]
        self.regex_sets = {}    # arn -> [compiled]
        self.rule_groups = {}   # arn -> RuleGroup dict
        self.warnings = []


def load_snapshot():
    lbs = elbv2.describe_load_balancers(Names=[ALB_NAME])["LoadBalancers"]
    alb_arn = lbs[0]["LoadBalancerArn"]
    resp = wafv2.get_web_acl_for_resource(ResourceArn=alb_arn)
    snap = Loaded(resp.get("WebACL"), alb_arn)
    if not snap.acl:
        return snap

    def walk(stmt):
        for kind, body in stmt.items():
            if kind == "IPSetReferenceStatement" and body["ARN"] not in snap.ip_sets:
                _, scope, name, rid = parse_waf_arn(body["ARN"])
                s = wafv2.get_ip_set(Name=name, Scope=scope, Id=rid)["IPSet"]
                snap.ip_sets[body["ARN"]] = [ipaddress.ip_network(a, strict=False) for a in s["Addresses"]]
            elif kind == "RegexPatternSetReferenceStatement" and body["ARN"] not in snap.regex_sets:
                _, scope, name, rid = parse_waf_arn(body["ARN"])
                s = wafv2.get_regex_pattern_set(Name=name, Scope=scope, Id=rid)["RegexPatternSet"]
                snap.regex_sets[body["ARN"]] = [re.compile(r["RegexString"]) for r in s["RegularExpressionList"]]
            elif kind == "RuleGroupReferenceStatement" and body["ARN"] not in snap.rule_groups:
                _, scope, name, rid = parse_waf_arn(body["ARN"])
                group = wafv2.get_rule_group(Name=name, Scope=scope, Id=rid)["RuleGroup"]
                snap.rule_groups[body["ARN"]] = group
                for r in group.get("Rules", []):
                    walk(r["Statement"])
            elif kind == "ManagedRuleGroupStatement":
                snap.warnings.append(f"ManagedRuleGroupStatement {body.get('Name')} is not emulated; it never matches")
            if isinstance(body, dict):
                for key in ("Statement", "ScopeDownStatement"):
                    if key in body:
                        walk(body[key])
                for child in body.get("Statements", []):
                    walk(child)

    for rule in snap.acl.get("Rules", []):
        walk(rule["Statement"])
    return snap


current = Loaded()
current_lock = threading.Lock()


def refresher():
    global current
    last_sig = None
    while True:
        try:
            snap = load_snapshot()
            sig = json.dumps(snap.acl, sort_keys=True, default=str)
            with current_lock:
                current = snap
            if sig != last_sig:
                last_sig = sig
                if snap.acl:
                    log("web ACL loaded", name=snap.acl["Name"],
                        rules=[r["Name"] for r in sorted(snap.acl.get("Rules", []), key=lambda r: r["Priority"])],
                        warnings=snap.warnings)
                else:
                    log("no web ACL associated with ALB; passing all traffic", alb=ALB_NAME)
        except Exception as e:  # ALB may not exist yet before terraform apply
            if last_sig != "error":
                log("waiting for ALB / web ACL", alb=ALB_NAME, error=str(e))
                last_sig = "error"
            with current_lock:
                current = Loaded()
        time.sleep(REFRESH_SECONDS)


# --------------------------------------------------------------------------
# Request model, field extraction, text transformations
# --------------------------------------------------------------------------

class Req:
    def __init__(self, method, target, headers, body, source_ip, country):
        # Split by hand: urlsplit() reads a path like "//admin" as a hostname.
        path, _, query = target.partition("?")
        self.method = method
        self.path = path or "/"
        self.query = query
        self.headers = headers              # list of (name, value), original case
        self.body = body[:BODY_INSPECTION_LIMIT]
        self.source_ip = source_ip
        self.country = country
        self.labels = set()

    def header(self, name):
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def cookies(self):
        out = []
        for k, v in self.headers:
            if k.lower() == "cookie":
                for part in v.split(";"):
                    if "=" in part:
                        ck, cv = part.strip().split("=", 1)
                        out.append((ck, cv))
        return out


def extract(field, req):
    """Return the list of candidate strings a FieldToMatch selects."""
    if "UriPath" in field:
        return [req.path]
    if "QueryString" in field:
        return [req.query]
    if "Method" in field:
        return [req.method]
    if "Body" in field or "JsonBody" in field:
        return [req.body.decode("utf-8", "replace")]
    if "SingleHeader" in field:
        v = req.header(field["SingleHeader"]["Name"])
        return [] if v is None else [v]
    if "SingleQueryArgument" in field:
        want = field["SingleQueryArgument"]["Name"].lower()
        return [v for k, v in urllib.parse.parse_qsl(req.query, keep_blank_values=True) if k.lower() == want]
    if "AllQueryArguments" in field:
        return [v for _, v in urllib.parse.parse_qsl(req.query, keep_blank_values=True)]
    if "Headers" in field or "Cookies" in field:
        spec = field.get("Headers") or field.get("Cookies")
        pairs = req.cookies() if "Cookies" in field else req.headers
        pattern = spec.get("MatchPattern", {})
        if "IncludedHeaders" in pattern or "IncludedCookies" in pattern:
            inc = {n.lower() for n in pattern.get("IncludedHeaders", pattern.get("IncludedCookies", []))}
            pairs = [(k, v) for k, v in pairs if k.lower() in inc]
        elif "ExcludedHeaders" in pattern or "ExcludedCookies" in pattern:
            exc = {n.lower() for n in pattern.get("ExcludedHeaders", pattern.get("ExcludedCookies", []))}
            pairs = [(k, v) for k, v in pairs if k.lower() not in exc]
        scope = spec.get("MatchScope", "ALL")
        return [k for k, _ in pairs] * (scope in ("KEY", "ALL")) + [v for _, v in pairs] * (scope in ("VALUE", "ALL"))
    return []


def transform(value, transformations):
    for t in sorted(transformations or [], key=lambda t: t["Priority"]):
        kind = t["Type"]
        if kind == "LOWERCASE":
            value = value.lower()
        elif kind == "UPPERCASE":
            value = value.upper()
        elif kind in ("URL_DECODE", "URL_DECODE_UNI"):
            value = urllib.parse.unquote_plus(value)
        elif kind == "HTML_ENTITY_DECODE":
            value = html.unescape(value)
        elif kind == "COMPRESS_WHITE_SPACE":
            value = re.sub(r"\s+", " ", value)
        elif kind == "REMOVE_NULLS":
            value = value.replace("\x00", "")
        elif kind == "BASE64_DECODE":
            try:
                value = base64.b64decode(value + "===").decode("utf-8", "replace")
            except Exception:
                pass
        elif kind in ("NORMALIZE_PATH", "NORMALIZE_PATH_WIN"):
            value = re.sub(r"/+", "/", os.path.normpath(value.replace("\\", "/")))
        elif kind == "CMD_LINE":
            value = re.sub(r"[\\\"'^]", "", value)
            value = re.sub(r"\s*([,;/(])\s*", r"\1", value).lower()
    return value


def candidates(body, req):
    return [transform(v, body.get("TextTransformations")) for v in extract(body["FieldToMatch"], req)]


SQLI = re.compile(r"('|\")\s*(or|and)\s+[\w'\"]+\s*=|union(\s|/\*.*?\*/)+select|;\s*(drop|delete|insert|update)\s|--\s*$|/\*|\bsleep\s*\(|\bbenchmark\s*\(", re.I)
XSS = re.compile(r"<\s*script|javascript:|on(error|load|click|mouseover)\s*=|<\s*(iframe|img|svg)[^>]*>", re.I)


# --------------------------------------------------------------------------
# Statement evaluation
# --------------------------------------------------------------------------

rate_windows = defaultdict(deque)   # (rule name, key) -> deque[timestamps]
rate_lock = threading.Lock()


def client_ip(req, fwd_config):
    """The IP a statement inspects: source IP, or one taken from a header."""
    if not fwd_config:
        return req.source_ip
    raw = req.header(fwd_config["HeaderName"])
    if not raw:
        return fwd_config.get("FallbackBehavior", "MATCH")
    ips = [p.strip() for p in raw.split(",") if p.strip()]
    pos = fwd_config.get("Position", "FIRST")
    return ips if pos == "ANY" else (ips[0] if pos == "FIRST" else ips[-1])


def ip_in(ip, networks):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks)


def matches(stmt, req, snap, rule_name):
    kind, body = next(iter(stmt.items()))

    if kind == "ByteMatchStatement":
        needle = body["SearchString"]
        needle = needle.decode() if isinstance(needle, bytes) else needle
        pos = body["PositionalConstraint"]
        for v in candidates(body, req):
            if (pos == "EXACTLY" and v == needle) or (pos == "STARTS_WITH" and v.startswith(needle)) \
                    or (pos == "ENDS_WITH" and v.endswith(needle)) or (pos == "CONTAINS" and needle in v) \
                    or (pos == "CONTAINS_WORD" and re.search(rf"(^|\W){re.escape(needle)}(\W|$)", v)):
                return True
        return False

    if kind == "RegexMatchStatement":
        rx = re.compile(body["RegexString"])
        return any(rx.search(v) for v in candidates(body, req))

    if kind == "RegexPatternSetReferenceStatement":
        rxs = snap.regex_sets.get(body["ARN"], [])
        return any(rx.search(v) for v in candidates(body, req) for rx in rxs)

    if kind == "SizeConstraintStatement":
        size, op = body["Size"], body["ComparisonOperator"]
        cmp = {"EQ": int.__eq__, "NE": int.__ne__, "LE": int.__le__,
               "LT": int.__lt__, "GE": int.__ge__, "GT": int.__gt__}[op]
        return any(cmp(len(v.encode()), size) for v in candidates(body, req))

    if kind == "SqliMatchStatement":
        return any(SQLI.search(v) for v in candidates(body, req))

    if kind == "XssMatchStatement":
        return any(XSS.search(v) for v in candidates(body, req))

    if kind == "IPSetReferenceStatement":
        ip = client_ip(req, body.get("IPSetForwardedIPConfig"))
        if ip in ("MATCH", "NO_MATCH"):
            return ip == "MATCH"
        nets = snap.ip_sets.get(body["ARN"], [])
        return any(ip_in(i, nets) for i in ip) if isinstance(ip, list) else ip_in(ip, nets)

    if kind == "GeoMatchStatement":
        return (req.country or "").upper() in body["CountryCodes"]

    if kind == "LabelMatchStatement":
        key = body["Key"]
        if body["Scope"] == "NAMESPACE":
            return any(l.startswith(key) or f":{key}" in l for l in req.labels)
        return any(l == key or l.endswith(f":{key}") for l in req.labels)

    if kind == "AndStatement":
        return all(matches(s, req, snap, rule_name) for s in body["Statements"])
    if kind == "OrStatement":
        return any(matches(s, req, snap, rule_name) for s in body["Statements"])
    if kind == "NotStatement":
        return not matches(body["Statement"], req, snap, rule_name)

    if kind == "RateBasedStatement":
        scope_down = body.get("ScopeDownStatement")
        if scope_down and not matches(scope_down, req, snap, rule_name):
            return False
        agg = body.get("AggregateKeyType", "IP")
        if agg == "CONSTANT":
            key = "*"
        elif agg == "FORWARDED_IP":
            key = client_ip(req, body.get("ForwardedIPConfig"))
            key = key[0] if isinstance(key, list) else key
        else:
            key = req.source_ip
        window = body.get("EvaluationWindowSec", 300)
        now = time.time()
        with rate_lock:
            q = rate_windows[(rule_name, key)]
            q.append(now)
            while q and q[0] < now - window:
                q.popleft()
            return len(q) > body["Limit"]

    if kind == "ManagedRuleGroupStatement":
        return False

    log("unsupported statement treated as no-match", statement=kind, rule=rule_name)
    return False


def evaluate(req, snap):
    """Walk the web ACL like AWS WAF. Returns (action, rule, custom_response, non_terminating)."""
    acl = snap.acl
    account = acl["ARN"].split(":")[4]
    non_terminating = []

    def run_rules(rules, label_ns, override_count=False, overrides=None, excluded=()):
        for rule in sorted(rules, key=lambda r: r["Priority"]):
            if rule["Name"] in excluded:
                continue
            stmt = rule["Statement"]
            if "RuleGroupReferenceStatement" in stmt:
                ref = stmt["RuleGroupReferenceStatement"]
                group = snap.rule_groups.get(ref["ARN"])
                if not group:
                    continue
                count = "Count" in rule.get("OverrideAction", {})
                ovr = {o["Name"]: o["ActionToUse"] for o in ref.get("RuleActionOverrides", [])}
                exc = {e["Name"] for e in ref.get("ExcludedRules", [])}
                ns = f"awswaf:{account}:rulegroup:{group['Name']}:"
                result = run_rules(group.get("Rules", []), ns, count, ovr, exc)
                if result:
                    return result
                continue
            if not matches(stmt, req, snap, rule["Name"]):
                continue
            for lbl in rule.get("RuleLabels", []):
                req.labels.add(label_ns + lbl["Name"])
            action = (overrides or {}).get(rule["Name"], rule.get("Action", {}))
            name = next(iter(action), "Count")
            if override_count or name == "Count":
                non_terminating.append(rule["Name"])
                continue
            return name, rule["Name"], action.get(name, {}).get("CustomResponse")
        return None

    result = run_rules(acl.get("Rules", []), f"awswaf:{account}:webacl:{acl['Name']}:")
    if result:
        return (*result, non_terminating)
    default = acl["DefaultAction"]
    name = next(iter(default))
    return name, "Default_Action", default[name].get("CustomResponse"), non_terminating


# --------------------------------------------------------------------------
# HTTP proxy
# --------------------------------------------------------------------------

recent = deque(maxlen=int(os.environ.get("LOG_BUFFER", "200")))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _respond(self, code, body, ctype="text/plain", headers=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _admin(self):
        with current_lock:
            snap = current
        if self.path.startswith("/__waf/logs"):
            return self._respond(200, json.dumps(list(recent), indent=2), "application/json")
        status = {
            "alb": ALB_NAME,
            "albArn": snap.alb_arn,
            "webAcl": snap.acl and snap.acl["Name"],
            "defaultAction": snap.acl and next(iter(snap.acl["DefaultAction"])),
            "rules": snap.acl and [
                {"priority": r["Priority"], "name": r["Name"],
                 "action": next(iter(r.get("Action") or r.get("OverrideAction") or {"?": 0}))}
                for r in sorted(snap.acl.get("Rules", []), key=lambda r: r["Priority"])],
            "warnings": snap.warnings,
        }
        return self._respond(200, json.dumps(status, indent=2), "application/json")

    def _handle(self):
        # http.server collapses a leading "//" in self.path; WAF inspects the raw target.
        self.path = self.raw_requestline.decode("latin-1").split()[1]
        if self.path.startswith("/__waf/"):
            return self._admin()

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = [(k, v) for k, v in self.headers.items()]
        source_ip = self.headers.get("X-Lab-Source-IP") or self.client_address[0]
        req = Req(self.command, self.path, [(k, v) for k, v in headers if k.lower() not in LAB_HEADERS],
                  body, source_ip, self.headers.get("X-Lab-Country"))

        with current_lock:
            snap = current
        if snap.acl:
            action, rule, custom, counted = evaluate(req, snap)
        else:
            action, rule, custom, counted = "Allow", "No_WebACL", None, []

        entry = {
            "timestamp": int(time.time() * 1000),
            "action": action.upper(),
            "terminatingRuleId": rule,
            "nonTerminatingMatchingRules": counted,
            "labels": sorted(req.labels),
            "httpRequest": {"clientIp": source_ip, "country": req.country, "httpMethod": req.method,
                            "uri": req.path, "args": req.query,
                            "headers": [{"name": k, "value": v} for k, v in req.headers]},
        }
        recent.append(entry)
        log("request", **{k: entry[k] for k in ("action", "terminatingRuleId", "nonTerminatingMatchingRules", "labels")},
            clientIp=source_ip, method=req.method, uri=self.path)

        waf_headers = [("x-lab-waf-action", action.upper()), ("x-lab-waf-rule", rule)]
        if action == "Block":
            return self._block(custom, snap, waf_headers)
        if action == "Captcha":
            return self._respond(405, "CAPTCHA required (emulated)", headers=waf_headers)
        if action == "Challenge":
            return self._respond(202, "Challenge required (emulated)", headers=waf_headers)

        # Allow: forward with the X-Forwarded-* headers a real ALB adds (Floci's ALB doesn't),
        # plus a header per label so the backend can see what WAF decided.
        fwd = [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP and k.lower() not in LAB_HEADERS]
        xff = self.headers.get("X-Forwarded-For")
        fwd = [(k, v) for k, v in fwd if k.lower() not in ("x-forwarded-for", "x-forwarded-proto", "x-forwarded-port")]
        fwd += [("X-Forwarded-For", f"{xff}, {source_ip}" if xff else source_ip),
                ("X-Forwarded-Proto", "http"), ("X-Forwarded-Port", "80")]
        fwd += [(f"x-amzn-waf-{lbl.split(':')[-1]}", "true") for lbl in sorted(req.labels)]
        self._forward(fwd, body, waf_headers)

    def _block(self, custom, snap, waf_headers):
        if not custom:
            return self._respond(403, "<html><body><h1>403 Forbidden</h1></body></html>", "text/html", waf_headers)
        bodies = snap.acl.get("CustomResponseBodies", {})
        b = bodies.get(custom.get("CustomResponseBodyKey"), {})
        ctype = {"APPLICATION_JSON": "application/json", "TEXT_HTML": "text/html"}.get(b.get("ContentType"), "text/plain")
        extra = [(f"x-amzn-waf-{h['Name']}", h["Value"]) for h in custom.get("ResponseHeaders", [])]
        self._respond(custom["ResponseCode"], b.get("Content", ""), ctype, waf_headers + extra)

    def _forward(self, headers, body, waf_headers):
        try:
            conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=30)
            conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            for k, v in headers:
                conn.putheader(k, v)
            if body:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body or None)
            resp = conn.getresponse()
            data = resp.read()
        except Exception as e:
            return self._respond(502, f"waf-enforcer could not reach ALB listener: {e}\n", headers=waf_headers)
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() not in HOP_BY_HOP and k.lower() != "content-length":
                self.send_header(k, v)
        for k, v in waf_headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


if __name__ == "__main__":
    threading.Thread(target=refresher, daemon=True).start()
    log("waf-enforcer listening", port=LISTEN_PORT, upstream=f"{UPSTREAM_HOST}:{UPSTREAM_PORT}", alb=ALB_NAME)
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
