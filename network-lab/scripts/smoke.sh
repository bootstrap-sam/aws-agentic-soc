#!/usr/bin/env bash
# Runs one request per lab behaviour through the WAF front door and prints
# the status code, which WAF rule decided, and which app answered.
set -u
FRONT=${FRONT:-http://localhost:8080}
ALB=${ALB:-http://localhost:8081}
tmp=$(mktemp)

t() {
  printf '%-36s ' "$1"; shift
  curl -s -o "$tmp" -D - "$@" | tr -d '\r' | awk '
    NR==1 {printf "%s  ", $2}
    tolower($1)=="x-lab-waf-rule:" {printf "waf=%-34s", $2}
    tolower($1)=="location:" {loc=$2}
    END {if (loc) printf "-> %s", loc}'
  grep -m1 -o 'Name: app-.' "$tmp" || echo
}

echo "== ALB routing =="
t "default (round robin)"       "$FRONT/"
t "default (round robin)"       "$FRONT/"
t "path /a/*"                   "$FRONT/a/hello"
t "path /b/*"                   "$FRONT/b/hello"
t "header X-Beta: true"         "$FRONT/x" -H 'X-Beta: true'
t "fixed-response"              "$FRONT/maintenance"
t "redirect"                    "$FRONT/old-docs/page"

echo; echo "== WAF rules =="
t "blocklisted IP"              "$FRONT/" -H 'X-Lab-Source-IP: 203.0.113.9'
t "SQLi in query string"        "$FRONT/search?q=1%27%20OR%20%271%27%3D%271"
t "/admin from random IP"       "$FRONT/admin"
t "/admin from office IP"       "$FRONT/admin" -H 'X-Lab-Source-IP: 198.51.100.7'
t "scanner UA on / (count)"     "$FRONT/" -A sqlmap/1.7
t "scanner UA on /b (label)"    "$FRONT/b" -A sqlmap/1.7
t "geo KP"                      "$FRONT/" -H 'X-Lab-Country: KP'
t "ALB direct (no WAF)"         "$ALB/admin"

echo; echo "== rate limit: 13 x /login from one IP (limit 10/60s) =="
ip="192.0.2.$((RANDOM % 250 + 1))"
for _ in $(seq 1 13); do curl -s -o /dev/null -w '%{http_code} ' "$FRONT/login" -H "X-Lab-Source-IP: $ip"; done
echo
rm -f "$tmp"
