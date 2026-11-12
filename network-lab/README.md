# Local AWS networking lab: VPC · ALB · WAF

A hands-on lab that runs entirely on your laptop with [Floci](https://github.com/floci-io/floci),
a local AWS emulator. You only need Docker (Docker Desktop, Colima, OrbStack, or Docker Engine on Linux / WSL2). You define real AWS resources in Terraform, then send real
HTTP traffic through them and watch what each layer does.

```
                    ┌──────────────────────────── VPC 172.30.0.0/16 ─────────────────────────────┐
                    │  public subnets (→ IGW)                 private subnets (→ NAT GW)          │
 curl ──► :8080 ──► │  [ WAF web ACL ] ──► [ ALB lab-alb :80 ] ──┬─► tg-app-a ─► app-a 172.30.11.10 │
          (front    │   waf-enforcer        listener rules       ├─► tg-app-b ─► app-b 172.30.12.10 │
           door)    │                                            └─► tg-all  ─► both (round robin)  │
 curl ──► :8081 ──────────────────────────► (ALB direct, no WAF)                                    │
                    └────────────────────────────────────────────────────────────────────────────┘
```

| Piece | What it is |
|---|---|
| `docker-compose.yml` | Floci, the WAF enforcer, and two `whoami` apps that echo back the request they received |
| `terraform/network.tf` | VPC, 2 public + 2 private subnets across 2 AZs, IGW, NAT gateway, route tables, security groups |
| `terraform/alb.tf` | ALB, 3 target groups, listener with path / header / fixed-response / redirect rules |
| `terraform/waf.tf` | WAFv2 web ACL with IP sets, regex sets, SQLi, AND/NOT logic, labels, geo, rate limiting |
| `waf-enforcer/` | Small proxy that reads your web ACL from Floci and **actually enforces it** (Floci doesn't, see below) |
| `scripts/smoke.sh` | One request per behaviour, so you can check everything works |

## Start / stop

```bash
docker compose up -d --build
```

```bash
docker compose run --rm terraform init && docker compose run --rm terraform apply -auto-approve
```

(Terraform runs in a container, so you don't need it installed. If you have it locally,
`terraform -chdir=terraform init && terraform -chdir=terraform apply -auto-approve` works too.)

```bash
./scripts/smoke.sh
```

Floci keeps state **in memory**. After `docker compose down` or a Floci restart, delete
`terraform/terraform.tfstate*` and re-apply.

```bash
docker compose down && rm -f terraform/terraform.tfstate*
```

Talk to the emulator with the normal AWS CLI by setting these first:

```bash
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_DEFAULT_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_PAGER=""
```

Watch WAF decisions live (one JSON line per request, shaped like real WAF logs):

```bash
docker compose logs -f waf-enforcer
```

`http://localhost:8080/__waf/status` shows the loaded web ACL, and `/__waf/logs` shows the most recent requests in full (2,000 kept, `LOG_BUFFER`).

## Lab-only headers

On AWS, WAF sees the real client IP and looks up its country. Locally every request comes
from your Mac, so the enforcer lets you pretend. It strips these headers before forwarding:

| Header | Pretends… |
|---|---|
| `X-Lab-Source-IP: 203.0.113.9` | the TCP connection came from this IP |
| `X-Lab-Country: KP` | GeoIP resolved the client to this country |

---

## Exercises

### 1. Explore the network you built

```bash
aws ec2 describe-subnets --query 'Subnets[].[Tags[?Key==`Name`]|[0].Value,CidrBlock,AvailabilityZone]' --output table
```

```bash
aws ec2 describe-route-tables --query 'RouteTables[].[Tags[0].Value,Routes[].[DestinationCidrBlock,GatewayId||NatGatewayId]]' --output json
```

Questions to answer:
- What makes a subnet "public"? (Hint: it isn't a flag on the subnet. It's the route table's `0.0.0.0/0 → igw-…` route.)
- Why does the NAT gateway live in a *public* subnet, while the private route table points at it?
- Look at `app-sg`: its ingress source is another **security group**, not a CIDR. Why is that better than `172.30.1.0/24`?
- Why does the ALB need subnets in two AZs?

### 2. ALB routing

```bash
for i in 1 2 3 4; do curl -s localhost:8080/ | grep Name; done
```

```bash
curl -s localhost:8080/a/anything | grep Name
```

```bash
curl -s localhost:8080/x -H 'X-Beta: true' | grep Name
```

```bash
curl -si localhost:8080/old-docs/foo | head -3
```

- Change the priority of `beta_header` to `5` and send `curl localhost:8080/a -H 'X-Beta: true'`. Which app answers now, and why?
- Add a `host_header` condition rule (for example `api.lab.local` → tg-app-b) and test it with `curl -H 'Host: api.lab.local' localhost:8080/`.
- Look at the full request the app received: `curl -s localhost:8080/a`. Find `X-Forwarded-For`. Your backend sees the ALB's IP as the TCP peer, so this header is the only way it knows the client IP.

### 3. Target health

```bash
aws elbv2 describe-target-health --target-group-arn $(aws elbv2 describe-target-groups --names tg-all --query 'TargetGroups[0].TargetGroupArn' --output text)
```

```bash
docker compose stop app-a
```

Wait about 20 s and run `describe-target-health` again. Then curl `/` several times: every request
now goes to app-b. With app-a stopped, `/a` returns `503` because its target group has no healthy targets. Bring
it back with `docker compose start app-a`.

### 4. WAF basics: rule order and terminating actions

Run `./scripts/smoke.sh` and read `terraform/waf.tf` side by side. For each 403, find the rule.

- **Allow/Block stop evaluation. Count doesn't.** `sqlmap` on `/` is only *counted* (rule 20 adds
  the `scanner` label). On `/b` the label plus the path match rule 50 → blocked.
- Set rule `admin-office-only` to `count {}` and re-apply. `/admin` now gets through, and the
  enforcer log shows it under `nonTerminatingMatchingRules`. This is how you safely roll out a
  new rule in production: count first, check the logs, then block.

### 5. Text transformations (WAF evasion 101)

```bash
curl -s "localhost:8080/search?q=1%27%20OR%20%271%27%3D%271"
```

```bash
curl -s "localhost:8080/ADMIN" -o /dev/null -w '%{http_code}\n'
```

`/ADMIN` is blocked because of the `LOWERCASE` transformation. Remove it, re-apply, and try again:
that's a bypass. Attackers rely on encoding and case tricks. Text transformations normalise the
input before matching.

### 6. Rate limiting

```bash
for i in $(seq 1 13); do curl -s -o /dev/null -w '%{http_code} ' localhost:8080/login -H 'X-Lab-Source-IP: 192.0.2.77'; done; echo
```

- The scope-down statement means only `/login` counts. Try `/` 13 times: none are blocked.
- Change `aggregate_key_type` to `FORWARDED_IP` with a `forwarded_ip_config { header_name = "X-Forwarded-For", fallback_behavior = "MATCH" }`. Then send different `X-Forwarded-For` values. Why is trusting that header dangerous when there's no CDN in front of you?

### 7. Defence in depth: bypassing the WAF

```bash
curl -s localhost:8081/admin | grep Name
```

Port 8081 reaches the ALB directly and `/admin` works from anywhere. On AWS the equivalent
mistake is apps with public IPs, or an SG that allows `0.0.0.0/0` instead of only the ALB's SG.
WAF only protects the path that goes through it.

### 8. Build your own

Ideas: block `POST` bodies over 1 KB (`size_constraint_statement` on `body`), add an XSS rule on a
query argument, create a `rule_group` and reference it from the web ACL, or return a custom 429
with a JSON body for the rate limit.

---

## Challenges

Answer each one using only the AWS CLI (`export AWS_PROFILE=floci`) and `curl`. Keep a tally
of points. Answers are stored encoded in `answers/answers.b64`, so you can't see them by
accident. Reveal one at a time when you're ready:

```bash
./scripts/answer.sh N1
```

Some answers are IDs that change every time you re-apply, so the answer gives you the command
that proves it.

### 🌐 Networking

**N1: Address space** (50 pts)
What CIDR block does `lab-vpc` use, and how many /24 subnets could it hold in total?

> 🔒 Answer: `./scripts/answer.sh N1`

**N2: Way out** (50 pts)
`public-rt` sends `0.0.0.0/0` to a gateway. What's its ID, and what resource type is it?

> 🔒 Answer: `./scripts/answer.sh N2`

**N3: Where does NAT live?** (100 pts)
Which subnet (by `Name` tag) is the NAT gateway in? Why can't it go in a private subnet?

> 🔒 Answer: `./scripts/answer.sh N3`

**N4: Security group chain** (100 pts)
`app-sg` allows port 80 from *what*? Give the group name, and explain why that's better than a CIDR.

> 🔒 Answer: `./scripts/answer.sh N4`

**N5: Find the zone** (100 pts)
Which Availability Zone is the IP `172.30.12.10` in?

> 🔒 Answer: `./scripts/answer.sh N5`

**N6: Broken on purpose** (150 pts)
Remove the `0.0.0.0/0` route from `private-rt` (in Terraform) and apply. On real AWS, what
breaks and what keeps working?

> 🔒 Answer: `./scripts/answer.sh N6`

### ⚖️ Load balancer

**A1: Rule order** (50 pts)
What priority is the listener rule that matches the `X-Beta` header?

> 🔒 Answer: `./scripts/answer.sh A1`

**A2: Predict it** (100 pts)
Without running it, which app answers `curl localhost:8080/b -H 'X-Beta: true'`, and which rule
wins? Then run it.

> 🔒 Answer: `./scripts/answer.sh A2`

**A3: Counting targets** (100 pts)
In how many target groups is `172.30.11.10` registered?

> 🔒 Answer: `./scripts/answer.sh A3`

**A4: No one home** (100 pts)
Stop `app-a` (`docker compose stop app-a`), wait 30 s, and curl `/a`. What status code do you get,
and what does `/` do?

> 🔒 Answer: `./scripts/answer.sh A4`

**A5 Task: Host-based routing** (200 pts)
Make requests with `Host: api.lab.local` go only to `app-b`.
**Verify:** `for i in 1 2 3 4; do curl -s -H 'Host: api.lab.local' localhost:8080/ | grep Name; done` prints `app-b` four times.

> 🔒 Solution: `./scripts/answer.sh A5`

**A6 Task: Drain without downtime** (200 pts)
Take `app-a` out of the default rotation on `/` **without stopping its container**. `/a` must keep working.
**Verify:** `/` only ever returns `app-b`, and `curl localhost:8080/a | grep Name` still says `app-a`.

> 🔒 Solution: `./scripts/answer.sh A6`

### 🛡️ WAF

**W1: First match wins** (100 pts)
A request comes from `203.0.113.9` to `/search?q=1' OR '1'='1`. It breaks two rules. Which one blocks it?
**Verify:** `curl -si "localhost:8080/search?q=1%27%20OR%20%271%27%3D%271" -H 'X-Lab-Source-IP: 203.0.113.9' | grep x-lab-waf-rule`

> 🔒 Answer: `./scripts/answer.sh W1`

**W2: Name that label** (100 pts)
What's the *full* label that `label-scanners` adds to a request?

> 🔒 Answer: `./scripts/answer.sh W2`

**W3: How many tries?** (50 pts)
How many `/login` requests can one IP make in a minute before it's blocked?

> 🔒 Answer: `./scripts/answer.sh W3`

**W4: Encoding** (250 pts)
The `/admin` rule lowercases the path, then checks whether it starts with `/admin`. Find a path
that still reaches the app's `/admin` from a non-office IP through port 8080. Hint: what does
`%61` mean in a URL?
**Verify:** `curl -s --path-as-is localhost:8080/<your-path> | grep -E '^GET|Name'` shows a response from an app.

> 🔒 Answer: `./scripts/answer.sh W4`

**W5 Task: Close the gap** (250 pts)
Fix the `admin-office-only` rule so that W4 no longer works, and `/admin` from the office IP (`198.51.100.7`) still returns 200.
**Verify:** `curl -s --path-as-is -o /dev/null -w '%{http_code}\n' localhost:8080/%61dmin` prints `403`.

> 🔒 Solution: `./scripts/answer.sh W5`

**W6 Task: New office** (150 pts)
Your team moved. Let `192.0.2.10` reach `/admin` as well, without touching the rule.
**Verify:** `curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/admin -H 'X-Lab-Source-IP: 192.0.2.10'` prints `200`.

> 🔒 Solution: `./scripts/answer.sh W6`

**W7 Task: Be polite** (200 pts)
Make the rate limit return **429** with a JSON body, instead of the default 403.
**Verify:** `for i in $(seq 1 11); do curl -s -o /dev/null -w '%{http_code} ' localhost:8080/login -H 'X-Lab-Source-IP: 192.0.2.88'; done` ends with `429`.

> 🔒 Solution: `./scripts/answer.sh W7`

**W8: Count first** (150 pts)
You want a new rule that blocks requests with no `User-Agent` header, but you're worried about
breaking real clients. How would you roll it out safely?

> 🔒 Answer: `./scripts/answer.sh W8`

**W9: Defence in depth** (50 pts)
Which port reaches the apps with no WAF at all? On real AWS, what two mistakes would create the same gap?

> 🔒 Answer: `./scripts/answer.sh W9`

**Total: 2,600 pts** (+100 bonus)

---

## What's real and what's emulated

Floci is an emulator, so check this list before treating local behaviour as AWS behaviour.

| Area | In this lab |
|---|---|
| VPC, subnets, route tables, IGW, NAT, EIP, SGs | **API only.** Created and described exactly like AWS, but no packets are routed by them. Every container on the Docker network can reach every other. |
| Security groups as a firewall | Off. Floci can enforce them with `FLOCI_NETWORK_SECURITY_GROUP_ENFORCEMENT_ENABLED=true`, but only on Linux hosts, so not on Docker Desktop for Mac. |
| ALB listeners, rules, target groups, health checks | **Real.** Floci proxies HTTP, evaluates rule priority and conditions, round-robins, and health-checks targets. |
| ALB headers | Floci rewrites `Host` to the target IP and doesn't add `X-Forwarded-*`. The enforcer adds `X-Forwarded-For/Proto/Port` to match AWS. |
| WAFv2 resources | **API only in Floci.** It stores them and doesn't filter traffic. |
| WAFv2 enforcement | Done by `waf-enforcer/`: a faithful but partial re-implementation. Supported: ByteMatch, Regex, RegexPatternSet, SizeConstraint, IPSet (+ forwarded IP), Geo (via header), RateBased (+ scope-down), LabelMatch, And/Or/Not, RuleGroupReference, Count, custom responses, text transformations. **SqliMatch / XssMatch are simple regex heuristics**, much weaker than AWS's. **AWS managed rule groups are not emulated** (they never match, and a warning is shown in `/__waf/status`). |
