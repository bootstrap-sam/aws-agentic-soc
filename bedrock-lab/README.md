# Bedrock agent lab: Floci vs the AWS Emulator

This lab runs a custom Bedrock agent (a Converse tool-use loop, [lab/agent.py](lab/agent.py)) against two
local emulators side by side. A probe ([lab/probe.py](lab/probe.py)) grades which Bedrock features each one really implements.

| | Floci 2.4.0 | AWS Emulator v1.0.x (launched 2026-11-11) |
|---|---|---|
| Endpoint | `http://127.0.0.1:4567` (host port moved from 4566 so it can run with `../`) | `https://127.0.0.1:9297` (self-signed CA) |
| Image | `floci/floci:2.4.0` | none published; built from AWS's RPM in [aws-emulator/Dockerfile](aws-emulator/Dockerfile) (x86_64 or arm64, auto) |
| Credentials | anything | regenerated each start in `.state/aws-emulator/9297/` |
| Persistence | `FLOCI_STORAGE_MODE` = memory / persistent / hybrid / wal | in memory only, wiped on stop |
| IAM | off by default; `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true` turns it on | policies not evaluated (SigV4 is checked) |
| License | MIT | CC0-1.0 (code written by AI agents; doesn't accept PRs) |

## Bedrock features for agent work

**Measured** with `lab/probe.py` on 2026-11-12: Floci 2.4.0 (proxy → Ollama `qwen2.5:7b`) vs AWS Emulator LTS latest.
✅ real behaviour · 🟡 right shape, canned/not acted on · ❌ not served

| Feature | Floci | AWS Emulator |
|---|---|---|
| **Converse**: real completion | ✅ real answer from the local LLM (~2–4 s) | 🟡 canned text: "No language model runs in this emulator…" (~4 ms) |
| Converse **tool use** | ✅ picked `get_weather({"city":"Oslo"})` | 🟡 fabricates a call from the schema (wrong tool, placeholder args) |
| **ConverseStream** | ✅ real streamed answer | 🟡 well-formed event stream of canned text |
| InvokeModel | ❌ ValidationException in proxy mode | 🟡 Anthropic-shaped canned body |
| ListFoundationModels | ❌ 404 (Floci bug: docs list it) | ✅ 132 models |
| CreateGuardrail | ✅ | ✅ |
| **Guardrail enforcement** (Converse `guardrailConfig`) | ❌ ignored | ✅ word filter → `guardrail_intervened` |
| ApplyGuardrail | ❌ 404 | ✅ `GUARDRAIL_INTERVENED` |
| Bedrock Agents (CreateAgent, action groups) | ❌ 404 | ❌ 501 |
| InvokeAgent / Retrieve | ❌ 404 | 🟡 served, validates, ResourceNotFound (agents can't be created yet) |
| AgentCore control plane | ✅ (ListAgentRuntimes) | ✅ (ListAgentRuntimes) |
| AgentCore InvokeAgentRuntime | 🟡 fixed `{"output":"yes"}` | ❌ 501 |
| Lambda (tool handlers) | ✅ real Docker containers, per the docs (not probed) | not probed |
| Persistence | memory / persistent / hybrid / wal | memory only |
| IAM | off by default, can enforce | not evaluated |

`LAB_TARGET=floci uv run pytest` passes: 3 behavioural agent tests, plus the guardrail test, which is skipped off real AWS.

### Verdict for testing custom agents

**Floci is the one for agent behaviour.** It's the only one of the two with a real model in the loop, so tests like
"it called the calculator" and "it checked both cities" actually mean something, offline and free. Not having managed
Bedrock Agents doesn't matter if your agent is your own Converse loop (or Strands, LangGraph, ...).

**The AWS Emulator is better than I expected for everything around the model.** It has the broadest, most accurate API
surface (generated from the SDK's own models), it really **enforces guardrails**, and it's ~1000× faster.
Its canned tool call is useful too: it drives your tool-dispatch and error paths deterministically, with no LLM flakiness.
But it never produces a meaningful completion, so it can't tell you whether the agent behaves.

**Neither runs managed Bedrock Agents or AgentCore Runtime containers**, and a local Qwen isn't Claude
(tool-calling reliability differs). Keep a small real-Bedrock suite (`LAB_TARGET=aws`).

Suggested layering:

1. **Unit:** the agent loop with a fake `converse` (no emulator), deterministic.
2. **Floci + Ollama:** behavioural agent tests (tool choice, multi-turn, stop conditions) on every PR.
3. **AWS Emulator:** guardrail wiring, SDK/IaC shape checks, deterministic tool-dispatch and error-path tests.
4. **Real Bedrock:** nightly, a few golden-path tests with the real model.

## Run it

Needs Docker and [uv](https://docs.astral.sh/uv/). Run a local model with Ollama natively (best on a Mac, uses the GPU):

```bash
ollama serve
```

```bash
ollama pull qwen2.5:7b
```

```bash
docker compose up -d --build
```

```bash
uv sync && uv run python -m lab.probe
```

```bash
uv run python -m lab.agent --target floci "What is 17.5% of 2340, and is it warmer in Paris or Oslo?"
```

```bash
LAB_TARGET=floci uv run pytest -v
```

No Docker Desktop (or it's stuck on a password prompt)? Colima works with no admin rights:
`brew install colima && colima start --cpu 4 --memory 8 --vm-type vz`, then prefix commands with
`DOCKER_CONTEXT=colima` (e.g. `DOCKER_CONTEXT=colima docker compose up -d --build`).

The probe prints a side-by-side grade per feature and writes `results/probe.json`. That turns the ❓s above
into facts for the exact versions you're running. Re-run it whenever either emulator updates.

The local model is any Ollama tag with tool support (`LOCAL_MODEL=qwen3:8b docker compose up -d`). Floci maps
every Bedrock model ID to it, so the agent code keeps the real `us.anthropic.claude-sonnet-4-5…` ID.

To hit real Bedrock with the same code, pass `--target aws` (it uses your normal credentials and `AWS_REGION`).

### CLI against each emulator

```bash
export AWS_ENDPOINT_URL=http://127.0.0.1:4567 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
```

```bash
export AWS_ENDPOINT_URL=https://127.0.0.1:9297 AWS_SHARED_CREDENTIALS_FILE=$PWD/.state/aws-emulator/9297/emulator_credentials AWS_CA_BUNDLE=$PWD/.state/aws-emulator/9297/ca.pem AWS_DISABLE_HOST_PREFIX_INJECTION=true AWS_EC2_METADATA_DISABLED=true AWS_REGION=us-east-1
```

The emulator writes fresh keys and a CA to `.state/aws-emulator/9297/` each start (gitignored).
Ignore the `config` file there: it holds container paths.

## Sources

- [AWS Emulator announcement](https://aws.amazon.com/about-aws/whats-new/2026/11/aws-emulator-now-available/), [docs](https://docs.aws.amazon.com/emulator/latest/userguide/what-is-service.html), [repo](https://github.com/aws/aws-emulator), [The Register](https://www.theregister.com/off-prem/2026/11/12/aws-distills-its-cloud-into-a-local-emulator-that-runs-on-your-pc/5309251), [SiliconANGLE](https://siliconangle.com/2026/11/11/amazons-open-source-aws-emulator-lets-developers-validate-their-code-locally-without-the-cloud/)
- Floci: [repo](https://github.com/floci-io/floci), [Bedrock Runtime](https://floci.io/floci/services/bedrock-runtime/), [Bedrock](https://floci.io/floci/services/bedrock/), [AgentCore](https://floci.io/floci/services/bedrock-agentcore/), [Lambda](https://floci.io/floci/services/lambda/)
