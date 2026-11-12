# Local AWS labs

Hands-on AWS labs that run entirely on your machine with local emulators. You don't need an AWS account,
credentials or API keys, and nothing in this repo is secret.

| Lab | What you do |
|---|---|
| [network-lab](network-lab) | Build a VPC, ALB and WAFv2 web ACL in Terraform against [Floci](https://github.com/floci-io/floci), then attack it with `curl` and watch each layer react. Includes challenges. |
| [bedrock-lab](bedrock-lab) | Compare Floci and the official [AWS Emulator](https://github.com/aws/aws-emulator) for testing Bedrock agents. Includes a probe that grades which Bedrock features each one really implements. |
| [soc-lab](soc-lab) | An agentic SOC: LLM agents triage WAF traffic, investigate, and block attackers through the WAF, with a policy gate, prompt-injection tests and a scored eval. Runs on a local model. |

## Requirements

- **Docker** with Compose v2.20+: Docker Desktop, [Colima](https://github.com/abiosoft/colima), OrbStack, or Docker
  Engine on Linux. On Windows, use WSL2.
- **A local model** for `bedrock-lab` and `soc-lab`: [Ollama](https://ollama.com) natively (recommended on a Mac),
  or the `ollama` compose profile.
- Optional: [uv](https://docs.astral.sh/uv/) to run the Python parts on the host, and the AWS CLI for the exercises.

Terraform runs in a container, so you don't need to install it.

Each folder's README has its own steps. `network-lab` and `soc-lab` share a Docker network, so run one at a time.

## Credentials

The only credentials in this repo are the emulator placeholders `test` / `test`, which Floci accepts in place of real
keys. The AWS Emulator generates its own throwaway keys each time it starts, under `bedrock-lab/.state/` (gitignored).
To run anything against real AWS, use your normal credential chain (`aws login`, `AWS_PROFILE`). Never put keys in files here.

CI runs [gitleaks](https://github.com/gitleaks/gitleaks) on every push. To run the same scan locally (in Docker):

```bash
./scripts/check-secrets.sh
```
