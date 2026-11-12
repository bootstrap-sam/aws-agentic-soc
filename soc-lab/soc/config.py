"""All settings come from the environment. Nothing here is secret: the emulator accepts any keys."""
import os


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# Where AWS calls go. Empty string = real AWS with your normal credential chain.
ENDPOINT_URL = os.environ.get("SOC_ENDPOINT_URL", "http://localhost:4566")
WAF_URL = os.environ.get("SOC_WAF_URL", "http://localhost:8080")
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Real Bedrock model IDs. Floci maps them to local models (BEDROCK_MODEL_MAPPING / LOCAL_MODEL).
TRIAGE_MODEL = os.environ.get("SOC_TRIAGE_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
INVESTIGATE_MODEL = os.environ.get("SOC_INVESTIGATE_MODEL", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")

BLOCKLIST_IP_SET = os.environ.get("SOC_BLOCKLIST_IP_SET", "blocklist")
BLOCKLIST_RULE = os.environ.get("SOC_BLOCKLIST_RULE", "block-ip-blocklist")
ALLOWLIST_IP_SETS = _list("SOC_ALLOWLIST_IP_SETS", "office")
# Never blockable regardless of what any agent says: office/TEST-NET-2, the lab network, loopback, RFC1918.
PROTECTED_CIDRS = _list("SOC_PROTECTED_CIDRS", "198.51.100.0/24,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16,127.0.0.0/8,::1/128")
MAX_BLOCKS_PER_RUN = int(os.environ.get("SOC_MAX_BLOCKS_PER_RUN", "5"))
AUTO_APPROVE_MIN_CONFIDENCE = float(os.environ.get("SOC_AUTO_APPROVE_MIN_CONFIDENCE", "0.7"))

CASES_TABLE = os.environ.get("SOC_CASES_TABLE", "soc-cases")
INTEL_FILE = os.environ.get("SOC_INTEL_FILE", os.path.join(os.path.dirname(__file__), "..", "intel", "ip_reputation.json"))
