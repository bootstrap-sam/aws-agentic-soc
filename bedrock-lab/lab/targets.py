"""boto3 sessions for each place a Bedrock call can go: Floci, the AWS Emulator, or real AWS."""
from __future__ import annotations

import configparser
import os
from pathlib import Path

import boto3
from botocore.config import Config

TARGETS = ("floci", "aws-emulator", "aws")

FLOCI_URL = os.environ.get("FLOCI_URL", "http://127.0.0.1:4567")
EMULATOR_PORT = os.environ.get("EMULATOR_PORT", "9297")
EMULATOR_DIR = Path(os.environ.get(
    "EMULATOR_STATE_DIR", Path(__file__).resolve().parent.parent / ".state" / "aws-emulator")) / EMULATOR_PORT
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Bedrock Runtime uses host prefixes for some ops; emulators listen on one host.
_EMU_CONFIG = Config(inject_host_prefix=False, retries={"max_attempts": 1}, read_timeout=300)


def client(target: str, service: str):
    if target == "floci":
        return boto3.client(
            service, region_name=REGION, endpoint_url=FLOCI_URL,
            aws_access_key_id="test", aws_secret_access_key="test", config=_EMU_CONFIG,
        )
    if target == "aws-emulator":
        # Credentials and CA are regenerated on every emulator start.
        creds = configparser.ConfigParser()
        creds.read(EMULATOR_DIR / "emulator_credentials")
        if not creds.sections():
            raise RuntimeError(f"No AWS Emulator credentials in {EMULATOR_DIR}; is it running?")
        prof = creds[creds.sections()[0]]
        return boto3.client(
            service, region_name=REGION, endpoint_url=f"https://127.0.0.1:{EMULATOR_PORT}",
            aws_access_key_id=prof["aws_access_key_id"],
            aws_secret_access_key=prof["aws_secret_access_key"],
            aws_session_token=prof.get("aws_session_token"),
            verify=str(EMULATOR_DIR / "ca.pem"), config=_EMU_CONFIG,
        )
    if target == "aws":
        # Real AWS: normal credential chain (AWS_PROFILE, `aws login`, ...).
        return boto3.client(service, region_name=REGION)
    raise ValueError(f"unknown target {target!r}, pick one of {TARGETS}")
