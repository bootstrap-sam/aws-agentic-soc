import boto3
from botocore.config import Config

from soc import config

_CFG = Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=300)


def client(service: str):
    if config.ENDPOINT_URL:
        # Emulator placeholders, not credentials: Floci accepts any non-empty value.
        return boto3.client(service, region_name=config.REGION, endpoint_url=config.ENDPOINT_URL,
                            aws_access_key_id="test", aws_secret_access_key="test", config=_CFG)
    return boto3.client(service, region_name=config.REGION, config=_CFG)
