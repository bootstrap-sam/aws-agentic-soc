"""Case records in DynamoDB (Floci locally): one item per investigated IP per run."""
from __future__ import annotations

import json
import time

from soc import config
from soc.aws import client


def ensure_table() -> None:
    ddb = client("dynamodb")
    if config.CASES_TABLE in ddb.list_tables()["TableNames"]:
        return
    ddb.create_table(TableName=config.CASES_TABLE, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "case_id", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "case_id", "KeyType": "HASH"}])


def put_case(case: dict) -> None:
    client("dynamodb").put_item(TableName=config.CASES_TABLE, Item={
        "case_id": {"S": case["case_id"]},
        "ip": {"S": case["ip"]},
        "outcome": {"S": case["outcome"]},
        "created_ms": {"N": str(int(time.time() * 1000))},
        "body": {"S": json.dumps(case, default=str)},
    })
