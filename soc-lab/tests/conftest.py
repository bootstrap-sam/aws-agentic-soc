import pytest


def event(ip, action="ALLOW", rule="Default_Action", counted=(), uri="/", ua="curl/8", ts=1000):
    return {"timestamp": ts, "action": action, "terminatingRuleId": rule,
            "nonTerminatingMatchingRules": list(counted), "labels": [],
            "httpRequest": {"clientIp": ip, "country": None, "httpMethod": "GET", "uri": uri, "args": "",
                            "headers": [{"name": "User-Agent", "value": ua}]}}


@pytest.fixture
def mk_event():
    return event
