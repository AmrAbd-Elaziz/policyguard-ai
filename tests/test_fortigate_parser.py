from core.parsers.fortigate import (
    parse_fortigate_config,
)


def test_parse_fortigate_config():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    assert len(rules) == 5


def test_fortigate_any_any_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[0]

    assert rule["rule_id"] == "1"
    assert rule["source"] == "any"
    assert rule["destination"] == "any"
    assert rule["service"] == "any"
    assert rule["action"] == "allow"
    assert rule["logging"] == "no"


def test_fortigate_ssh_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[1]

    assert rule["source"] == "lab-admin-net"
    assert rule["destination"] == "lab-app-server"
    assert rule["service"] == "ssh"
    assert rule["logging"] == "yes"
    assert (
        rule["business_justification"]
        == "Approved lab administrative access"
    )


def test_fortigate_telnet_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[2]

    assert rule["service"] == "telnet"


def test_fortigate_mssql_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[3]

    assert rule["service"] == "1433"


def test_fortigate_deny_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[4]

    assert rule["action"] == "deny"

def test_fortigate_security_profile_detection():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[1]

    assert rule["security_profile"] == "yes"


def test_fortigate_mixed_environment_detection():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[3]

    assert rule["environment"] == "mixed"