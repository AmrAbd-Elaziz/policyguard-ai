from core.analyzer import (
    load_detection_rules,
    rule_matches_detection,
    analyze_yaml_rules,
)

from core.analyzer import (
    load_detection_rules,
    rule_matches_detection,
    analyze_yaml_rules,
    evaluate_condition_group,
)


def base_rule():
    return {
        "rule_id": "YAML-001",
        "source": "10.0.0.10",
        "destination": "10.0.0.20",
        "service": "https",
        "action": "allow",
        "logging": "yes",
        "security_profile": "yes",
        "business_justification": "Approved access",
        "environment": "production",
    }


def test_yaml_rules_load():
    detections = load_detection_rules()

    names = {
        detection["name"]
        for detection in detections
    }

    assert "INSECURE_PROTOCOL" in names
    assert "LOGGING_GAP" in names


def test_yaml_insecure_protocol_detection():
    rule = base_rule()
    rule["service"] = "telnet"

    findings = analyze_yaml_rules(rule)

    names = {
        finding["finding"]
        for finding in findings
    }

    assert "INSECURE_PROTOCOL" in names


def test_yaml_logging_gap_detection():
    rule = base_rule()
    rule["logging"] = "no"

    findings = analyze_yaml_rules(rule)

    names = {
        finding["finding"]
        for finding in findings
    }

    assert "LOGGING_GAP" in names


def test_clean_rule_does_not_match_yaml_rules():
    findings = analyze_yaml_rules(
        base_rule()
    )

    assert findings == []


def test_rule_matches_detection():
    detection = {
        "conditions": {
            "action": {
                "equals": "allow",
            },
            "service": {
                "in": [
                    "telnet",
                    "ftp",
                ],
            },
        }
    }

    rule = base_rule()
    rule["service"] = "ftp"

    assert rule_matches_detection(
        rule,
        detection,
    ) is True

from core.analyzer import condition_matches


def test_condition_not_equals():
    assert condition_matches(
        "allow",
        {"not_equals": "deny"},
    ) is True

    assert condition_matches(
        "deny",
        {"not_equals": "deny"},
    ) is False


def test_condition_not_in():
    assert condition_matches(
        "https",
        {"not_in": ["telnet", "ftp"]},
    ) is True

    assert condition_matches(
        "telnet",
        {"not_in": ["telnet", "ftp"]},
    ) is False


def test_condition_empty():
    assert condition_matches(
        "",
        {"empty": True},
    ) is True

    assert condition_matches(
        "Approved access",
        {"empty": True},
    ) is False


def test_condition_not_empty():
    assert condition_matches(
        "Approved access",
        {"empty": False},
    ) is True

    assert condition_matches(
        "",
        {"empty": False},
    ) is False

def test_all_condition_group():
    rule = base_rule()

    detection = {
        "match": {
            "all": [
                {
                    "action": {
                        "equals": "allow"
                    }
                },
                {
                    "service": {
                        "equals": "https"
                    }
                },
            ]
        }
    }

    assert rule_matches_detection(
        rule,
        detection,
    ) is True


def test_any_condition_group():
    rule = base_rule()
    rule["service"] = "ssh"

    detection = {
        "match": {
            "any": [
                {
                    "service": {
                        "equals": "ssh"
                    }
                },
                {
                    "service": {
                        "equals": "rdp"
                    }
                },
            ]
        }
    }

    assert rule_matches_detection(
        rule,
        detection,
    ) is True


def test_nested_all_any_condition():
    rule = base_rule()
    rule["service"] = "ssh"
    rule["destination"] = "any"

    detection = {
        "match": {
            "all": [
                {
                    "action": {
                        "equals": "allow"
                    }
                },
                {
                    "service": {
                        "in": [
                            "ssh",
                            "rdp",
                            "telnet",
                            "winrm",
                        ]
                    }
                },
                {
                    "any": [
                        {
                            "source": {
                                "equals": "any"
                            }
                        },
                        {
                            "destination": {
                                "equals": "any"
                            }
                        },
                    ]
                },
            ]
        }
    }

    assert rule_matches_detection(
        rule,
        detection,
    ) is True

def test_yaml_admin_service_exposure():
    rule = base_rule()

    rule["service"] = "ssh"
    rule["destination"] = "any"

    findings = analyze_yaml_rules(rule)

    names = {
        finding["finding"]
        for finding in findings
    }

    assert "ADMIN_SERVICE_EXPOSURE" in names

def test_scoped_admin_service_not_exposed():
    rule = base_rule()

    rule["service"] = "ssh"
    rule["source"] = "management-network"
    rule["destination"] = "application-server"

    findings = analyze_yaml_rules(rule)

    names = {
        finding["finding"]
        for finding in findings
    }

    assert "ADMIN_SERVICE_EXPOSURE" not in names
def test_yaml_database_exposure():
    rule = base_rule()

    rule["service"] = "1433"
    rule["environment"] = "mixed"

    findings = analyze_yaml_rules(rule)

    names = {
        finding["finding"]
        for finding in findings
    }

    assert "DB_EXPOSURE" in names


def test_scoped_database_service_not_exposed():
    rule = base_rule()

    rule["service"] = "1433"
    rule["source"] = "application-server"
    rule["destination"] = "database-server"
    rule["environment"] = "production"

    findings = analyze_yaml_rules(rule)

    names = {
        finding["finding"]
        for finding in findings
    }

    assert "DB_EXPOSURE" not in names

def test_count_condition_group():
    rule = base_rule()
    rule["source"] = "any"
    rule["destination"] = "any"

    group = {
        "count": {
            "at_least": 2,
            "conditions": [
                {"source": {"equals": "any"}},
                {"destination": {"equals": "any"}},
                {"service": {"equals": "any"}},
                {"environment": {"equals": "mixed"}},
            ],
        }
    }

    assert evaluate_condition_group(
        rule,
        group,
    ) is True