from core.analyzer import (
    load_detection_rules,
    rule_matches_detection,
    analyze_yaml_rules,
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