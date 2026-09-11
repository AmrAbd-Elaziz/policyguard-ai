from core.validation import (
    validate_detection_rule,
    validate_rule_pack,
)


def test_valid_detection_rule():
    rule = {
        "id": "PG-999",
        "name": "TEST_RULE",
        "severity": "HIGH",
        "description": "Test detection.",
        "recommendation": "Test recommendation.",
        "conditions": {
            "action": {
                "equals": "allow",
            }
        },
    }

    assert validate_detection_rule(rule) == []


def test_invalid_severity():
    rule = {
        "id": "PG-999",
        "name": "TEST_RULE",
        "severity": "EXTREME",
        "description": "Test detection.",
        "recommendation": "Test recommendation.",
        "conditions": {
            "action": {
                "equals": "allow",
            }
        },
    }

    errors = validate_detection_rule(rule)

    assert "Invalid severity: EXTREME" in errors


def test_duplicate_detection_id():
    rules = [
        {
            "id": "PG-001",
            "name": "RULE_ONE",
            "severity": "HIGH",
            "description": "Test.",
            "recommendation": "Fix.",
            "conditions": {
                "action": {
                    "equals": "allow",
                }
            },
        },
        {
            "id": "PG-001",
            "name": "RULE_TWO",
            "severity": "MEDIUM",
            "description": "Test.",
            "recommendation": "Fix.",
            "conditions": {
                "action": {
                    "equals": "deny",
                }
            },
        },
    ]

    errors = validate_rule_pack(rules)

    assert "Duplicate detection ID: PG-001" in errors
    
def test_rule_pack_rejects_missing_required_fields():
    rules = [
        {
            "id": "PG-999",
            "name": "BROKEN_RULE",
            "severity": "HIGH",
        }
    ]

    errors = validate_rule_pack(rules)

    assert errors
    assert any(
        "Missing required fields" in error
        for error in errors
    )