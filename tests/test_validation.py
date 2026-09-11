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

def test_rejects_unsupported_operator():
    rule = {
        "id": "PG-997",
        "name": "BAD_OPERATOR",
        "severity": "HIGH",
        "description": "Test.",
        "recommendation": "Fix.",
        "conditions": {
            "service": {
                "contains": "ssh",
            }
        },
    }

    errors = validate_detection_rule(rule)

    assert any(
        "Unsupported operator 'contains'" in error
        for error in errors
    )


def test_count_requires_at_least():
    rule = {
        "id": "PG-998",
        "name": "BAD_COUNT",
        "severity": "HIGH",
        "description": "Test.",
        "recommendation": "Fix.",
        "match": {
            "count": {
                "conditions": [
                    {
                        "source": {
                            "equals": "any",
                        }
                    }
                ]
            }
        },
    }

    errors = validate_detection_rule(rule)

    assert any(
        "missing 'at_least'" in error
        for error in errors
    )


def test_all_requires_list():
    rule = {
        "id": "PG-999",
        "name": "BAD_ALL",
        "severity": "HIGH",
        "description": "Test.",
        "recommendation": "Fix.",
        "match": {
            "all": {
                "action": {
                    "equals": "allow",
                }
            }
        },
    }

    errors = validate_detection_rule(rule)

    assert any(
        "match.all must be a list" in error
        for error in errors
    )

from core.analyzer import load_detection_rules


def test_production_rule_pack_is_valid():
    rules = load_detection_rules()

    assert len(rules) == 12

    errors = validate_rule_pack(rules)

    assert errors == []