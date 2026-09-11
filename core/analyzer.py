from pathlib import Path

import yaml

def create_finding(rule, finding_type, severity, description, recommendation):
    return {
        "rule_id": rule["rule_id"],
        "finding": finding_type,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }

RULES_FILE = (
    Path(__file__).resolve().parent.parent
    / "rules"
    / "firewall_rules.yaml"
)


def load_detection_rules():
    with open(
        RULES_FILE,
        "r",
        encoding="utf-8",
    ) as f:
        data = yaml.safe_load(f) or {}

    return data.get("detections", [])

def condition_matches(value, condition):
    value = str(value).lower().strip()

    if "equals" in condition:
        expected = str(
            condition["equals"]
        ).lower().strip()

        if value != expected:
            return False

    if "not_equals" in condition:
        expected = str(
            condition["not_equals"]
        ).lower().strip()

        if value == expected:
            return False

    if "in" in condition:
        expected_values = {
            str(item).lower().strip()
            for item in condition["in"]
        }

        if value not in expected_values:
            return False

    if "not_in" in condition:
        excluded_values = {
            str(item).lower().strip()
            for item in condition["not_in"]
        }

        if value in excluded_values:
            return False

    if "empty" in condition:
        expected_empty = condition["empty"]

        is_empty = value == ""

        if is_empty != expected_empty:
            return False

    return True

def rule_matches_detection(rule, detection):
    # New nested DSL
    if "match" in detection:
        return evaluate_condition_group(
            rule,
            detection["match"],
        )

    # Backward compatibility
    conditions = detection.get(
        "conditions",
        {},
    )

    return evaluate_condition_group(
        rule,
        conditions,
    )

def analyze_yaml_rules(rule):
    findings = []

    for detection in load_detection_rules():
        if not rule_matches_detection(
            rule,
            detection,
        ):
            continue

        findings.append(
            {
                "rule_id": rule["rule_id"],
                "finding": detection["name"],
                "severity": detection["severity"],
                "description": detection.get(
                    "description",
                    "",
                ),
                "recommendation": detection.get(
                    "recommendation",
                    "",
                ),
                "detection_id": detection["id"],
            }
        )

    return findings

def analyze_rule(rule):
    findings = []
    findings.extend(analyze_yaml_rules(rule))
    source = str(rule["source"]).lower().strip()
    destination = str(rule["destination"]).lower().strip()
    service = str(rule["service"]).lower().strip()
    action = str(rule["action"]).lower().strip()
    logging = str(rule["logging"]).lower().strip()
    security_profile = str(rule["security_profile"]).lower().strip()
    justification = str(rule["business_justification"]).strip()
    environment = str(rule["environment"]).lower().strip()

    # PG-001 — Any-to-Any
    if source == "any" and destination == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "ANY_ANY_RULE",
                "CRITICAL",
                "The rule permits traffic from any source to any destination.",
                "Restrict the source and destination to approved systems or networks.",
            )
        )

    # PG-002 — Broad destination
    if destination == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "BROAD_DESTINATION",
                "HIGH",
                "The rule permits access to any destination.",
                "Replace 'any' with explicitly approved destinations.",
            )
        )


    # PG-007 — Test/production mixing
    if environment == "mixed" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "TEST_PROD_MIXING",
                "HIGH",
                "The rule mixes test and production environments.",
                "Separate test and production access using dedicated rules and zones.",
            )
        )

    # PG-008 — Any service
    if service == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "ANY_SERVICE",
                "HIGH",
                "The rule permits any service or port.",
                "Restrict the rule to explicitly required applications and ports.",
            )
        )

    # PG-009 — Broad source
    if source == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "BROAD_SOURCE",
                "HIGH",
                "The rule permits traffic from any source.",
                "Restrict the source to approved hosts, subnets, or management networks.",
            )
        )


    # PG-012 — Rule should be split
    split_conditions = 0

    if service == "any":
        split_conditions += 1

    if source == "any":
        split_conditions += 1

    if destination == "any":
        split_conditions += 1

    if environment == "mixed":
        split_conditions += 1

    if action == "allow" and split_conditions >= 2:
        findings.append(
            create_finding(
                rule,
                "RULE_NEEDS_SPLITTING",
                "MEDIUM",
                "The rule combines multiple broad access conditions and should be separated into more specific rules.",
                "Split the rule by source, destination, service, or environment to enforce least privilege.",
            )
        )

    return findings


def analyze_rules(rules):
    findings = []

    for rule in rules:
        findings.extend(
            analyze_rule(rule)
        )

    return findings

def evaluate_condition_group(rule, group):
    """
    Evaluate nested YAML condition groups.

    Supported:
    - all: every condition must match
    - any: at least one condition must match
    - field conditions using equals, not_equals,
      in, not_in, and empty
    """

    if "all" in group:
        return all(
            evaluate_condition_group(rule, item)
            for item in group["all"]
        )

    if "any" in group:
        return any(
            evaluate_condition_group(rule, item)
            for item in group["any"]
        )

    for field, condition in group.items():
        value = rule.get(field, "")

        if not condition_matches(
            value,
            condition,
        ):
            return False

    return True