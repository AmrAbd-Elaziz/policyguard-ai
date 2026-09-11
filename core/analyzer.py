from pathlib import Path
from functools import lru_cache

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

CONTROL_MAPPINGS_FILE = (
    Path(__file__).resolve().parent.parent
    / "rules"
    / "control_mappings.yaml"
)


@lru_cache(maxsize=1)
def load_control_mappings():
    with open(
        CONTROL_MAPPINGS_FILE,
        "r",
        encoding="utf-8",
    ) as f:
        data = yaml.safe_load(f) or {}

    return data.get("mappings", {})

def get_control_mapping(finding_name):
    mappings = load_control_mappings()

    return mappings.get(
        finding_name,
        {
            "principles": [],
            "nist_csf_2_0": [],
            "cis_controls_8_1": [],
            "pci_dss_4": [],
        },
    )


@lru_cache(maxsize=1)
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
    if "match" in detection:
        return evaluate_condition_group(
            rule,
            detection["match"],
        )

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

        finding_name = detection["name"]

        findings.append(
            {
                "rule_id": rule["rule_id"],
                "finding": finding_name,
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



    return attach_control_mappings(findings)

def attach_control_mappings(findings):
    for finding in findings:
        finding["control_mappings"] = (
            get_control_mapping(
                finding["finding"]
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
    Recursively evaluate YAML detection logic.

    Supported:
    - all
    - any
    - field conditions
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

    if "count" in group:
        count_config = group["count"]

        conditions = count_config.get(
            "conditions",
            [],
        )

        at_least = int(
            count_config.get(
                "at_least",
                1,
            )
        )

        matched = sum(
            1
            for item in conditions
            if evaluate_condition_group(rule, item)
        )

        return matched >= at_least
        

    for field, condition in group.items():
        value = rule.get(field, "")

        if not condition_matches(
            value,
            condition,
        ):
            return False

    return True