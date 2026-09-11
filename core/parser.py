import json
import pandas as pd

from core.parsers.paloalto import parse_paloalto_csv
from core.parsers.fortigate import parse_fortigate_config

def normalize_rule(rule):
    return {
        "rule_id": str(rule.get("rule_id", "")).strip(),
        "source": str(rule.get("source", "")).strip(),
        "destination": str(rule.get("destination", "")).strip(),
        "service": str(rule.get("service", "")).strip(),
        "action": str(rule.get("action", "")).strip(),
        "logging": str(rule.get("logging", "")).strip(),
        "security_profile": str(rule.get("security_profile", "")).strip(),
        "business_justification": str(
            rule.get("business_justification", "")
        ).strip(),
        "environment": str(rule.get("environment", "")).strip(),
    }


def load_csv_rules(file_path):
    df = pd.read_csv(file_path)
    df = df.fillna("")

    rules = df.to_dict(orient="records")

    return [
        normalize_rule(rule)
        for rule in rules
    ]


def load_json_rules(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        rules = data.get("rules", [])
    elif isinstance(data, list):
        rules = data
    else:
        raise ValueError("Unsupported JSON structure.")

    return [
        normalize_rule(rule)
        for rule in rules
    ]


def load_firewall_rules(file_path):
    file_path_lower = file_path.lower()

    if file_path_lower.endswith(".csv"):
        return load_csv_rules(file_path)

    if file_path_lower.endswith(".json"):
        return load_json_rules(file_path)

    raise ValueError(
        "Unsupported input format. "
        "PolicyGuard currently supports CSV and JSON."
    )

def load_vendor_rules(file_path, vendor):
    vendor = vendor.lower().strip()

    if vendor == "paloalto":
        return parse_paloalto_csv(file_path)

    raise ValueError(
        f"Unsupported firewall vendor: {vendor}"
    )

def load_vendor_rules(file_path, vendor):
    vendor = vendor.lower().strip()

    if vendor == "paloalto":
        return parse_paloalto_csv(file_path)

    if vendor == "fortigate":
        return parse_fortigate_config(file_path)

    raise ValueError(
        f"Unsupported firewall vendor: {vendor}"
    )