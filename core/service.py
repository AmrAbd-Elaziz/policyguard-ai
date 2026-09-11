from core.parser import (
    load_firewall_rules,
    load_vendor_rules,
)
from core.analyzer import analyze_rules
from core.risk import (
    score_findings,
    calculate_rule_risk,
    get_priority,
)


def analyze_policy(input_file, vendor="normalized"):
    if vendor == "normalized":
        rules = load_firewall_rules(
            input_file
        )
    else:
        rules = load_vendor_rules(
            input_file,
            vendor,
        )

    findings = analyze_rules(rules)

    findings = score_findings(
        findings,
        rules,
    )

    findings = sorted(
        findings,
        key=lambda item: item[
            "rule_risk_score"
        ],
        reverse=True,
    )

    rule_results = []

    for rule in rules:
        risk = calculate_rule_risk(rule)

        rule_results.append(
            {
                "rule_id": rule["rule_id"],
                "risk_score": risk["score"],
                "severity": risk["severity"],
                "priority": get_priority(
                    risk["score"]
                ),
                "risk_drivers": risk[
                    "breakdown"
                ],
            }
        )

    return {
        "summary": {
            "rules_analyzed": len(rules),
            "findings_detected": len(findings),
            "vendor": vendor,
            "input_file": str(input_file),
        },
        "findings": findings,
        "rules": rule_results,
    }