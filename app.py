import json
import os
import argparse

from core.reporting import generate_html_report
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

from rich.console import Console
from rich.table import Table
from rich.panel import Panel


console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="PolicyGuard AI Firewall Security Policy Analyzer"
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        default="data/sample_rules.csv",
        help="Firewall policy file to analyze",
    )

    parser.add_argument(
        "--vendor",
        choices=["normalized", "paloalto"],
        default="normalized",
        help="Firewall vendor/parser type",
    )

    args = parser.parse_args()

    input_file = args.input_file
    vendor = args.vendor

    # --------------------------------------------------
    # Load firewall rules
    # --------------------------------------------------

    if vendor == "paloalto":
        rules = load_vendor_rules(
            input_file,
            vendor,
        )
    else:
        rules = load_firewall_rules(
            input_file
        )

    # --------------------------------------------------
    # Analyze rules
    # --------------------------------------------------

    findings = analyze_rules(rules)

    # Calculate contextual risk
    findings = score_findings(
        findings,
        rules,
    )

    # Sort findings by rule risk score
    findings = sorted(
        findings,
        key=lambda x: x["rule_risk_score"],
        reverse=True,
    )

    # --------------------------------------------------
    # Header
    # --------------------------------------------------

    console.print("\n[bold]PolicyGuard AI[/bold]")
    console.print(f"Input file: {input_file}")
    console.print(f"Vendor: {vendor}")
    console.print("Firewall Security Policy Analyzer\n")

    console.print(
        f"Rules analyzed: {len(rules)}"
    )
    console.print(
        f"Findings detected: {len(findings)}\n"
    )

    # --------------------------------------------------
    # Security Findings Table
    # --------------------------------------------------

    table = Table(
        title="Security Findings"
    )

    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Score")
    table.add_column("Priority")
    table.add_column("Finding")
    table.add_column("Recommendation")

    for finding in findings:
        table.add_row(
            finding["rule_id"],
            finding["severity"],
            str(finding["rule_risk_score"]),
            finding["priority"],
            finding["finding"],
            finding["recommendation"],
        )

    console.print(table)

    # --------------------------------------------------
    # Build Rule Risk Results
    # --------------------------------------------------

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
                "risk_drivers": risk["breakdown"],
            }
        )

    # --------------------------------------------------
    # JSON Report
    # --------------------------------------------------

    os.makedirs(
        "reports",
        exist_ok=True,
    )

    report = {
        "summary": {
            "rules_analyzed": len(rules),
            "findings_detected": len(findings),
            "vendor": vendor,
            "input_file": input_file,
        },
        "findings": findings,
        "rules": rule_results,
    }

    report_filename = (
    f"{vendor}-policyguard-report.json"
    )

    report_path = os.path.join(
    "reports",
    report_filename,
    )

    with open(
        report_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            report,
            f,
            indent=4,
            ensure_ascii=False,
        )

    console.print(
        f"\n[green]JSON report generated:[/green] "
        f"{report_path}"
    )
    
    html_report_filename = (
        f"{vendor}-policyguard-report.html"
    )

    html_report_path = os.path.join(
    "reports",
    html_report_filename,
    )   

    generate_html_report(
    report,
    html_report_path,
    )

    print(
        f"HTML report generated: "
        f"{html_report_path}"
    )


    # --------------------------------------------------
    # Rule Risk Summary
    # --------------------------------------------------

    console.print(
        "\n[bold]Rule Risk Summary[/bold]\n"
    )

    for result in rule_results:
        if result["risk_score"] == 0:
            continue

        drivers = "\n".join(
            f"- {driver}"
            for driver in result["risk_drivers"]
        )

        summary = (
            f"[bold]Risk Score:[/bold] "
            f"{result['risk_score']}/100\n"
            f"[bold]Severity:[/bold] "
            f"{result['severity']}\n"
            f"[bold]Priority:[/bold] "
            f"{result['priority']}\n\n"
            f"[bold]Risk Drivers:[/bold]\n"
            f"{drivers}"
        )

        console.print(
            Panel(
                summary,
                title=f"Rule {result['rule_id']}",
                expand=False,
            )
        )


if __name__ == "__main__":
    main()