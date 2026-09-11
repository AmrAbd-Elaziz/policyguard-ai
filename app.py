import json
import os
import argparse

from core.reporting import generate_html_report
from core.service import analyze_policy

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
        choices=["normalized", "paloalto","fortigate",],
        default="normalized",
        help="Firewall vendor/parser type",
    )

    args = parser.parse_args()

    input_file = args.input_file
    vendor = args.vendor

    # --------------------------------------------------
    # Load firewall rules
    # --------------------------------------------------

    report = analyze_policy(
        input_file,
        vendor,
    )

    findings = report["findings"]
    rule_results = report["rules"]

    # --------------------------------------------------
    # Header
    # --------------------------------------------------

    console.print("\n[bold]PolicyGuard AI[/bold]")
    console.print(f"Input file: {input_file}")
    console.print(f"Vendor: {vendor}")
    console.print("Firewall Security Policy Analyzer\n")

    console.print(
        f"Rules analyzed: "
        f"{report['summary']['rules_analyzed']}"
    )
    console.print(
        f"Findings detected: "
        f"{report['summary']['findings_detected']}\n"
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
    # JSON Report
    # --------------------------------------------------

    os.makedirs(
        "reports",
        exist_ok=True,
    )

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