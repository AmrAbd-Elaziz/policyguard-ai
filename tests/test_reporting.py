from core.reporting import (
    _build_remediation_items,
    _unique_controls,
    _render_controls,
    calculate_overall_risk,
    generate_html_report,
)

def test_build_remediation_items_sorts_and_deduplicates():
    findings = [
        {
            "rule_id": "R002",
            "finding": "LOGGING_GAP",
            "recommendation": "Enable logging.",
            "priority": "P3",
            "rule_risk_score": 40,
        },
        {
            "rule_id": "R001",
            "finding": "ANY_ANY_RULE",
            "recommendation": "Restrict the rule.",
            "priority": "P1",
            "rule_risk_score": 90,
        },
        {
            "rule_id": "R001",
            "finding": "ANY_ANY_RULE",
            "recommendation": "Restrict the rule.",
            "priority": "P1",
            "rule_risk_score": 90,
        },
        {
            "rule_id": "R003",
            "finding": "INSECURE_PROTOCOL",
            "recommendation": "Use a secure protocol.",
            "priority": "P4",
            "rule_risk_score": 25,
        },
    ]

    result = _build_remediation_items(findings)

    assert len(result) == 3

    assert result[0]["rule_id"] == "R001"
    assert result[0]["priority"] == "P1"

    assert result[1]["rule_id"] == "R002"
    assert result[1]["priority"] == "P3"

    assert result[2]["rule_id"] == "R003"
    assert result[2]["priority"] == "P4"

def test_unique_controls_returns_sorted_unique_values():
    findings = [
        {
            "control_mappings": {
                "nist_csf_2_0": [
                    "PR.AA-05",
                    "PR.IR-01",
                ]
            }
        },
        {
            "control_mappings": {
                "nist_csf_2_0": [
                    "PR.AA-05",
                    "PR.PS-04",
                ]
            }
        },
    ]

    result = _unique_controls(
        findings,
        "nist_csf_2_0",
    )

    assert result == [
        "PR.AA-05",
        "PR.IR-01",
        "PR.PS-04",
    ]


def test_render_controls_handles_empty_list():
    html = _render_controls([])

    assert (
        "No contextual references identified"
        in html
    )


def test_calculate_overall_risk_uses_highest_rule_score():
    rules = [
        {
            "risk_score": 28,
        },
        {
            "risk_score": 81,
        },
        {
            "risk_score": 49,
        },
    ]

    result = calculate_overall_risk(
        rules
    )

    assert result["score"] == 81
    assert result["severity"] == "CRITICAL"


def test_html_report_contains_required_sections(
    tmp_path,
):
    report = {
        "summary": {
            "rules_analyzed": 2,
            "findings_detected": 2,
            "vendor": "paloalto",
            "input_file": "sample.csv",
        },
        "findings": [
            {
                "rule_id": "PA-001",
                "finding": "ANY_ANY_RULE",
                "severity": "CRITICAL",
                "recommendation": (
                    "Restrict access."
                ),
                "rule_risk_score": 81,
                "priority": "P1",
                "control_mappings": {
                    "principles": [
                        "Least Privilege"
                    ],
                    "nist_csf_2_0": [
                        "PR.AA-05"
                    ],
                    "cis_controls_8_1": [
                        "12.2"
                    ],
                    "pci_dss_4": [
                        "1.3.1"
                    ],
                },
            },
            {
                "rule_id": "PA-002",
                "finding": "LOGGING_GAP",
                "severity": "MEDIUM",
                "recommendation": (
                    "Enable logging."
                ),
                "rule_risk_score": 35,
                "priority": "P3",
                "control_mappings": {
                    "principles": [
                        "Security Monitoring"
                    ],
                    "nist_csf_2_0": [
                        "PR.PS-04"
                    ],
                    "cis_controls_8_1": [
                        "13.6"
                    ],
                    "pci_dss_4": [],
                },
            },
        ],
        "rules": [
            {
                "rule_id": "PA-001",
                "risk_score": 81,
                "severity": "CRITICAL",
                "priority": "P1",
                "risk_drivers": [
                    "Broad source +18",
                    "Any service +20",
                ],
            },
            {
                "rule_id": "PA-002",
                "risk_score": 35,
                "severity": "MEDIUM",
                "priority": "P3",
                "risk_drivers": [
                    "Logging disabled +8"
                ],
            },
        ],
    }

    output_path = (
        tmp_path
        / "policyguard-report.html"
    )

    generate_html_report(
        report,
        output_path,
    )

    html = output_path.read_text(
        encoding="utf-8"
    )

    assert "Executive Summary" in html
    assert "Assessment Scope" in html
    assert "Assessment Methodology" in html
    assert "Framework Coverage" in html
    assert "Prioritized Remediation Plan" in html
    assert "Top Risky Rules" in html
    assert "Security Findings" in html

    assert "NIST CSF 2.0" in html
    assert "PR.AA-05" in html
    assert "PR.PS-04" in html
    assert "CIS Controls" in html
    assert "PCI DSS" in html

    assert "CRITICAL" in html
    assert "81/100" in html