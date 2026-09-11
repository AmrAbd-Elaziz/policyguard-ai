from html import escape
from pathlib import Path


def _severity_class(severity):
    severity = str(severity).lower().strip()

    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }

    return mapping.get(severity, "info")


def _render_control_mappings(mappings):
    if not mappings:
        return "-"

    parts = []

    principles = mappings.get(
        "principles",
        [],
    )
    nist = mappings.get(
        "nist_csf_2_0",
        [],
    )
    cis = mappings.get(
        "cis_controls_8_1",
        [],
    )
    pci = mappings.get(
        "pci_dss_4",
        [],
    )

    if principles:
        parts.append(
            "<strong>Principles:</strong> "
            + ", ".join(
                escape(str(item))
                for item in principles
            )
        )

    if nist:
        parts.append(
            "<strong>NIST CSF 2.0:</strong> "
            + ", ".join(
                escape(str(item))
                for item in nist
            )
        )

    if cis:
        parts.append(
            "<strong>CIS Controls:</strong> "
            + ", ".join(
                escape(str(item))
                for item in cis
            )
        )

    if pci:
        parts.append(
            "<strong>PCI DSS:</strong> "
            + ", ".join(
                escape(str(item))
                for item in pci
            )
        )

    if not parts:
        return "-"

    return "<br>".join(parts)

def _unique_controls(findings, key):
    controls = set()

    for finding in findings:
        mappings = finding.get(
            "control_mappings",
            {},
        )

        for control in mappings.get(key, []):
            controls.add(str(control))

    return sorted(controls)


def _render_controls(controls):
    if not controls:
        return (
            '<span class="muted">'
            'No contextual references identified'
            '</span>'
        )

    return "".join(
        f'<span class="control-tag">'
        f'{escape(control)}'
        f'</span>'
        for control in controls
    )

def calculate_overall_risk(rule_results):
    scores = [
        int(rule.get("risk_score", 0))
        for rule in rule_results
    ]

    if not scores:
        return {
            "score": 0,
            "severity": "INFO",
        }

    highest_score = max(scores)

    if highest_score >= 80:
        severity = "CRITICAL"
    elif highest_score >= 60:
        severity = "HIGH"
    elif highest_score >= 35:
        severity = "MEDIUM"
    elif highest_score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "score": highest_score,
        "severity": severity,
    }


def generate_html_report(
    report,
    output_path,
):
    findings = report.get(
        "findings",
        [],
    )

    rule_results = report.get(
        "rules",
        [],
    )

    overall_risk = calculate_overall_risk(
    rule_results
    )

    overall_risk_score = overall_risk[
        "score"
    ]

    overall_risk_severity = overall_risk[
        "severity"
    ]

    summary = report.get(
        "summary",
        {},
    )

    rules_analyzed = summary.get(
        "rules_analyzed",
        0,
    )

    findings_detected = summary.get(
        "findings_detected",
        len(findings),
    )

    vendor = summary.get(
        "vendor",
        "unknown",
    )

    input_file = summary.get(
        "input_file",
        "",
    )

    critical_count = sum(
        1
        for finding in findings
        if finding.get(
            "severity",
            "",
        ).upper()
        == "CRITICAL"
    )

    high_count = sum(
        1
        for finding in findings
        if finding.get(
            "severity",
            "",
        ).upper()
        == "HIGH"
    )

    medium_count = sum(
        1
        for finding in findings
        if finding.get(
            "severity",
            "",
        ).upper()
        == "MEDIUM"
    )

    low_count = sum(
        1
        for finding in findings
        if finding.get(
            "severity",
            "",
        ).upper()
        == "LOW"
    )

    findings_rows = []

    for finding in findings:
        severity = finding.get(
            "severity",
            "INFO",
        )

        finding_name = escape(
            str(
                finding.get(
                    "finding",
                    "",
                )
            )
        )

        rule_id = escape(
            str(
                finding.get(
                    "rule_id",
                    "",
                )
            )
        )

        recommendation = escape(
            str(
                finding.get(
                    "recommendation",
                    "",
                )
            )
        )

        score = finding.get(
            "rule_risk_score",
            0,
        )

        priority = escape(
            str(
                finding.get(
                    "priority",
                    "",
                )
            )
        )

        mappings = (
            finding.get(
                "control_mappings",
                {},
            )
        )

        findings_rows.append(
            f"""
            <tr>
                <td>{rule_id}</td>
                <td>
                    <span class="badge {_severity_class(severity)}">
                        {escape(str(severity))}
                    </span>
                </td>
                <td>{score}</td>
                <td>{priority}</td>
                <td>{finding_name}</td>
                <td>{recommendation}</td>
                <td>
                    {_render_control_mappings(mappings)}
                </td>
            </tr>
            """
        )

    risk_rows = []

    sorted_rules = sorted(
        rule_results,
        key=lambda item: item.get(
            "risk_score",
            0,
        ),
        reverse=True,
    )

    for rule in sorted_rules:
        score = rule.get(
            "risk_score",
            0,
        )

        if score == 0:
            continue

        severity = rule.get(
            "severity",
            "INFO",
        )

        drivers = rule.get(
            "risk_drivers",
            [],
        )

        driver_html = "<br>".join(
            escape(str(driver))
            for driver in drivers
        )

        risk_rows.append(
            f"""
            <tr>
                <td>
                    {escape(str(rule.get("rule_id", "")))}
                </td>
                <td>{score}</td>
                <td>
                    <span class="badge {_severity_class(severity)}">
                        {escape(str(severity))}
                    </span>
                </td>
                <td>
                    {escape(str(rule.get("priority", "")))}
                </td>
                <td>{driver_html}</td>
            </tr>
            """
        )
    assessment_scope = f"""
    <div class="section">

    <h2>Assessment Scope</h2>

    <div class="info-grid">

    <div class="info-card">
    <strong>Firewall Vendor</strong>
    <div>{escape(str(vendor))}</div>
    </div>

    <div class="info-card">
    <strong>Input Source</strong>
    <div>{escape(str(input_file))}</div>
    </div>

    <div class="info-card">
    <strong>Rules Evaluated</strong>
    <div>{rules_analyzed}</div>
    </div>

    <div class="info-card">
    <strong>Findings Identified</strong>
    <div>{findings_detected}</div>
    </div>

    </div>

    </div>
    """

    assessment_methodology = """
    <div class="section">

    <h2>Assessment Methodology</h2>

    <div class="methodology-card">

    <ol>
    <li>
    <strong>Policy Normalization:</strong>
    Firewall policy data is converted into a common internal rule model.
    </li>

    <li>
    <strong>Deterministic Security Detection:</strong>
    Rules are evaluated against PolicyGuard security checks for excessive access,
    weak protocols, missing controls, and environment separation issues.
    </li>

    <li>
    <strong>Contextual Risk Scoring:</strong>
    Each rule receives a contextual risk score based on exposure,
    service sensitivity, security controls, logging, and business justification.
    </li>

    <li>
    <strong>Prioritization:</strong>
    Rules are assigned a remediation priority based on their calculated risk.
    </li>

    <li>
    <strong>Control Mapping:</strong>
    Applicable findings are mapped to contextual security control references
    such as NIST CSF 2.0, CIS Controls, and PCI DSS.
    </li>

    </ol>

    </div>

    </div>
    """

    nist_controls = _unique_controls(
        findings,
        "nist_csf_2_0",
    )

    cis_controls = _unique_controls(
        findings,
        "cis_controls_8_1",
    )

    pci_controls = _unique_controls(
        findings,
        "pci_dss_4",
    )

    framework_coverage = f"""
    <div class="section">

    <h2>Framework Coverage</h2>

    <p class="section-description">
    Contextual control references associated with findings
    identified during this assessment.
    </p>

    <div class="framework-grid">

    <div class="framework-card">
    <h3>NIST CSF 2.0</h3>
    <div class="control-tags">
    {_render_controls(nist_controls)}
    </div>
    </div>

    <div class="framework-card">
    <h3>CIS Controls</h3>
    <div class="control-tags">
    {_render_controls(cis_controls)}
    </div>
    </div>

    <div class="framework-card">
    <h3>PCI DSS</h3>
    <div class="control-tags">
    {_render_controls(pci_controls)}
    </div>
    </div>

    </div>

    <div class="mapping-note">
    These mappings provide contextual security references only
    and do not constitute a compliance determination.
    </div>

    </div>
    """
    executive_summary = f"""
    <div class="section">

    <h2>Executive Summary</h2>

    <div class="executive-grid">

    <div class="overall-risk-card">

    <div class="risk-label">
    Overall Risk Rating
    </div>

    <div class="overall-risk-value">
    <span class="badge {_severity_class(overall_risk_severity)}">
    {escape(str(overall_risk_severity))}
    </span>
    </div>

    <div class="overall-risk-score">
    Highest Rule Risk Score:
    <strong>{overall_risk_score}/100</strong>
    </div>

    </div>

    <div class="executive-text">

    The assessment analyzed
    <strong>{rules_analyzed}</strong>
    firewall rules and identified
    <strong>{findings_detected}</strong>
    security findings.

    The highest observed rule risk was
    <strong>{overall_risk_score}/100</strong>,
    resulting in an overall assessment rating of
    <strong>{escape(str(overall_risk_severity))}</strong>.

    PolicyGuard evaluates firewall policies using
    deterministic security detections, contextual risk
    scoring, remediation guidance, and control mapping.

    </div>

    </div>

    </div>
    """
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>PolicyGuard AI Security Assessment</title>

<style>

body {{
    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background:
        #0b1220;

    color:
        #e5e7eb;

    margin:
        0;

    padding:
        40px;
}}

.container {{
    max-width:
        1400px;

    margin:
        auto;
}}

.header {{
    margin-bottom:
        32px;
}}

.header h1 {{
    font-size:
        36px;

    margin-bottom:
        8px;
}}

.subtitle {{
    color:
        #94a3b8;
}}

.summary-grid {{
    display:
        grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                180px,
                1fr
            )
        );

    gap:
        16px;

    margin:
        28px 0;
}}

.card {{
    background:
        #111827;

    border:
        1px solid #1f2937;

    border-radius:
        12px;

    padding:
        20px;
}}

.card .number {{
    font-size:
        28px;

    font-weight:
        bold;

    margin-top:
        8px;
}}

.section {{
    margin-top:
        38px;
}}

.section h2 {{
    margin-bottom:
        16px;
}}

table {{
    width:
        100%;

    border-collapse:
        collapse;

    background:
        #111827;

    border-radius:
        12px;

    overflow:
        hidden;
}}

th {{
    background:
        #172033;

    text-align:
        left;

    padding:
        14px;
}}

td {{
    padding:
        14px;

    vertical-align:
        top;

    border-top:
        1px solid #1f2937;
}}

.badge {{
    display:
        inline-block;

    padding:
        4px 10px;

    border-radius:
        999px;

    font-size:
        12px;

    font-weight:
        bold;
}}

.critical {{
    background:
        #7f1d1d;
}}

.high {{
    background:
        #9a3412;
}}

.medium {{
    background:
        #854d0e;
}}

.low {{
    background:
        #075985;
}}

.info {{
    background:
        #334155;
}}

.meta {{
    background:
        #111827;

    padding:
        16px 20px;

    border-radius:
        12px;

    border:
        1px solid #1f2937;
}}

.footer {{
    margin-top:
        50px;

    color:
        #64748b;

    font-size:
        13px;
}}
.executive-grid {{
    display: grid;
    grid-template-columns:
        minmax(220px, 300px)
        1fr;
    gap: 20px;
}}

.overall-risk-card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 22px;
}}

.risk-label {{
    color: #94a3b8;
    margin-bottom: 14px;
}}

.overall-risk-value {{
    margin-bottom: 14px;
}}

.overall-risk-value .badge {{
    font-size: 16px;
    padding: 7px 14px;
}}

.overall-risk-score {{
    color: #cbd5e1;
}}

.executive-text {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 22px;
    line-height: 1.7;
    color: #cbd5e1;
}}

@media (max-width: 800px) {{
    .executive-grid {{
        grid-template-columns: 1fr;
    }}
}}
.info-grid {{
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(200px, 1fr)
        );
    gap: 16px;
}}

.info-card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 18px;
}}

.info-card strong {{
    display: block;
    color: #94a3b8;
    margin-bottom: 8px;
}}

.methodology-card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 22px;
    line-height: 1.7;
}}

.methodology-card li {{
    margin-bottom: 12px;
}}
.section-description {{
    color: #94a3b8;
    margin-bottom: 18px;
}}

.framework-grid {{
    display: grid;
    grid-template-columns:
        repeat(
            3,
            minmax(0, 1fr)
        );
    gap: 16px;
}}

.framework-card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 20px;
}}

.framework-card h3 {{
    margin-top: 0;
    margin-bottom: 16px;
}}

.control-tags {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}}

.control-tag {{
    background: #172033;
    border: 1px solid #334155;
    border-radius: 999px;
    padding: 6px 10px;
    font-size: 12px;
}}

.mapping-note {{
    color: #64748b;
    font-size: 13px;
    margin-top: 14px;
}}

.muted {{
    color: #64748b;
}}

@media (max-width: 800px) {{
    .framework-grid {{
        grid-template-columns: 1fr;
    }}
}}
</style>
</head>

<body>

<div class="container">

<div class="header">

<h1>PolicyGuard AI</h1>

<div class="subtitle">
Firewall Security Policy Assessment Report
</div>

</div>

<div class="meta">

<strong>Vendor:</strong>
{escape(str(vendor))}

<br>

<strong>Input:</strong>
{escape(str(input_file))}

</div>

{executive_summary}
<div class="summary-grid">

<div class="card">
Rules Analyzed
<div class="number">
{rules_analyzed}
</div>
</div>

<div class="card">
Total Findings
<div class="number">
{findings_detected}
</div>
</div>

<div class="card">
Critical
<div class="number">
{critical_count}
</div>
</div>

<div class="card">
High
<div class="number">
{high_count}
</div>
</div>

<div class="card">
Medium
<div class="number">
{medium_count}
</div>
</div>

<div class="card">
Low
<div class="number">
{low_count}
</div>
</div>

</div>
{assessment_scope}

{assessment_methodology}

{framework_coverage}

<div class="section">

<h2>Top Risky Rules</h2>

<table>

<thead>
<tr>
<th>Rule</th>
<th>Risk Score</th>
<th>Severity</th>
<th>Priority</th>
<th>Risk Drivers</th>
</tr>
</thead>

<tbody>

{"".join(risk_rows)}

</tbody>

</table>

</div>


<div class="section">

<h2>Security Findings</h2>

<table>

<thead>

<tr>
<th>Rule</th>
<th>Finding Severity</th>
<th>Rule Risk</th>
<th>Priority</th>
<th>Finding</th>
<th>Recommendation</th>
<th>Control Mapping</th>
</tr>

</thead>

<tbody>

{"".join(findings_rows)}

</tbody>

</table>

</div>


<div class="footer">

Generated by PolicyGuard AI.

<br>

Control mappings are contextual references and do not represent
a formal compliance determination.

</div>

</div>

</body>
</html>
"""

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        html,
        encoding="utf-8",
    )

    return str(
        output_path
    )