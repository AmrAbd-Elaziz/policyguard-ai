import json
import os
import tempfile

import pandas as pd
import streamlit as st

from core.reporting import (
    generate_html_report,
    calculate_overall_risk,
)
from core.service import analyze_policy


st.set_page_config(
    page_title="PolicyGuard AI",
    page_icon="🛡️",
    layout="wide",
)


# --------------------------------------------------
# Styling
# --------------------------------------------------

st.markdown(
    """
    <style>
        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }

        .pg-title {
            font-size: 2.6rem;
            font-weight: 750;
            margin-bottom: 0;
        }

        .pg-subtitle {
            color: #9aa4b2;
            font-size: 1rem;
            margin-top: 0.2rem;
            margin-bottom: 1.7rem;
        }

        .pg-card {
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 18px;
            background: rgba(255,255,255,0.025);
        }

        .pg-label {
            color: #9aa4b2;
            font-size: 0.82rem;
            margin-bottom: 4px;
        }

        .pg-value {
            font-size: 2rem;
            font-weight: 700;
        }

        .pg-note {
            border-left: 3px solid #4da3ff;
            padding: 10px 14px;
            background: rgba(77,163,255,0.05);
            margin-top: 1rem;
            margin-bottom: 1rem;
        }

        div[data-testid="stMetric"] {
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 14px 16px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# Header
# --------------------------------------------------

st.markdown(
    """
    <div class="pg-title">
        🛡️ PolicyGuard AI
    </div>

    <div class="pg-subtitle">
        Firewall Security Policy Analysis,
        Risk Prioritization & Control Mapping
    </div>
    """,
    unsafe_allow_html=True,
)

st.write(
    "Upload a firewall policy to identify security findings, "
    "calculate contextual risk, prioritize remediation, "
    "and generate assessment reports."
)

st.markdown(
    """
    <div class="pg-note">
        <strong>Deterministic security analysis:</strong>
        detection and risk decisions are produced by the PolicyGuard
        rules engine. No external AI model is required for analysis.
    </div>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# Input
# --------------------------------------------------

vendor = st.selectbox(
    "Policy Format",
    options=[
        "normalized",
        "paloalto",
        "fortigate",
    ],
    format_func=lambda value: {
        "normalized": "Normalized CSV / JSON",
        "paloalto": "Palo Alto-style CSV",
        "fortigate": "FortiGate Configuration",
    }[value],
)

uploaded_file = st.file_uploader(
    "Upload Firewall Policy",
    type=[
        "csv",
        "json",
        "conf",
        "txt",
    ],
)


# --------------------------------------------------
# Analysis
# --------------------------------------------------

if uploaded_file is not None:
    suffix = os.path.splitext(
        uploaded_file.name
    )[1]

    temp_path = None
    html_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
        ) as temp_file:
            temp_file.write(
                uploaded_file.getvalue()
            )

            temp_path = temp_file.name

        report = analyze_policy(
            temp_path,
            vendor,
        )
        
        report["summary"]["input_file"] = (
            uploaded_file.name
        )

        summary = report["summary"]
        findings = report["findings"]
        rules = report["rules"]

        overall_risk = calculate_overall_risk(
            rules
        )

        highest_score = overall_risk[
            "score"
        ]

        highest_severity = overall_risk[
            "severity"
        ]

        p1_rules = sum(
            1
            for rule in rules
            if rule["priority"] == "P1"
        )

        st.success(
            "Policy analysis completed successfully."
        )

        # --------------------------------------------------
        # Executive Metrics
        # --------------------------------------------------

        st.subheader("Executive Risk Summary")

        col1, col2, col3, col4, col5 = (
            st.columns(5)
        )

        col1.metric(
            "Rules Analyzed",
            summary["rules_analyzed"],
        )

        col2.metric(
            "Findings",
            summary["findings_detected"],
        )

        col3.metric(
            "Highest Risk",
            f"{highest_score}/100",
        )

        col4.metric(
            "Overall Severity",
            highest_severity,
        )

        col5.metric(
            "P1 Rules",
            p1_rules,
        )

        # --------------------------------------------------
        # Risk Overview
        # --------------------------------------------------

        st.divider()
        st.subheader("Rule Risk Overview")

        risk_df = pd.DataFrame(
            rules
        )

        if not risk_df.empty:
            risk_display = risk_df[
                [
                    "rule_id",
                    "risk_score",
                    "severity",
                    "priority",
                ]
            ].sort_values(
                by="risk_score",
                ascending=False,
            )

            st.dataframe(
                risk_display,
                use_container_width=True,
                hide_index=True,
            )

            chart_df = (
                risk_display
                .set_index("rule_id")[
                    ["risk_score"]
                ]
            )

            st.bar_chart(
                chart_df
            )

        else:
            st.info(
                "No firewall rules were identified."
            )

        # --------------------------------------------------
        # Top Risky Rules
        # --------------------------------------------------

        st.subheader("Top Risky Rules")

        risky_rules = [
            rule
            for rule in sorted(
                rules,
                key=lambda item: item[
                    "risk_score"
                ],
                reverse=True,
            )
            if rule["risk_score"] > 0
        ][:5]

        if risky_rules:
            for rule in risky_rules:
                with st.expander(
                    f"Rule {rule['rule_id']} "
                    f"— {rule['risk_score']}/100 "
                    f"({rule['priority']})"
                ):
                    st.write(
                        f"**Severity:** "
                        f"{rule['severity']}"
                    )

                    st.write(
                        "**Risk Drivers:**"
                    )

                    for driver in rule[
                        "risk_drivers"
                    ]:
                        st.write(
                            f"- {driver}"
                        )
        else:
            st.success(
                "No elevated-risk rules identified."
            )

        # --------------------------------------------------
        # Findings Filters
        # --------------------------------------------------

        st.divider()
        st.subheader("Security Findings")

        findings_df = pd.DataFrame(
            findings
        )

        if not findings_df.empty:
            filter_col1, filter_col2 = (
                st.columns(2)
            )

            severities = sorted(
                findings_df[
                    "severity"
                ].dropna().unique()
            )

            priorities = sorted(
                findings_df[
                    "priority"
                ].dropna().unique()
            )

            selected_severities = (
                filter_col1.multiselect(
                    "Severity",
                    severities,
                    default=severities,
                )
            )

            selected_priorities = (
                filter_col2.multiselect(
                    "Priority",
                    priorities,
                    default=priorities,
                )
            )

            filtered_findings = (
                findings_df[
                    findings_df[
                        "severity"
                    ].isin(
                        selected_severities
                    )
                    &
                    findings_df[
                        "priority"
                    ].isin(
                        selected_priorities
                    )
                ]
            )

            display_columns = [
                "rule_id",
                "severity",
                "rule_risk_score",
                "priority",
                "finding",
                "recommendation",
            ]

            st.dataframe(
                filtered_findings[
                    display_columns
                ],
                use_container_width=True,
                hide_index=True,
            )

        else:
            st.success(
                "No security findings detected."
            )

        # --------------------------------------------------
        # Remediation View
        # --------------------------------------------------

        st.subheader(
            "Prioritized Remediation"
        )

        if findings:
            seen = set()

            sorted_findings = sorted(
                findings,
                key=lambda item: (
                    item["priority"],
                    -item[
                        "rule_risk_score"
                    ],
                ),
            )

            for finding in sorted_findings:
                key = (
                    finding["rule_id"],
                    finding["finding"],
                )

                if key in seen:
                    continue

                seen.add(key)

                st.markdown(
                    f"""
                    **{finding['priority']} —
                    Rule {finding['rule_id']} —
                    {finding['finding']}**

                    {finding['recommendation']}
                    """
                )

        # --------------------------------------------------
        # Reports
        # --------------------------------------------------

        st.divider()
        st.subheader(
            "Assessment Reports"
        )

        json_report = json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
        )

        html_path = (
            temp_path
            + "-policyguard-report.html"
        )

        generate_html_report(
            report,
            html_path,
        )

        with open(
            html_path,
            "r",
            encoding="utf-8",
        ) as file:
            html_report = file.read()

        download_col1, download_col2 = (
            st.columns(2)
        )

        download_col1.download_button(
            "⬇ Download JSON Report",
            json_report,
            file_name=(
                f"{vendor}-"
                "policyguard-report.json"
            ),
            mime="application/json",
            use_container_width=True,
        )

        download_col2.download_button(
            "⬇ Download HTML Report",
            html_report,
            file_name=(
                f"{vendor}-"
                "policyguard-report.html"
            ),
            mime="text/html",
            use_container_width=True,
        )

        st.caption(
            "PolicyGuard provides security engineering "
            "decision support. Control mappings are contextual "
            "references and do not constitute a compliance "
            "certification or determination."
        )

    except Exception as exc:
        st.error(
            f"Analysis failed: {exc}"
        )

    finally:
        if (
            temp_path
            and os.path.exists(temp_path)
        ):
            os.remove(temp_path)

        if (
            html_path
            and os.path.exists(html_path)
        ):
            os.remove(html_path)