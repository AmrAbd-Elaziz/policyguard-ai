from core.service import analyze_policy


def test_analyze_normalized_policy():
    report = analyze_policy(
        "data/sample_rules.csv",
        "normalized",
    )

    assert report["summary"][
        "rules_analyzed"
    ] == 8

    assert report["summary"][
        "findings_detected"
    ] == 22


def test_analyze_paloalto_policy():
    report = analyze_policy(
        "data/paloalto_sample.csv",
        "paloalto",
    )

    assert report["summary"][
        "rules_analyzed"
    ] == 6

    assert report["summary"][
        "findings_detected"
    ] == 17


def test_analyze_fortigate_policy():
    report = analyze_policy(
        "data/fortigate_sample.conf",
        "fortigate",
    )

    assert report["summary"][
        "rules_analyzed"
    ] == 5

    assert report["summary"][
        "findings_detected"
    ] == 14


def test_report_contains_expected_sections():
    report = analyze_policy(
        "data/fortigate_sample.conf",
        "fortigate",
    )

    assert "summary" in report
    assert "findings" in report
    assert "rules" in report