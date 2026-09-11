from core.analyzer import analyze_rule
from core.risk import calculate_rule_risk


def base_rule():
    return {
        "rule_id": "TEST-001",
        "source": "10.0.0.1",
        "destination": "10.0.0.2",
        "service": "https",
        "action": "allow",
        "logging": "yes",
        "security_profile": "yes",
        "business_justification": "Approved access",
        "environment": "production",
    }


def test_any_any_rule_detected():
    rule = base_rule()
    rule["source"] = "any"
    rule["destination"] = "any"
    rule["service"] = "any"
    rule["logging"] = "no"
    rule["security_profile"] = "no"
    rule["business_justification"] = ""

    findings = analyze_rule(rule)

    finding_names = {
        finding["finding"]
        for finding in findings
    }

    assert "ANY_ANY_RULE" in finding_names
    assert "BROAD_SOURCE" in finding_names
    assert "BROAD_DESTINATION" in finding_names
    assert "ANY_SERVICE" in finding_names
    assert "RULE_NEEDS_SPLITTING" in finding_names


def test_any_any_rule_is_critical():
    rule = base_rule()
    rule["source"] = "any"
    rule["destination"] = "any"
    rule["service"] = "any"
    rule["logging"] = "no"
    rule["security_profile"] = "no"
    rule["business_justification"] = ""

    risk = calculate_rule_risk(rule)

    assert risk["score"] == 81
    assert risk["severity"] == "CRITICAL"


def test_deny_rule_has_zero_risk():
    rule = base_rule()
    rule["action"] = "deny"
    rule["source"] = "any"
    rule["destination"] = "any"
    rule["service"] = "any"

    risk = calculate_rule_risk(rule)

    assert risk["score"] == 0
    assert risk["severity"] == "INFO"


def test_mixed_database_exposure():
    rule = base_rule()
    rule["service"] = "1433"
    rule["environment"] = "mixed"
    rule["business_justification"] = ""

    findings = analyze_rule(rule)

    finding_names = {
        finding["finding"]
        for finding in findings
    }

    assert "DB_EXPOSURE" in finding_names
    assert "TEST_PROD_MIXING" in finding_names

    risk = calculate_rule_risk(rule)

    assert risk["score"] == 49
    assert risk["severity"] == "MEDIUM"


def test_admin_service_without_broad_exposure():
    rule = base_rule()
    rule["service"] = "ssh"

    findings = analyze_rule(rule)

    finding_names = {
        finding["finding"]
        for finding in findings
    }

    assert "ADMIN_SERVICE_EXPOSURE" not in finding_names


def test_admin_service_with_broad_destination():
    rule = base_rule()
    rule["service"] = "ssh"
    rule["destination"] = "any"

    findings = analyze_rule(rule)

    finding_names = {
        finding["finding"]
        for finding in findings
    }

    assert "ADMIN_SERVICE_EXPOSURE" in finding_names


def test_clean_rule_has_no_findings():
    rule = base_rule()

    findings = analyze_rule(rule)

    assert findings == []

from core.risk import score_findings


def test_finding_severity_is_preserved():
    rule = {
        "rule_id": "T001",
        "source": "10.10.10.10",
        "destination": "any",
        "service": "https",
        "action": "allow",
        "logging": "yes",
        "security_profile": "yes",
        "business_justification": "Approved access",
        "environment": "production",
    }

    findings = analyze_rule(rule)

    scored_findings = score_findings(
        findings,
        [rule],
    )

    broad_destination = next(
        finding
        for finding in scored_findings
        if finding["finding"] == "BROAD_DESTINATION"
    )

    assert broad_destination["severity"] == "HIGH"
    assert broad_destination["rule_risk_score"] == 18
    assert broad_destination["rule_risk_severity"] == "LOW"
    assert broad_destination["priority"] == "P4"