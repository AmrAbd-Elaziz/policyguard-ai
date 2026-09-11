from core.analyzer import (
    load_control_mappings,
    get_control_mapping,
    analyze_rule,
)


def base_rule():
    return {
        "rule_id": "MAP-001",
        "source": "any",
        "destination": "any",
        "service": "any",
        "action": "allow",
        "logging": "no",
        "security_profile": "no",
        "business_justification": "",
        "environment": "production",
    }


def test_control_mappings_load():
    mappings = load_control_mappings()

    assert "ANY_ANY_RULE" in mappings
    assert "INSECURE_PROTOCOL" in mappings
    assert "LOGGING_GAP" in mappings


def test_any_any_rule_has_nist_mapping():
    mapping = get_control_mapping(
        "ANY_ANY_RULE"
    )

    assert "PR.AA-05" in mapping["nist_csf_2_0"]


def test_unknown_finding_returns_empty_mapping():
    mapping = get_control_mapping(
        "DOES_NOT_EXIST"
    )

    assert mapping["principles"] == []
    assert mapping["nist_csf_2_0"] == []
    assert mapping["cis_controls_8_1"] == []
    assert mapping["pci_dss_4"] == []


def test_finding_contains_control_mapping():
    findings = analyze_rule(
        base_rule()
    )

    any_any = next(
        finding
        for finding in findings
        if finding["finding"]
        == "ANY_ANY_RULE"
    )

    assert "control_mappings" in any_any
    assert (
        "Least Privilege"
        in any_any[
            "control_mappings"
        ]["principles"]
    )