import pytest

from core.parsers.paloalto import parse_paloalto_csv


def test_parse_paloalto_csv_success():
    rules = parse_paloalto_csv(
        "data/paloalto_sample.csv"
    )

    assert len(rules) == 6

    first_rule = rules[0]

    assert first_rule["rule_id"] == "PA-001"
    assert first_rule["source"] == "any"
    assert first_rule["destination"] == "any"
    assert first_rule["service"] == "any"
    assert first_rule["action"] == "allow"
    assert first_rule["vendor"] == "paloalto"


def test_paloalto_logging_mapping():
    rules = parse_paloalto_csv(
        "data/paloalto_sample.csv"
    )

    first_rule = rules[0]
    second_rule = rules[1]

    assert first_rule["logging"] == "no"
    assert second_rule["logging"] == "yes"


def test_paloalto_security_profile_mapping():
    rules = parse_paloalto_csv(
        "data/paloalto_sample.csv"
    )

    first_rule = rules[0]
    second_rule = rules[1]

    assert first_rule["security_profile"] == "no"
    assert second_rule["security_profile"] == "yes"


def test_paloalto_description_mapping():
    rules = parse_paloalto_csv(
        "data/paloalto_sample.csv"
    )

    rule = rules[1]

    assert (
        rule["business_justification"]
        == "Approved administrative access"
    )


def test_missing_required_columns(tmp_path):
    bad_csv = tmp_path / "bad_paloalto.csv"

    bad_csv.write_text(
        "Name,Source,Action\n"
        "Bad-Rule,any,allow\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Missing Palo Alto columns",
    ):
        parse_paloalto_csv(bad_csv)