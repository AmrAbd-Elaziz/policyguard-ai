VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
}


REQUIRED_FIELDS = {
    "id",
    "name",
    "severity",
    "description",
    "recommendation",
}


def validate_detection_rule(rule):
    errors = []

    missing_fields = [
        field
        for field in REQUIRED_FIELDS
        if not rule.get(field)
    ]

    if missing_fields:
        errors.append(
            f"Missing required fields: {', '.join(sorted(missing_fields))}"
        )

    severity = str(
        rule.get("severity", "")
    ).upper().strip()

    if severity and severity not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity: {severity}"
        )

    if "conditions" not in rule and "match" not in rule:
        errors.append(
            "Detection rule must define either 'conditions' or 'match'."
        )

    return errors


def validate_rule_pack(rules):
    errors = []

    seen_ids = set()

    for index, rule in enumerate(rules):
        rule_id = str(
            rule.get("id", "")
        ).strip()

        if rule_id:
            if rule_id in seen_ids:
                errors.append(
                    f"Duplicate detection ID: {rule_id}"
                )

            seen_ids.add(rule_id)

        rule_errors = validate_detection_rule(
            rule
        )

        for error in rule_errors:
            errors.append(
                f"Rule {rule_id or index}: {error}"
            )

    return errors