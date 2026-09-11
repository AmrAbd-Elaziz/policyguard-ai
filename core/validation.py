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

SUPPORTED_OPERATORS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "empty",
}

SUPPORTED_GROUPS = {
    "all",
    "any",
    "count",
}

def validate_condition_group(group, path="match"):
    errors = []

    if not isinstance(group, dict):
        return [
            f"{path} must be a mapping."
        ]

    for key, value in group.items():
        if key in {"all", "any"}:
            if not isinstance(value, list):
                errors.append(
                    f"{path}.{key} must be a list."
                )
                continue

            for index, item in enumerate(value):
                errors.extend(
                    validate_condition_group(
                        item,
                        f"{path}.{key}[{index}]",
                    )
                )

            continue

        if key == "count":
            if not isinstance(value, dict):
                errors.append(
                    f"{path}.count must be a mapping."
                )
                continue

            if "at_least" not in value:
                errors.append(
                    f"{path}.count is missing 'at_least'."
                )

            if "conditions" not in value:
                errors.append(
                    f"{path}.count is missing 'conditions'."
                )

            conditions = value.get(
                "conditions",
                [],
            )

            if not isinstance(conditions, list):
                errors.append(
                    f"{path}.count.conditions must be a list."
                )
                continue

            for index, item in enumerate(conditions):
                errors.extend(
                    validate_condition_group(
                        item,
                        f"{path}.count.conditions[{index}]",
                    )
                )

            continue

        if not isinstance(value, dict):
            errors.append(
                f"{path}.{key} must define an operator mapping."
            )
            continue

        for operator in value:
            if operator not in SUPPORTED_OPERATORS:
                errors.append(
                    f"Unsupported operator '{operator}' at {path}.{key}."
                )

    return errors

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

    if "conditions" in rule:
        errors.extend(
            validate_condition_group(
                rule["conditions"],
                "conditions",
            )
        )

    if "match" in rule:
        errors.extend(
            validate_condition_group(
                rule["match"],
                "match",
            )
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
