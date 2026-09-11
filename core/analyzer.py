def create_finding(rule, finding_type, severity, description, recommendation):
    return {
        "rule_id": rule["rule_id"],
        "finding": finding_type,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }


def analyze_rule(rule):
    findings = []

    source = str(rule["source"]).lower().strip()
    destination = str(rule["destination"]).lower().strip()
    service = str(rule["service"]).lower().strip()
    action = str(rule["action"]).lower().strip()
    logging = str(rule["logging"]).lower().strip()
    security_profile = str(rule["security_profile"]).lower().strip()
    justification = str(rule["business_justification"]).strip()
    environment = str(rule["environment"]).lower().strip()

    # PG-001 — Any-to-Any
    if source == "any" and destination == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "ANY_ANY_RULE",
                "CRITICAL",
                "The rule permits traffic from any source to any destination.",
                "Restrict the source and destination to approved systems or networks.",
            )
        )

    # PG-002 — Broad destination
    if destination == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "BROAD_DESTINATION",
                "HIGH",
                "The rule permits access to any destination.",
                "Replace 'any' with explicitly approved destinations.",
            )
        )

    # PG-003 — Insecure protocols
    if service in {"telnet", "ftp"} and action == "allow":
        findings.append(
            create_finding(
                rule,
                "INSECURE_PROTOCOL",
                "HIGH",
                f"The rule permits the insecure or clear-text service '{service}'.",
                "Use an encrypted alternative or document an approved exception.",
            )
        )

    # PG-004 — Missing logging
    if logging == "no" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "LOGGING_GAP",
                "MEDIUM",
                "Traffic allowed by this rule is not logged.",
                "Enable appropriate security logging and centralized monitoring.",
            )
        )

    # PG-005 — Missing security inspection
    if security_profile == "no" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "MISSING_SECURITY_PROFILE",
                "HIGH",
                "The allow rule does not have a security inspection profile.",
                "Apply the appropriate security inspection controls.",
            )
        )

    # PG-006 — Missing business justification
    if not justification and action == "allow":
        findings.append(
            create_finding(
                rule,
                "MISSING_BUSINESS_JUSTIFICATION",
                "MEDIUM",
                "No business justification is documented for this allow rule.",
                "Document the business owner, purpose and required access.",
            )
        )

    # PG-007 — Test/production mixing
    if environment == "mixed" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "TEST_PROD_MIXING",
                "HIGH",
                "The rule mixes test and production environments.",
                "Separate test and production access using dedicated rules and zones.",
            )
        )

    # PG-008 — Any service
    if service == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "ANY_SERVICE",
                "HIGH",
                "The rule permits any service or port.",
                "Restrict the rule to explicitly required applications and ports.",
            )
        )

    # PG-009 — Broad source
    if source == "any" and action == "allow":
        findings.append(
            create_finding(
                rule,
                "BROAD_SOURCE",
                "HIGH",
                "The rule permits traffic from any source.",
                "Restrict the source to approved hosts, subnets, or management networks.",
            )
        )

    # PG-010 — Administrative service exposure
    admin_services = {
        "ssh",
        "rdp",
        "telnet",
        "winrm",
    }

    if (
        service in admin_services
        and action == "allow"
        and (
            source == "any"
            or destination == "any"
        )
    ):
        findings.append(
            create_finding(
                rule,
                "ADMIN_SERVICE_EXPOSURE",
                "HIGH",
                f"Administrative service '{service}' is exposed with a broad source or destination.",
                "Restrict administrative access to approved jump hosts or management networks.",
            )
        )

    # PG-011 — Database exposure
    database_services = {
        "1433",
        "3306",
        "5432",
        "1521",
    }

    if (
        service in database_services
        and action == "allow"
        and (
            source == "any"
            or destination == "any"
            or environment == "mixed"
        )
    ):
        findings.append(
            create_finding(
                rule,
                "DB_EXPOSURE",
                "HIGH",
                f"Database service '{service}' is exposed across a broad or mixed environment.",
                "Restrict database access to approved application hosts and dedicated zones.",
            )
        )

    # PG-012 — Rule should be split
    split_conditions = 0

    if service == "any":
        split_conditions += 1

    if source == "any":
        split_conditions += 1

    if destination == "any":
        split_conditions += 1

    if environment == "mixed":
        split_conditions += 1

    if action == "allow" and split_conditions >= 2:
        findings.append(
            create_finding(
                rule,
                "RULE_NEEDS_SPLITTING",
                "MEDIUM",
                "The rule combines multiple broad access conditions and should be separated into more specific rules.",
                "Split the rule by source, destination, service, or environment to enforce least privilege.",
            )
        )

    return findings


def analyze_rules(rules):
    findings = []

    for rule in rules:
        findings.extend(
            analyze_rule(rule)
        )

    return findings