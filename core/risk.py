ADMIN_SERVICES = {
    "ssh",
    "rdp",
    "telnet",
    "winrm",
}

INSECURE_SERVICES = {
    "telnet",
    "ftp",
}

DATABASE_SERVICES = {
    "1433",   # MSSQL
    "3306",   # MySQL
    "5432",   # PostgreSQL
    "1521",   # Oracle
}


def calculate_rule_risk(rule):
    score = 0
    breakdown = []

    source = str(rule.get("source", "")).lower().strip()
    destination = str(rule.get("destination", "")).lower().strip()
    service = str(rule.get("service", "")).lower().strip()
    action = str(rule.get("action", "")).lower().strip()
    logging = str(rule.get("logging", "")).lower().strip()
    security_profile = str(
        rule.get("security_profile", "")
    ).lower().strip()

    justification = str(
        rule.get("business_justification", "")
    ).strip()

    environment = str(
        rule.get("environment", "")
    ).lower().strip()

    if action != "allow":
        return {
            "score": 0,
            "severity": "INFO",
            "breakdown": [],
        }

    # Exposure
    if source == "any":
        score += 18
        breakdown.append("Broad source +18")

    if destination == "any":
        score += 18
        breakdown.append("Broad destination +18")

    # Service scope
    if service == "any":
        score += 20
        breakdown.append("Any service +20")

    # Administrative access
    if service in ADMIN_SERVICES:
        score += 15
        breakdown.append("Administrative service +15")

    if (
        service in ADMIN_SERVICES
        and (source == "any" or destination == "any")
    ):
        score += 10
        breakdown.append("Broad administrative exposure +10")

    # Insecure protocol
    if service in INSECURE_SERVICES:
        score += 18
        breakdown.append("Insecure protocol +18")

    # Database exposure
    if service in DATABASE_SERVICES:
        score += 12
        breakdown.append("Database service +12")

    if (
        service in DATABASE_SERVICES
        and environment == "mixed"
    ):
        score += 10
        breakdown.append("Database exposed across mixed environments +10")

    # Environment separation
    if environment == "mixed":
        score += 20
        breakdown.append("Test/production mixing +20")

    # Security controls
    if security_profile == "no":
        score += 10
        breakdown.append("Missing security profile +10")

    if logging == "no":
        score += 8
        breakdown.append("Logging disabled +8")

    # Governance
    if not justification:
        score += 7
        breakdown.append("Missing business justification +7")

    score = min(score, 100)

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "score": score,
        "severity": severity,
        "breakdown": breakdown,
    }

def get_priority(score):
    if score >= 80:
        return "P1"
    elif score >= 60:
        return "P2"
    elif score >= 35:
        return "P3"
    elif score > 0:
        return "P4"
    return "P5"


def score_findings(findings, rules):
    rule_index = {
        rule["rule_id"]: rule
        for rule in rules
    }

    for finding in findings:
        rule = rule_index.get(
            finding["rule_id"],
            {}
        )

        risk = calculate_rule_risk(rule)

        finding["rule_risk_score"] = risk["score"]
        finding["rule_risk_severity"] = risk["severity"]
        finding["risk_breakdown"] = risk["breakdown"]
        finding["priority"] = get_priority(
            risk["score"]
        )

    return findings

