import shlex


SERVICE_MAP = {
    "ALL": "any",
    "SSH": "ssh",
    "TELNET": "telnet",
    "HTTP": "http",
    "HTTPS": "https",
    "RDP": "rdp",
    "MSSQL": "1433",
    "MYSQL": "3306",
}


SECURITY_PROFILE_KEYS = {
    "ips-sensor",
    "av-profile",
    "webfilter-profile",
    "application-list",
    "ssl-ssh-profile",
    "dnsfilter-profile",
    "emailfilter-profile",
    "dlp-sensor",
}


def _clean_value(value):
    if value is None:
        return ""

    value = value.strip()

    if value.lower() == "all":
        return "any"

    return value


def _normalize_service(values):
    if not values:
        return ""

    normalized = [
        SERVICE_MAP.get(
            value.upper(),
            value.lower(),
        )
        for value in values
    ]

    if "any" in normalized:
        return "any"

    return ",".join(normalized)


def _normalize_action(value):
    value = value.lower()

    if value == "accept":
        return "allow"

    if value == "deny":
        return "deny"

    return value


def _normalize_logging(value):
    value = value.lower()

    if value in {
        "all",
        "utm",
    }:
        return "yes"

    return "no"


def _normalize_security_profile(rule):
    for key in SECURITY_PROFILE_KEYS:
        value = str(
            rule.get(
                key,
                "",
            )
        ).strip()

        if value:
            return "yes"

    return "no"


def _detect_environment(rule):
    values = [
        str(rule.get("srcintf", "")),
        str(rule.get("dstintf", "")),
        " ".join(rule.get("srcaddr", [])),
        " ".join(rule.get("dstaddr", [])),
        str(rule.get("name", "")),
    ]

    combined = " ".join(
        values
    ).lower()

    has_test = any(
        token in combined
        for token in {
            "test",
            "dev",
            "qa",
            "uat",
        }
    )

    has_prod = any(
        token in combined
        for token in {
            "prod",
            "production",
        }
    )

    if has_test and has_prod:
        return "mixed"

    if has_test:
        return "test"

    return "production"


def parse_fortigate_config(path):
    rules = []

    current_rule = None
    inside_policy = False

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:
        for raw_line in file:
            line = raw_line.strip()

            if not line:
                continue

            if line == "config firewall policy":
                inside_policy = True
                continue

            if not inside_policy:
                continue

            if line == "end":
                break

            if line.startswith("edit "):
                rule_id = line.split(
                    maxsplit=1,
                )[1]

                current_rule = {
                    "rule_id": rule_id,
                    "name": "",
                    "srcintf": "",
                    "dstintf": "",
                    "srcaddr": [],
                    "dstaddr": [],
                    "service": [],
                    "action": "",
                    "logtraffic": "",
                    "comments": "",
                }

                continue

            if line == "next":
                if current_rule:
                    rules.append(
                        _normalize_rule(
                            current_rule
                        )
                    )

                current_rule = None
                continue

            if (
                current_rule is None
                or not line.startswith("set ")
            ):
                continue

            parts = shlex.split(line)

            if len(parts) < 3:
                continue

            key = parts[1]
            values = parts[2:]

            if key in {
                "srcaddr",
                "dstaddr",
                "service",
            }:
                current_rule[key] = values

            else:
                current_rule[key] = " ".join(
                    values
                )

    return rules


def _normalize_rule(rule):
    source = ",".join(
        _clean_value(value)
        for value in rule.get(
            "srcaddr",
            [],
        )
    )

    destination = ",".join(
        _clean_value(value)
        for value in rule.get(
            "dstaddr",
            [],
        )
    )

    return {
        "rule_id": str(
            rule.get(
                "rule_id",
                "",
            )
        ),
        "source": source,
        "destination": destination,
        "service": _normalize_service(
            rule.get(
                "service",
                [],
            )
        ),
        "action": _normalize_action(
            rule.get(
                "action",
                "",
            )
        ),
        "logging": _normalize_logging(
            rule.get(
                "logtraffic",
                "",
            )
        ),
        "security_profile": _normalize_security_profile(
            rule
        ),
        "business_justification": rule.get(
            "comments",
            "",
        ),
        "environment": _detect_environment(
            rule
        ),
    }