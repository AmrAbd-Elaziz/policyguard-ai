import pandas as pd


def yes_no(value):
    value = str(value).lower().strip()

    return "yes" if value in {
        "yes", "true", "enabled", "enable"
    } else "no"


def parse_paloalto_csv(file_path):
    """
    Parse a Palo Alto-style CSV export and convert
    it into PolicyGuard's normalized rule schema.
    """

    df = pd.read_csv(file_path).fillna("")

    required_columns = {
        "Name",
        "Source",
        "Destination",
        "Service",
        "Action",
    }

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing Palo Alto columns: {sorted(missing)}"
        )

    rules = []

    for index, row in df.iterrows():

        rule = {
            "rule_id": f"PA-{index + 1:03}",
            "source": str(row["Source"]).strip(),
            "destination": str(row["Destination"]).strip(),
            "service": str(row["Service"]).strip(),
            "action": str(row["Action"]).lower().strip(),

            "logging": yes_no(
                row.get("Log End", "")
            ),

            "security_profile": yes_no(
                row.get("Security Profile", "")
            ),

            "business_justification": str(
                row.get("Description", "")
            ).strip(),

            "environment": str(
                row.get("Environment", "production")
            ).lower().strip(),

            # Preserve vendor metadata
            "vendor": "paloalto",
            "original_name": str(
                row["Name"]
            ).strip(),
        }

        rules.append(rule)

    return rules