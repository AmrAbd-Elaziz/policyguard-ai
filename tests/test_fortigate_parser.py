from core.parsers.fortigate import (
    parse_fortigate_config,
)


def test_parse_fortigate_config():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    assert len(rules) == 5


def test_fortigate_any_any_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[0]

    assert rule["rule_id"] == "1"
    assert rule["source"] == "any"
    assert rule["destination"] == "any"
    assert rule["service"] == "any"
    assert rule["action"] == "allow"
    assert rule["logging"] == "no"


def test_fortigate_ssh_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[1]

    assert rule["source"] == "lab-admin-net"
    assert rule["destination"] == "lab-app-server"
    assert rule["service"] == "ssh"
    assert rule["logging"] == "yes"
    assert (
        rule["business_justification"]
        == "Approved lab administrative access"
    )


def test_fortigate_telnet_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[2]

    assert rule["service"] == "telnet"


def test_fortigate_mssql_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[3]

    assert rule["service"] == "1433"


def test_fortigate_deny_rule():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[4]

    assert rule["action"] == "deny"

def test_fortigate_security_profile_detection():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[1]

    assert rule["security_profile"] == "yes"


def test_fortigate_mixed_environment_detection():
    rules = parse_fortigate_config(
        "data/fortigate_sample.conf"
    )

    rule = rules[3]

    assert rule["environment"] == "mixed"

def test_fortigate_multiple_addresses_and_services(tmp_path):
    config = """
config firewall policy
    edit 10
        set srcaddr "lab-admin-net" "lab-vpn-net"
        set dstaddr "lab-app-server" "lab-db-server"
        set action accept
        set service "SSH" "HTTPS"
        set logtraffic all
    next
end
"""

    config_file = tmp_path / "fortigate_multi.conf"
    config_file.write_text(config)

    rules = parse_fortigate_config(
        config_file
    )

    rule = rules[0]

    assert rule["source"] == (
        "lab-admin-net,lab-vpn-net"
    )
    assert rule["destination"] == (
        "lab-app-server,lab-db-server"
    )
    assert rule["service"] == "ssh,https"


def test_fortigate_logtraffic_utm(tmp_path):
    config = """
config firewall policy
    edit 20
        set srcaddr "lab-user-net"
        set dstaddr "lab-app-server"
        set action accept
        set service "HTTPS"
        set logtraffic utm
    next
end
"""

    config_file = tmp_path / "fortigate_utm.conf"
    config_file.write_text(config)

    rules = parse_fortigate_config(
        config_file
    )

    assert rules[0]["logging"] == "yes"


def test_fortigate_missing_optional_fields(tmp_path):
    config = """
config firewall policy
    edit 30
        set srcaddr "lab-user-net"
        set dstaddr "lab-app-server"
        set action accept
        set service "HTTPS"
    next
end
"""

    config_file = tmp_path / "fortigate_minimal.conf"
    config_file.write_text(config)

    rules = parse_fortigate_config(
        config_file
    )

    rule = rules[0]

    assert rule["rule_id"] == "30"
    assert rule["logging"] == "no"
    assert rule["security_profile"] == "no"
    assert rule["business_justification"] == ""


def test_fortigate_quoted_comment(tmp_path):
    config = """
config firewall policy
    edit 40
        set srcaddr "lab-admin-net"
        set dstaddr "lab-app-server"
        set action accept
        set service "SSH"
        set comments "Approved temporary administrative access"
    next
end
"""

    config_file = tmp_path / "fortigate_comment.conf"
    config_file.write_text(config)

    rules = parse_fortigate_config(
        config_file
    )

    assert (
        rules[0]["business_justification"]
        == "Approved temporary administrative access"
    )


def test_fortigate_webfilter_profile(tmp_path):
    config = """
config firewall policy
    edit 50
        set srcaddr "lab-user-net"
        set dstaddr "any"
        set action accept
        set service "HTTPS"
        set webfilter-profile "lab-web-profile"
    next
end
"""

    config_file = tmp_path / "fortigate_profile.conf"
    config_file.write_text(config)

    rules = parse_fortigate_config(
        config_file
    )

    assert rules[0]["security_profile"] == "yes"

def test_fortigate_all_with_multiple_values(tmp_path):
    config = """
config firewall policy
    edit 60
        set srcaddr "all" "lab-admin-net"
        set dstaddr "lab-app-server"
        set action accept
        set service "ALL" "HTTPS"
        set logtraffic all
    next
end
"""

    config_file = tmp_path / "fortigate_all_multi.conf"
    config_file.write_text(config)

    rules = parse_fortigate_config(
        config_file
    )

    rule = rules[0]

    assert rule["source"] == "any,lab-admin-net"
    assert rule["service"] == "any"

def test_fortigate_append_and_unset(tmp_path):
    config = """
config firewall policy
    edit 70
        set srcaddr "lab-admin-net"
        append srcaddr "lab-vpn-net"
        set dstaddr "lab-app-server"
        set service "SSH"
        append service "HTTPS"
        set logtraffic all
        unset comments
    next
end
"""

    config_file = tmp_path / "fortigate_append_unset.conf"
    config_file.write_text(config)

    rules = parse_fortigate_config(
        config_file
    )

    rule = rules[0]

    assert rule["source"] == (
        "lab-admin-net,lab-vpn-net"
    )
    assert rule["service"] == "ssh,https"
    assert rule["business_justification"] == ""