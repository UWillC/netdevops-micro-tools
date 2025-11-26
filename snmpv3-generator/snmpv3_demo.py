import datetime


def generate_header(device: str, mode: str) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"""=== SNMPv3 Config Generator v0.4 DEMO ===

Mode   : {mode}
Device : {device}
Date   : {now}

"""
    return header


def generate_snmpv3_cli(user, group, auth_algo, auth_pass, priv_algo, priv_pass, host):
    cfg = f"""
! SNMPv3 demo config
snmp-server view ALL iso included
snmp-server group {group} v3 priv read ALL write ALL
snmp-server user {user} {group} v3 auth {auth_algo} {auth_pass} priv {priv_algo} {priv_pass}
snmp-server host {host} version 3 priv {user}
snmp-server enable traps
!
"""
    return cfg.strip()


def main():
    # Fixed demo values – always the same output for GIFs / documentation
    mode = "secure-default"
    device = "Cisco IOS XE"
    user = "monitoring"
    group = "monitoring_grp"
    host = "10.10.10.10"
    auth_algo = "SHA-256"
    priv_algo = "AES-256"
    auth_pass = "SecurePass123"
    priv_pass = "SecurePass123"

    header = generate_header(device, mode)
    config = generate_snmpv3_cli(
        user=user,
        group=group,
        auth_algo=auth_algo,
        auth_pass=auth_pass,
        priv_algo=priv_algo,
        priv_pass=priv_pass,
        host=host,
    )

    print(header)
    print(config)
    print("\n# Demo output – copy-paste to your lab switch.\n")


if __name__ == "__main__":
    main()
