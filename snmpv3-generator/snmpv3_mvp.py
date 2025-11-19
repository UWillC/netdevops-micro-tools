def generate_snmpv3(user, auth_algo, auth_pass, priv_algo, priv_pass):
    config = f"""
snmp-server group {user}_grp v3 priv
snmp-server user {user} {user}_grp v3 auth {auth_algo} {auth_pass} priv {priv_algo} {priv_pass}
snmp-server view ALL iso included
snmp-server host 10.10.10.10 version 3 {user}
    """
    return config.strip()

if __name__ == "__main__":
    print("=== SNMPv3 Config Generator ===")
    user = input("Username: ")
    auth_algo = input("Auth algorithm (SHA/SHA-256/SHA-512): ")
    auth_pass = input("Auth password: ")
    priv_algo = input("Privacy algorithm (AES-128/AES-256): ")
    priv_pass = input("Privacy password: ")

    print("\nGenerated SNMPv3 config:\n")
    print(generate_snmpv3(user, auth_algo, auth_pass, priv_algo, priv_pass))
