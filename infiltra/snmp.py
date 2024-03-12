import os
import subprocess
from infiltra.utils import (console, BOLD_CYAN, RICH_GREEN, RICH_YELLOW, RICH_RED, list_txt_files,
                            BOLD_GREEN, BOLD_BLUE, DEFAULT_COLOR, clear_screen)


# Commonly used OIDs
oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"]  # sysDescr, sysUpTime, sysName


def run_snmp_operations():
    clear_screen()
    udp_parsed_dir = 'udp_parsed/'
    udp_hosts_file = 'snmp-hosts.txt'
    udp_hosts_path = os.path.join(udp_parsed_dir, udp_hosts_file)

    excluded_files = [
        'whois_',
        'icmpecho_',
        'sslscan.txt',
        'tcp.txt',
        'udp.txt'
    ]
    txt_files = list_txt_files(os.getcwd(), excluded_files)

    if os.path.isdir(udp_parsed_dir) and os.path.isfile(udp_hosts_path):
        txt_files.append(udp_hosts_path)  # Add the udp hosts file to the list of available file

    # Ask user to select the IP list file from the available txt files
    if not txt_files:
        console.print("No .txt files found for IP lists.", style=RICH_RED)
        return

    console.print(f"Please select an IP list file to use:", style=RICH_GREEN)
    for idx, file in enumerate(txt_files, start=1):
        print(f"{BOLD_CYAN}{idx}. {DEFAULT_COLOR}{file}")

    selection = input(f"\n{BOLD_BLUE}Enter your choice: {DEFAULT_COLOR}").strip()
    if not selection.isdigit() or not 1 <= int(selection) <= len(txt_files):
        console.print("Invalid selection. Exiting SNMP operations.", style=RICH_RED)
        return

    ip_list_file = txt_files[int(selection) - 1]  # Get the selected file
    usernames_file = "snmp/users.txt"
    passwords_file = "snmp/passwords.txt"
    attempt_limit = 4

    def snmpwalk(username, password, ip, oid):
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
            print(f"{BOLD_GREEN}Testing IP: {DEFAULT_COLOR}{ip}")
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
                                response = snmpwalk(username, password, ip, oid)
                                if 'Unknown user name' not in response:
                                    console.print(f"Attempt {attempt_count} for {username} with password: {password}", style=RICH_GREEN)
                                    console.print(f"Querying OID {oid}", style=RICH_GREEN)
                                    console.print(response, style=RICH_GREEN)
                                    break  # If a valid response is found, exit the password loop

            console.print(f"Total usernames attempted for IP {ip}: {username_count}", style=RICH_YELLOW)
