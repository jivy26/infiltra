import os
import subprocess
import sys
from bbot.bbot_parse import bbot_main
from bbot.check_bbot import is_bbot_installed, install_bbot
from updater import check_and_update
from icmpecho import run_fping

# Define colors
IT_MAG = "\033[35;3m"
BOLD_BLUE = "\033[34;1m"
COLOR_RESET = "\033[0m"
BOLD_CYAN = "\033[36;1m"
BOLD_GREEN = "\033[32;1m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[33;1m"


# AORT Integration
def run_aort(domain):
    os.system('clear')

    # Module Info Box
    message_lines = [
        "This module will look use AORT and DNSRecon",
        "to enumerate DNS information."
    ]

    # Determine the width of the box based on the longest message line
    width = max(len(line) for line in message_lines) + 4  # padding for the sides of the box

    # Print the top border of the box
    print("+" + "-" * (width - 2) + "+")

    # Print each line of the message, centered within the box
    for line in message_lines:
        print("| " + line.center(width - 4) + " |")

    # Print the bottom border of the box
    print("+" + "-" * (width - 2) + "+")
    # End Module Info Box

    print(f"{BOLD_CYAN}Running AORT for domain: {COLOR_RESET}{BOLD_GREEN}{domain}{COLOR_RESET}\n")

    script_directory = os.path.dirname(os.path.realpath(__file__))
    aort_script_path = os.path.join(script_directory, 'aort/AORT.py')
    aort_command = f"python3 {aort_script_path} -d {domain} -a -w -n --output aort_dns.txt"

    print(f"{BOLD_BLUE}AORT is starting, subdomains will be saved to aort_dns.txt.{COLOR_RESET}\n")

    try:
        # Call AORT and let it handle the output directly
        os.system(aort_command)
    except Exception as e:
        print(f"{BOLD_RED}An error occurred while running AORT: {e}{COLOR_RESET}")

    input(f"\n{BOLD_GREEN}Press Enter to return to proceed with DNSRecon...{COLOR_RESET}")


def run_bbot(domain, display_menu):
    # Check if bbot is installed
    if not is_bbot_installed():
        print("bbot is not installed, installing now...")
        install_bbot()

    # Clear the screen and display sample commands
    os.system('clear')
    print(f"{BOLD_CYAN}Select the bbot command to run:{COLOR_RESET}")
    print(f"{BOLD_YELLOW}All output is saved to the bbot/ folder\n{COLOR_RESET}")
    print(f"1. Enumerate Subdomains")
    print(f"2. Subdomains, Port Scans, and Web Screenshots")
    print(f"3. Subdomains and Basic Web Scan")
    print(f"4. Full Enumeration {BOLD_YELLOW}--- Enumerates subdomains, emails, cloud buckets, port scan with nmap, basic web scan, nuclei scan, and web screenshots{COLOR_RESET}")


    # Get user choice
    choice = input(f"\n{BOLD_GREEN}Enter your choice (1-4): {COLOR_RESET}").strip()

    # Map user choice to bbot command
    commands = {
        '1': "-f subdomain-enum",
        '2': "-f subdomain-enum -m nmap gowitness",
        '3': "-f subdomain-enum web-basic",
        '4': "-f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly",
    }

    if choice in commands:
        command = commands[choice]
        full_command = f"bbot -t {domain} {command} -o . --name bbot"
        print(f"{BOLD_YELLOW}Executing: {full_command}{COLOR_RESET}")
        try:
            os.system(full_command)
        except Exception as e:
            print(f"{BOLD_RED}An error occurred while running bbot: {e}{COLOR_RESET}")
    else:
        print(f"{BOLD_RED}Invalid choice, please enter a number from 1 to 4.{COLOR_RESET}")

    input(f"{BOLD_GREEN}Press any key to return to the menu...{COLOR_RESET}")
    os.system('clear')
    display_menu(get_version())


# DNSRecon Integration
def run_dnsrecon(domain):
    os.system('clear')
    print(f"{BOLD_CYAN}Running DNSRecon for domain: {COLOR_RESET}{BOLD_GREEN}{domain}{COLOR_RESET}\n")

    dnsrecon_command = f"dnsrecon -d {domain} -t std"

    print(f"{BOLD_BLUE}DNSRecon is starting, results will be saved to dnsrecon_results.json.{COLOR_RESET}\n")

    try:
        # Call DNSRecon and let it handle the output directly
        os.system(dnsrecon_command)
    except Exception as e:
        print(f"{BOLD_RED}An error occurred while running DNSRecon: {e}{COLOR_RESET}")

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")


# Function to check if dnsrecon is installed
def is_dnsrecon_installed():
    try:
        subprocess.run(["dnsrecon", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# Nikto Integration
def run_nikto(targets):
    os.system('clear')  # Clear the screen

    nikto_dir = 'nikto'
    os.makedirs(nikto_dir, exist_ok=True)  # Create the nikto directory if it doesn't exist

    # Check if the input is a file or a single host
    if os.path.isfile(targets):
        with open(targets) as file:
            hosts = file.read().splitlines()
    else:
        hosts = [targets]  # If it's a single host, put it in a list

    for host in hosts:
        output_filename = f"nikto_{host.replace(':', '_').replace('/', '_')}.txt"  # Replace special characters
        output_path = os.path.join(nikto_dir, output_filename)

        print(f"{BOLD_CYAN}Running Nikto for {host}.{COLOR_RESET}")
        nikto_command = f"nikto -h {host} -C all -Tuning 13 -o {output_path} -Format txt"

        try:
            # Run Nikto and save the output to a file
            subprocess.run(nikto_command, shell=True)
            print(f"{BOLD_GREEN}Nikto scan for {host} completed. Results saved to {output_path}.{COLOR_RESET}")
        except Exception as e:
            print(f"{BOLD_RED}An error occurred while running Nikto for {host}: {e}{COLOR_RESET}")

        print(f"{BOLD_YELLOW}---{COLOR_RESET}")

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")


# Handle FPING
def check_alive_hosts():
    os.system('clear')
    hosts_input = input(
        f"{BOLD_GREEN}Enter the file name containing a list of IPs or input a single IP address: {COLOR_RESET}").strip()
    if os.path.isfile(hosts_input):
        with open(hosts_input) as file:
            hosts = file.read().splitlines()
    else:
        hosts = [hosts_input]

    alive_hosts = run_fping(hosts)
    print(f"\n{BOLD_CYAN}Alive Hosts:{COLOR_RESET}")
    for host in alive_hosts:
        print(f"\n{BOLD_YELLOW}{host}{COLOR_RESET}")

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")


# Function to get the current version from a file
def get_version():
    # Get the directory in which the script is located
    dir_of_script = os.path.dirname(os.path.realpath(__file__))
    # Construct the full path to the version.txt file
    version_file_path = os.path.join(dir_of_script, "version.txt")
    with open(version_file_path, "r") as file:
        return file.read().strip()


# Function to run EyeWitness
def run_eyewitness():
    os.system('clear')  # Clear the screen at the beginning of the function
    script_directory = os.path.dirname(os.path.realpath(__file__))
    eyewitness_script_path = os.path.join(script_directory, 'eyewitness.py')

    # Set default file path
    default_file = 'aort_dns.txt'

    # Prompt user for input
    print(
        f"\n{BOLD_CYAN}If you provide a domain, it will enumerate subdomains and attempt to screenshot them after enumeration.{COLOR_RESET}")
    user_input = input(
        f"\n{BOLD_GREEN}Enter a single IP, domain, or path to a file with domains (leave blank to use default aort_dns.txt from nmap_grep): {COLOR_RESET}").strip()

    # Determine which file or IP to use
    if user_input:
        input_file = user_input  # Use the user-provided file or IP
    else:
        input_file = default_file

    # Inform the user which input will be used
    if os.path.isfile(input_file):
        print(f"Using file: {input_file}")
    else:
        print(f"Using IP/domain: {input_file}")

    # Run the EyeWitness Python script
    subprocess.run(['python3', eyewitness_script_path, input_file])

    input(
        f"{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu


# Function to run sslscan and parse results
def run_sslscanparse():
    os.system('clear')  # Clear the screen at the beginning of the function
    sslscan_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'sslscanparse.py')
    default_file = 'tcp_parsed/https-hosts.txt'

    # Module Info Box
    message_lines = [
        "This module will run SSLScans on all IPs provided",
        "and use regex to only parse SSLScans with findings."
    ]

    # Determine the width of the box based on the longest message line
    width = max(len(line) for line in message_lines) + 4  # padding for the sides of the box

    # Print the top border of the box
    print("+" + "-" * (width - 2) + "+")

    # Print each line of the message, centered within the box
    for line in message_lines:
        print("| " + line.center(width - 4) + " |")

    # Print the bottom border of the box
    print("+" + "-" * (width - 2) + "+")
    # End Module Info Box

    print(
        f"\n{BOLD_RED}By default, this scans 'https-hosts.txt' which might not include all forward-facing web servers on non-standard ports such as 10443, etc.{COLOR_RESET}")
    use_default = input(
        f"\n{BOLD_BLUE}Do you want to use the default https-hosts.txt file? (Y/n): {COLOR_RESET}").strip().lower()

    if use_default == '' or use_default.startswith('y'):
        input_file = default_file
    else:
        input_file = input(
            f"{BOLD_BLUE}Enter the path to your custom .txt file with HTTPS hosts: {COLOR_RESET}").strip()

    # Check if the file exists
    if not os.path.isfile(input_file):
        print(f"{BOLD_RED}The file {input_file} does not exist. Please enter a valid file name.{COLOR_RESET}")
        return

    # Run the sslscanparse script
    print(f"\n{BOLD_GREEN}Running sslscanparse.py on {input_file}{COLOR_RESET}")
    process = subprocess.Popen(['python3', sslscan_script_path, input_file], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()  # Wait for the subprocess to finish

    # Display the output
    print(stdout.decode())

    # Check for errors
    if stderr:
        print(f"{BOLD_RED}An error occurred:\n" + stderr.decode())

    input(f"{BOLD_BLUE}Press Enter to return to the menu...{COLOR_RESET}")


# Function to run whois script
def run_whois():
    os.system('clear')  # Clear the screen at the beginning of the function
    whois_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'whois_script.sh')

    # Module Info Box
    message_lines = [
        "This module will look for OrgName in all whois requests",
        "and parse the names 1 per line."
    ]

    # Determine the width of the box based on the longest message line
    width = max(len(line) for line in message_lines) + 4  # padding for the sides of the box

    # Print the top border of the box
    print("+" + "-" * (width - 2) + "+")

    # Print each line of the message, centered within the box
    for line in message_lines:
        print("| " + line.center(width - 4) + " |")

    # Print the bottom border of the box
    print("+" + "-" * (width - 2) + "+")
    # End Module Info Box

    ip_input = input(f"\n{BOLD_GREEN}Enter a single IP or path to a file with IPs: {COLOR_RESET}").strip()

    # Run the whois script
    print(f"\n{BOLD_GREEN}Running whois_script.sh on {ip_input}{COLOR_RESET}\n")
    process = subprocess.Popen(['bash', whois_script_path, ip_input], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()  # Wait for the subprocess to finish

    # Display the output
    print(stdout.decode())

    # Check for errors
    if stderr:
        print(f"{BOLD_RED}An error occurred:\n" + stderr.decode())

    input(
        f"{BOLD_GREEN}Press any key to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu


def run_ngrep(scan_type):
    os.system('clear')  # Clear the screen at the beginning of the function
    script_directory = os.path.dirname(os.path.realpath(__file__))
    ngrep_script_path = os.path.join(script_directory, 'nmap-grep.sh')
    output_file = f"{scan_type.lower()}.txt"  # Assume the output file is named tcp.txt or udp.txt based on the scan_type
    output_path = f"{scan_type.lower()}_parsed/"  # Assume the output folder is named tcp_parsed/ or udp_parsed/ based on the scan_type

    # Check if the output directory already exists
    if os.path.isdir(output_path):
        overwrite = input(f"The directory {output_path} already exists. Overwrite it? (y/n): ").strip().lower()
        if overwrite == 'y':
            subprocess.run(['rm', '-rf', output_path])  # Removes the directory recursively
        else:
            print(f"Not overwriting the existing directory {output_path}.")
            return  # Exit the function if the user does not want to overwrite

    # Continue with running the nmap-grep.sh script
    print(f"{BOLD_GREEN}Running nmap-grep.sh on {output_file} for {scan_type.upper()} scans{COLOR_RESET}")
    subprocess.run(['bash', ngrep_script_path, output_file, scan_type.upper()])
    input(
        f"{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu

### Start Menu
# Function to run nmap scan
def run_nmap():
    os.system('clear')  # Clear the screen at the beginning of the function
    ip_input = input(f"\n{BOLD_GREEN}Enter a single IP or path to a file with IPs: {COLOR_RESET}")
    print(f"\n{BOLD_CYAN} NMAP Scans will run the following commands for TCP and UDP: {COLOR_RESET}")
    print(f"\n{BOLD_CYAN} TCP: nmap -sSV --top-ports 4000 -Pn {COLOR_RESET}")
    print(f"{BOLD_CYAN} UDP: nmap -sU --top-ports 400 -Pn {COLOR_RESET}")
    scan_type = input(f"\n{BOLD_GREEN}Enter scan type (tcp/udp/both): {COLOR_RESET}").lower()
    script_directory = os.path.dirname(os.path.realpath(__file__))
    nmap_script_path = os.path.join(script_directory, 'nmap_scan.py')

    # Make sure the input is not empty
    if ip_input and scan_type in ['tcp', 'udp', 'both']:
        print(f"\n{BOLD_GREEN}Running nmap_scan.py from {nmap_script_path}{COLOR_RESET}")
        if scan_type in ['tcp', 'both']:
            tcp_command = ['qterminal', '-e', f'sudo python3 {nmap_script_path} {ip_input} tcp']
            subprocess.Popen(tcp_command)
        if scan_type in ['udp', 'both']:
            udp_command = ['qterminal', '-e', f'sudo python3 {nmap_script_path} {ip_input} udp']
            subprocess.Popen(udp_command)
        print(f"\n{BOLD_GREEN}Nmap {scan_type} scans launched in separate windows.{COLOR_RESET}")
    else:
        print(f"{BOLD_YELLOW}Invalid input. Make sure you enter a valid IP, file path, and scan type.{COLOR_RESET}")

    input(
        f"\n{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu


# OSINT Sub menu
def osint_submenu():
    os.system('clear')  # Clear the screen
    domain = ''

    while True:
        print(f"{BOLD_CYAN}OSINT Submenu for {domain}:{COLOR_RESET}")
        print("\n1. Set Domain")
        print("1. Run AORT and DNSRecon")
        print("2. Run bbot (useful for black-box pen testing)")
        print("3. Parse bbot results")
        print(f"\n{BOLD_RED}X. Return to main menu{COLOR_RESET}")

        choice = input(f"\n{BOLD_GREEN}Enter your choice: {COLOR_RESET}").lower()

        if choice == '1':
            domain = input(f"{BOLD_CYAN}Please Input the Domain (i.e. google.com): {COLOR_RESET}")
            print(f"{BOLD_GREEN}Domain set to: {domain}{COLOR_RESET}")
            input(f"{BOLD_CYAN}Press Enter to continue...{COLOR_RESET}")
            os.system('clear')
        if choice == '2':
            run_aort(domain)
            if is_dnsrecon_installed():
                run_dnsrecon(domain)
            else:
                print(f"{BOLD_RED}DNSRecon is not installed. Please install it to use this feature.{COLOR_RESET}")
                input(f"\n{BOLD_GREEN}Press Enter to return to the submenu...{COLOR_RESET}")
        elif choice == '3':
            run_bbot(domain, display_menu)
        elif choice == '4':
            bbot_main()
        elif choice == 'x':
            break
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.{COLOR_RESET}")


# Function to display the menu
def display_menu(version):
    os.system('clear')  # Clear the screen
    print(f"{BOLD_CYAN}External Penetration Test Script v{version}{COLOR_RESET}")
    print(f"{BOLD_YELLOW}https://github.com/jivy26/ept{COLOR_RESET}")
    print(f"{BOLD_YELLOW}Created by Joshua Ivy{COLOR_RESET}\n\n")

    menu_options = [
        ("1. Whois", "Perform WHOIS lookups and analyze the results."),
        ("2. ICMP Echo ", "Check if hosts are alive with ICMP echo requests."),
        ("3. OSINT and Black Box OSINT", "Gather data from publicly available sources."),
        ("4. NMAP Scans", "Discover open ports and services on the network."),
        ("5. Parse NMAP Scans", "Parse network scan output for quick insights."),
        ("6. SSLScan and Parse", "Check SSL/TLS services for known vulnerabilities."),
        ("7. Run EyeWitness", "Take screenshots and gather info from web services."),
        ("8. Nikto Web Scans", "Scan web servers to identify potential security issues.")
    ]

    for option, description in menu_options:
        print(f"{BOLD_GREEN}{option.ljust(30)}{COLOR_RESET}{description}")

    print(f"\n{BOLD_CYAN}Utilities:{COLOR_RESET}")
    print(f"{BOLD_GREEN}U. Update Check{COLOR_RESET}".ljust(30) + " Check for the latest updates of the script.")
    print(f"{BOLD_GREEN}X. Exit{COLOR_RESET}".ljust(30) + " Exit the application.\n")

    choice = input(f"{BOLD_GREEN}Enter your choice: {COLOR_RESET}").lower()
    return choice


# Main function
def main():
    version = get_version()
    while True:
        choice = display_menu(version)
        #choice = input(f"\n{BOLD_GREEN}Enter your choice: {COLOR_RESET}").lower()
        if choice == '1':
            run_whois()
        elif choice == '2':
            check_alive_hosts()
        elif choice == '3':
            osint_submenu()
        elif choice == '4':
            run_nmap()
        elif choice == '5':
            scan_type = input(f"{BOLD_GREEN}Enter the scan type that was run (TCP/UDP): {COLOR_RESET}").upper()
            run_ngrep(scan_type)
        elif choice == '6':
            run_sslscanparse()
        elif choice == '7':
            run_eyewitness()
        elif choice == '8':
            target_input = input(
                f"{BOLD_GREEN}Enter a single IP/domain or path to a file with IPs/domains: {COLOR_RESET}")
            run_nikto(target_input)
        elif choice == 'u':
            print("Checking for updates...")
            updated = check_and_update()
        elif choice == 'x':
            break
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.{COLOR_RESET}")


# Ensure the `packaging` library is installed
try:
    from packaging import version
except ImportError:
    print(
        f"{BOLD_RED}The 'packaging' library is required for version comparison. Please install it using 'pip install packaging'.{COLOR_RESET}")
    exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting...")
        sys.exit()