import os
import subprocess
import ipaddress
import re
import sys
import pkg_resources
from infiltra.bbot.bbot_parse import bbot_main
from infiltra.bbot.check_bbot import is_bbot_installed, install_bbot
from infiltra.updater import check_and_update
from infiltra.icmpecho import run_fping
from colorama import init, Fore, Style


## Moved from ANSI to Colorama
# Initialize Colorama
init(autoreset=True)


# Define colors using Colorama
DEFAULT_COLOR = Fore.WHITE
IT_MAG = Fore.MAGENTA + Style.BRIGHT
BOLD_BLUE = Fore.BLUE + Style.BRIGHT
BOLD_CYAN = Fore.CYAN + Style.BRIGHT
BOLD_GREEN = Fore.GREEN + Style.BRIGHT
BOLD_RED = Fore.RED + Style.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style.BRIGHT


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

    print(f"{BOLD_CYAN}Running AORT for domain: {BOLD_GREEN}{domain}\n")

    script_directory = os.path.dirname(os.path.realpath(__file__))
    aort_script_path = os.path.join(script_directory, 'aort/AORT.py')
    aort_command = f"python3 {aort_script_path} -d {domain} -a -w -n --output aort_dns.txt"

    print(f"{BOLD_BLUE}AORT is starting, subdomains will be saved to aort_dns.txt.\n")

    try:
        # Call AORT and let it handle the output directly
        os.system(aort_command)
    except Exception as e:
        print(f"{BOLD_RED}An error occurred while running AORT: {e}")

    input(f"\n{BOLD_GREEN}Press Enter to return to proceed with DNSRecon...")


def run_bbot(domain, display_menu):
    # Check if bbot is installed
    if not is_bbot_installed():
        print("bbot is not installed, installing now...")
        install_bbot()

    # Clear the screen and display sample commands
    os.system('clear')
    print(f"{BOLD_CYAN}Select the bbot command to run:")
    print(f"{BOLD_YELLOW}All output is saved to the bbot/ folder\n")
    print(f"1. Enumerate Subdomains")
    print(f"2. Subdomains, Port Scans, and Web Screenshots")
    print(f"3. Subdomains and Basic Web Scan")
    print(f"4. Full Enumeration {BOLD_YELLOW}--- Enumerates subdomains, emails, cloud buckets, port scan with nmap, basic web scan, nuclei scan, and web screenshots")


    # Get user choice
    choice = input(f"\n{BOLD_GREEN}Enter your choice (1-4): ").strip()

    # Map user choice to bbot command
    commands = {
        '1': "-f subdomain-enum",
        '2': "-f subdomain-enum -m nmap gowitness",
        '3': "-f subdomain-enum web-basic",
        '4': "-f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly",
    }

    if choice.isdigit() in commands:
        command = commands[choice]
        full_command = f"bbot -t {domain} {command} -o . --name bbot"
        print(f"{BOLD_YELLOW}Executing: {full_command}")
        try:
            os.system(full_command)
        except Exception as e:
            print(f"{BOLD_RED}An error occurred while running bbot: {e}")
    else:
        print(f"{BOLD_RED}Invalid choice, please enter a number from 1 to 4.")

    input(f"{BOLD_GREEN}Press any key to return to the menu...")
    os.system('clear')
    display_menu(get_version())


# DNSRecon Integration
def run_dnsrecon(domain):
    os.system('clear')
    print(f"{BOLD_CYAN}Running DNSRecon for domain: {BOLD_GREEN}{domain}\n")

    dnsrecon_command = f"dnsrecon -d {domain} -t std"

    print(f"{BOLD_BLUE}DNSRecon is starting, results will be saved to dnsrecon_results.json.\n")

    try:
        # Call DNSRecon and let it handle the output directly
        os.system(dnsrecon_command)
    except Exception as e:
        print(f"{BOLD_RED}An error occurred while running DNSRecon: {e}")

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...")


# Function to check if dnsrecon is installed
def is_dnsrecon_installed():
    try:
        subprocess.run(["dnsrecon", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

# Nikto Integration


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname):
    if not hostname:
        return False
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def run_nikto(targets):
    os.system('clear')  # Clear the screen
    nikto_dir = 'nikto'
    os.makedirs(nikto_dir, exist_ok=True)  # Create the nikto directory if it doesn't exist
    hosts = targets
    # Check if the input is a file or a single host
    if os.path.isfile(targets):
        with open(targets) as file:
            hosts = file.read().splitlines()
    elif is_valid_ip(targets) or is_valid_hostname(targets):
        hosts = [targets]  # If it's a single host, put it in a list
    else:
        print(f"{BOLD_RED}Invalid target: {targets} is not a valid IP, hostname, or file.")
        return

    for host in hosts:
        output_filename = f"nikto_{host.replace(':', '_').replace('/', '_')}.txt"  # Replace special characters
        output_path = os.path.join(nikto_dir, output_filename)

        print(f"{BOLD_CYAN}Running Nikto for {host} in a new window.")
        nikto_command = f"nikto -h {host} -C all -Tuning 13 -o {output_path} -Format txt"

        # Open a new terminal window to run Nikto
        terminal_command = ['x-terminal-emulator', '-e', f'sudo {nikto_command}']
        subprocess.Popen(terminal_command)

    print(f"{BOLD_GREEN}Nikto scans launched in separate windows.")
    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...")


# Handle FPING
def check_alive_hosts():
    os.system('clear')
    hosts_input = input(f"{BOLD_GREEN}Enter the file name containing a list of IPs or input a single IP address: ").strip()

    # Check if input is a file or a valid IP
    if os.path.isfile(hosts_input):
        with open(hosts_input) as file:
            hosts = file.read().splitlines()
    elif is_valid_ip(hosts_input):
        hosts = [hosts_input]
    else:
        print(f"{BOLD_RED}Invalid input: {hosts_input} is neither a valid IP address nor a file path.")
        return

    alive_hosts = run_fping(hosts)
    print(f"\n{BOLD_CYAN}Alive Hosts:")
    for host in alive_hosts:
        print(f"\n{BOLD_YELLOW}{host}")

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...")


# Function to get the current version from a file
def get_version():
    try:
        # Read the version.txt from the package
        version_file_path = pkg_resources.resource_filename('infiltra', 'version.txt')
        with open(version_file_path, "r") as file:
            return file.read().strip()
    except Exception as e:
        print(f"Could not read version file: {e}")
        return "unknown"


# Function to run EyeWitness
def run_eyewitness(domain):
    os.system('clear')  # Clear the screen at the beginning of the function
    script_directory = os.path.dirname(os.path.realpath(__file__))
    eyewitness_script_path = os.path.join(script_directory, 'eyewitness.py')

    # Set default file path
    default_file = 'aort_dns.txt'

    # Prompt user for input
    print(
        f"\n{BOLD_CYAN}If you provide a domain, it will enumerate subdomains and attempt to screenshot them after enumeration.")
    user_input = input(
        f"\n{BOLD_GREEN}Enter a single IP, domain, or path to a file with domains (leave blank to use default aort_dns.txt from nmap_grep): ").strip()

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
        f"{BOLD_GREEN}Press Enter to return to the menu...")  # Allow users to see the message before returning to the menu


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
        f"\n{BOLD_RED}By default, this scans 'https-hosts.txt' which might not include all forward-facing web servers on non-standard ports such as 10443, etc.")
    use_default = input(
        f"\n{BOLD_BLUE}Do you want to use the default https-hosts.txt file? (Y/n): ").strip().lower()

    if use_default == '' or use_default.startswith('y'):
        input_file = default_file
    else:
        input_file = input(
            f"{BOLD_BLUE}Enter the path to your custom .txt file with HTTPS hosts: ").strip()

    # Check if the file exists
    if not os.path.isfile(input_file):
        print(f"{BOLD_RED}The file {input_file} does not exist. Please enter a valid file name.")
        return

    # Run the sslscanparse script
    print(f"\n{BOLD_GREEN}Running sslscanparse.py on {input_file}")
    process = subprocess.Popen(['python3', sslscan_script_path, input_file], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()  # Wait for the subprocess to finish

    # Display the output
    print(stdout.decode())

    # Check for errors
    if stderr:
        print(f"{BOLD_RED}An error occurred:\n" + stderr.decode())

    input(f"{BOLD_BLUE}Press Enter to return to the menu...")


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
    print(f"{BOLD_GREEN}+" + "-" * (width - 2) + f"+")

    # Print each line of the message, centered within the box
    for line in message_lines:
        print(f"{BOLD_GREEN}| " + line.center(width - 4) + f"{BOLD_GREEN} |")

    # Print the bottom border of the box
    print(f"{BOLD_GREEN}+" + "-" * (width - 2) + f"+")
    # End Module Info Box

    ip_input = input(f"\n{BOLD_GREEN}Enter a single IP or path to a file with IPs: ").strip()

    # Run the whois script
    print(f"\n{BOLD_GREEN}Running whois_script.sh on {ip_input}\n")
    process = subprocess.Popen(['bash', whois_script_path, ip_input], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()  # Wait for the subprocess to finish

    # Display the output
    print(stdout.decode())

    # Check for errors
    if stderr:
        print(f"{BOLD_RED}An error occurred:\n" + stderr.decode())

    input(
        f"{BOLD_GREEN}Press any key to return to the menu...")  # Allow users to see the message before returning to the menu


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
    print(f"{BOLD_GREEN}Running nmap-grep.sh on {output_file} for {scan_type.upper()} scans")
    subprocess.run(['bash', ngrep_script_path, output_file, scan_type.upper()])
    input(
        f"{BOLD_GREEN}Press Enter to return to the menu...")  # Allow users to see the message before returning to the menu

### Start Menu
# Function to run nmap scan
def run_nmap():
    os.system('clear')  # Clear the screen at the beginning of the function
    ip_input = input(f"\n{BOLD_GREEN}Enter a single IP or path to a file with IPs: ")

    # Check if ip_input is a valid IP address or a file path
    if not (is_valid_ip(ip_input) or os.path.isfile(ip_input)):
        print(f"{BOLD_RED}Invalid input: {ip_input} is neither a valid IP address nor a file path.")
        return

    print(f"\n{BOLD_CYAN}NMAP Scans will run the following commands for TCP and UDP: ")
    print(f"\n{BOLD_CYAN} TCP: nmap -sSV --top-ports 4000 -Pn ")
    print(f"{BOLD_CYAN} UDP: nmap -sU --top-ports 400 -Pn ")

    scan_type = input(f"\n{BOLD_GREEN}Enter scan type (tcp/udp/both): ").lower()

    # Validate scan_type
    if scan_type not in ['tcp', 'udp', 'both']:
        print(f"{BOLD_RED}Invalid scan type: {scan_type}. Please enter 'tcp', 'udp', or 'both'.")
        return

    script_directory = os.path.dirname(os.path.realpath(__file__))
    nmap_script_path = os.path.join(script_directory, 'nmap_scan.py')

    # Make sure the input is not empty
    if ip_input and scan_type in ['tcp', 'udp', 'both']:
        print(f"\n{BOLD_GREEN}Running nmap_scan.py from {nmap_script_path}")
        if scan_type in ['tcp', 'both']:
            tcp_command = ['qterminal', '-e', f'sudo python3 {nmap_script_path} {ip_input} tcp']
            subprocess.Popen(tcp_command)
        if scan_type in ['udp', 'both']:
            udp_command = ['qterminal', '-e', f'sudo python3 {nmap_script_path} {ip_input} udp']
            subprocess.Popen(udp_command)
        print(f"\n{BOLD_GREEN}Nmap {scan_type} scans launched in separate windows.")
    else:
        print(f"{BOLD_YELLOW}Invalid input. Make sure you enter a valid IP, file path, and scan type.")

    input(
        f"\n{BOLD_GREEN}Press Enter to return to the menu...")  # Allow users to see the message before returning to the menu


# OSINT Sub menu
def is_valid_domain(domain):
    # Basic pattern for validating a standard domain name
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    return re.match(pattern, domain) is not None

def osint_submenu():
    os.system('clear')  # Clear the screen
    domain = ''

    while True:
        print(f"{BOLD_CYAN}OSINT Submenu for {domain}:")
        if not domain:
            print(f"{BOLD_YELLOW}No domain has been set!\n")
        if not domain:
            print(f"{BOLD_YELLOW}1. Set Domain")
        else:
            print(f"{BOLD_GREEN}1. Set Domain")
        print("2. Run AORT and DNSRecon")
        print("3. Run bbot (useful for black-box pen testing)")
        print("4. Parse bbot results")
        print("5. Run EyeWitness")
        print(f"\n{BOLD_RED}X. Return to main menu")

        choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()

        if choice == '1':
            domain_input = input(f"{BOLD_CYAN}Please Input the Domain (i.e. google.com): ").strip()
            if is_valid_domain(domain_input):
                domain = domain_input
                print(f"{BOLD_GREEN}Domain set to: {domain}")
            else:
                print(f"{BOLD_RED}Invalid domain name. Please enter a valid domain.")
                continue
            input(f"{BOLD_CYAN}Press Enter to continue...")
            os.system('clear')
        elif choice == '2':
            run_aort(domain)
            if is_dnsrecon_installed():
                run_dnsrecon(domain)
            else:
                print(f"{BOLD_RED}DNSRecon is not installed. Please install it to use this feature.")
                input(f"\n{BOLD_GREEN}Press Enter to return to the submenu...")
        elif choice == '3':
            run_bbot(domain, display_menu)
        elif choice == '4':
            bbot_main()
        elif choice == '5':
            if domain:
                run_eyewitness(domain)  # Make sure domain is set before calling the function
            else:
                print(f"{BOLD_RED}Please set a domain first using option 1.")
        elif choice == 'x':
            break
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.")


# Function to display the menu

def get_ascii_art(text):
    # Run the toilet command with subprocess and capture the output
    try:
        result = subprocess.run(['toilet', '-f', 'mono9', '-F', 'gay', text], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        # Decode the result from bytes to a string and return it
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        return f"Error generating ASCII art: {e}"

def display_menu(version):
    os.system('clear')  # Clear the screen
    ascii_art = get_ascii_art("Infiltra")
    print(ascii_art)  # Print the ASCII art at the top of the menu
    print(f"{BOLD_CYAN}========================================================")
    print(f"{BOLD_CYAN}                Current Version: v{version}")
    print(f"{BOLD_YELLOW}            https://github.com/jivy26/ept")
    print(f"{BOLD_YELLOW}            Author: @jivy26")
    print(f"{BOLD_CYAN}========================================================\n")

    menu_options = [
        ("1. Whois", f"{DEFAULT_COLOR}Perform WHOIS lookups and parse results."),
        ("2. ICMP Echo ", f"{DEFAULT_COLOR}Ping requests and parse live hosts."),
        ("3. OSINT and Black Box OSINT", f"{DEFAULT_COLOR}AORT, DNS Recon, BBOT, and EyeWitness available."),
        ("4. NMAP Scans", f"{DEFAULT_COLOR}Discover open ports and services on the network."),
        ("5. Parse NMAP Scans", f"{DEFAULT_COLOR}Parse NMAP TCP/UDP Scans."),
        ("6. SSLScan and Parse", f"{DEFAULT_COLOR}Run SSLScan for Single IP or Range and Parse Findings."),
        ("7. Nikto Web Scans", f"{DEFAULT_COLOR}Scan web servers to identify potential security issues.")
    ]

    for option, description in menu_options:
        print(f"{BOLD_GREEN}{option.ljust(30)}{description}")

    print(f"\n{BOLD_CYAN}Utilities:")
    print(f"{BOLD_YELLOW}U. Update Check".ljust(30) + f"{DEFAULT_COLOR} Check for the latest updates of this tool.")
    print(f"{BOLD_RED}X. Exit".ljust(30) + f"{DEFAULT_COLOR} Exit the application.\n")

    choice = input(f"{BOLD_GREEN}Enter your choice: ").lower()
    return choice


# Main function
def main():
    version = get_version()
    while True:
        choice = display_menu(version)
        #choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()
        if choice == '1':
            run_whois()
        elif choice == '2':
            check_alive_hosts()
        elif choice == '3':
            osint_submenu()
        elif choice == '4':
            run_nmap()
        elif choice == '5':
            scan_type = input(f"{BOLD_GREEN}Enter the scan type that was run (TCP/UDP): ").upper()
            run_ngrep(scan_type)
        elif choice == '6':
            run_sslscanparse()
        elif choice == '7':
            target_input = input(
                f"{BOLD_GREEN}Enter a single IP/domain or path to a file with IPs/domains: ")
            run_nikto(target_input)
        elif choice == 'u':
            print("Checking for updates...")
            updated = check_and_update()
        elif choice == 'x':
            break
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.")


# Ensure the `packaging` library is installed
try:
    from packaging import version
except ImportError:
    print(
        f"{BOLD_RED}The 'packaging' library is required for version comparison. Please install it using 'pip install packaging'.")
    exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting...")
        sys.exit()
