"""
Infiltra - Open-Source CLI Penetration Testing Tool To Automate Various Processes

This script is designed for automating various network and security tasks.
It integrates multiple tools and utilities to facilitate domain analysis, network scanning, vulnerability
assessment, and more. Key features include:

- WHOIS lookups and parsing: Automates the process of gathering and interpreting WHOIS data.
- ICMP Echo: Implements ping requests to identify live hosts in a network.
- OSINT and Black Box OSINT: Integrates tools like AORT and DNS Recon for open-source intelligence gathering.
- BBOT: Utilizes the black-box testing tool for detailed domain and network analysis.
- NMAP Scans: Offers functionalities to perform comprehensive port and service scanning.
- SSLScan and Parsing: Facilitates scanning for SSL vulnerabilities and interpreting the results.
- Nikto Web Scans: Implements Nikto for scanning web servers for potential security issues.
- Additional Utilities: Includes features for update checking, vulnerability scanning, and more.

The script provides a user-friendly command-line interface for easy navigation and execution of various tasks.

Author: @jivy26
GitHub: https://github.com/jivy26/infiltra
"""

import os
import subprocess
import sys

from colorama import init, Fore, Style

from infiltra.icmpecho import run_fping
from infiltra.nuclei import nuclei_main
from infiltra.project_handler import project_submenu, last_project_file_path
from infiltra.updater import check_and_update
from infiltra.utils import (is_valid_ip,  get_version, get_ascii_art, list_txt_files, read_file_lines,
                            is_valid_domain, clear_screen, run_subprocess)
from infiltra.submenus.web_enum_sub import website_enumeration_submenu
from infiltra.submenus.osint_sub import osint_submenu


# Moved from ANSI to Colorama
# Initialize Colorama
init(autoreset=True)


# Define colors using Colorama
DEFAULT_COLOR = Fore.WHITE
IT_MAG = Fore.MAGENTA + Style.BRIGHT
BOLD_BLUE = Fore.BLUE + Style.BRIGHT
BOLD_CYAN = Fore.CYAN + Style.BRIGHT
BOLD_GREEN = Fore.GREEN + Style.BRIGHT
BOLD_RED = Fore.RED + Style.BRIGHT
BOLD_MAG = Fore.MAGENTA + Style.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style.BRIGHT
BOLD_WHITE = Fore.WHITE + Style.BRIGHT

# Utility Functions, Need to integrate into utils.py

# Ensure libnotify-bin is installed for notify-send to work
subprocess.run(["sudo", "apt-get", "install", "-y", "libnotify-bin"], check=True)


def check_and_install_gnome_terminal():
    try:
        # Check if gnome-terminal is installed
        subprocess.run(["which", "gnome-terminal"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{BOLD_GREEN}gnome-terminal is installed.")
    except subprocess.CalledProcessError:
        # gnome-terminal is not installed; proceed with installation
        print(f"{BOLD_YELLOW}gnome-terminal is not installed. Installing now...")
        install_command = "sudo apt install gnome-terminal -y"
        try:
            subprocess.run(install_command.split(), check=True)
            print(f"{BOLD_GREEN}gnome-terminal installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"{BOLD_RED}Failed to install gnome-terminal: {e}")
            sys.exit(1)


# Handle FPING
def check_alive_hosts():
    clear_screen()

    # List .txt files in the current directory
    txt_files = list_txt_files(os.getcwd())
    if txt_files:
        print(f"{BOLD_GREEN}ICMP Echo and Parser\n")
        print(f"{BOLD_CYAN}Available .txt Files In This Project's Folder\n")
        for idx, file in enumerate(txt_files, start=1):
            print(f"{BOLD_GREEN}{idx}. {BOLD_WHITE}{file}")

    # Prompt the user for an IP address or a file number
    selection = input(f"\n{BOLD_GREEN}Enter a number to select a file, or input a single IP address: {BOLD_WHITE}").strip()

    # If user enters a digit within the range of listed files, select the file
    if selection.isdigit() and 1 <= int(selection) <= len(txt_files):
        file_selected = txt_files[int(selection) - 1]
        hosts_input = os.path.join(os.getcwd(), file_selected)
    elif is_valid_ip(selection):
        hosts_input = selection
    else:
        print(f"{BOLD_RED}Invalid input. Please enter a valid IP address or selection number.")
        return

    # If it's a file, read IPs from it; if it's a single IP, create a list with it
    if os.path.isfile(hosts_input):
        hosts = read_file_lines(hosts_input)
    else:
        hosts = [hosts_input]

    # Run fping with the list of IPs
    clear_screen()
    print(f"\n{BOLD_CYAN}Running FPING\n")
    alive_hosts = run_fping(hosts)
    print(f"\n{BOLD_GREEN}Alive Hosts:")
    for host in alive_hosts:
        print(f"{BOLD_YELLOW}{host}")

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...")


# Function to run sslscan and parse results
def run_sslscanparse():
    clear_screen()
    sslscan_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'sslscanparse.py')

    # List the available .txt files
    txt_files = list_txt_files(os.getcwd())
    if txt_files:
        print(f"{BOLD_GREEN}SSLScanner and Parser\n")
        print(f"{BOLD_CYAN}Available .txt Files In This Project's Folder\n")
        for idx, file in enumerate(txt_files, start=1):
            print(f"{BOLD_GREEN}{idx}. {BOLD_WHITE}{file}")

    # Prompt for input: either a file number or a custom file path
    selection = input(f"{BOLD_GREEN}\nEnter a number to select a file, or input a custom file path: {BOLD_WHITE}").strip()

    # Check if the input is a digit and within the range of listed files
    if selection.isdigit() and 1 <= int(selection) <= len(txt_files):
        input_file = os.path.join(os.getcwd(), txt_files[int(selection) - 1])  # Use the selected file
    else:
        input_file = selection  # Assume the entered string is a custom file path

    # Validate that the file exists
    if not os.path.isfile(input_file):
        print(f"{BOLD_RED}File does not exist: {input_file}")
        return

    # Run the sslscanparse script
    clear_screen()
    print(f"\n{BOLD_GREEN}Running sslscanparse.py on {input_file}")
    with subprocess.Popen(['python3', sslscan_script_path, input_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            # Output each line as it's generated
            for line in process.stdout:
                print(line, end='')  # stdout is already newline-terminated
            process.wait()
            # After the process ends, check for any remaining stderr output
            stderr_output = process.stderr.read()
            if stderr_output:
                print(f"{BOLD_RED}Error:\n{stderr_output}")
        except Exception as e:
            print(f"{BOLD_RED}An error occurred: {e}")

    input(f"\n\n{BOLD_BLUE}Press Enter to return to the menu....")


# Function to run whois script
def run_whois():
    clear_screen()
    whois_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'whois_script.sh')

    txt_files = list_txt_files(os.getcwd())
    if txt_files:
        print(f"{BOLD_GREEN}WHOIS Scan and Parse\n")
        print(f"\n{BOLD_CYAN}Available .txt Files In This Project's Folder\n")
        for idx, file in enumerate(txt_files, start=1):
            print(f"{BOLD_GREEN}{idx}. {BOLD_WHITE}{file}")

    ip_input = input(f"\n{BOLD_GREEN}Enter a number to select a file, or input a single IP address: {BOLD_WHITE}").strip()

    if ip_input.isdigit() and 1 <= int(ip_input) <= len(txt_files):
        ip_input = txt_files[int(ip_input) - 1]  # If user selects a file, use its name as input
    elif not (is_valid_ip(ip_input) or ip_input.isdigit()):
        print(f"{BOLD_RED}Invalid input. Please enter a valid IP address or selection number.")
        return

    # Proceed with running the script using ip_input as either a filename or a single IP
    clear_screen()
    print(f"\n{BOLD_GREEN}Running WHOIS and Parsing results on {ip_input}\n")
    stdout = run_subprocess(['bash', whois_script_path, ip_input])
    print(stdout)
    input(f"{BOLD_GREEN}Press any key to return to the menu...")


def run_ngrep(scan_type):
    clear_screen()
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


# Function to run nmap scan
def run_nmap():
    clear_screen()

    # List the available .txt files
    txt_files = list_txt_files(os.getcwd())
    if txt_files:
        print(f"{BOLD_GREEN}NMAP Scanner\n")
        print(f"{BOLD_CYAN}Available .txt Files In This Project's Folder\n")
        for idx, file in enumerate(txt_files, start=1):
            print(f"{BOLD_GREEN}{idx}. {BOLD_WHITE}{file}")

    # Prompt for input: either a file number, a single IP, or 'x' to cancel
    selection = input(
        f"{BOLD_GREEN}\nEnter a number to select a file or input a single IP address: {BOLD_WHITE}").strip()

    # Check if the input is a digit and within the range of listed files
    if selection.isdigit() and 1 <= int(selection) <= len(txt_files):
        ip_input = txt_files[int(selection) - 1]  # Use the selected file
    elif is_valid_ip(selection) or is_valid_domain(selection):
        ip_input = selection  # Use the entered IP or domain
    else:
        print(f"{BOLD_RED}Invalid input. Please enter a valid IP address, domain, or selection number.")
        return

    # Ask for the type of scan
    clear_screen()
    print(f"{BOLD_GREEN}NMAP Scanner\n")
    print(f"{BOLD_MAG}NMAP Scans will launch in a separate terminal")
    print(f"{BOLD_CYAN}TCP: {BOLD_WHITE}nmap -sSV --top-ports 4000 -Pn ")
    print(f"{BOLD_CYAN}UDP: {BOLD_WHITE}nmap -sU --top-ports 400 -Pn ")
    scan_type = input(f"\n{BOLD_GREEN}Enter scan type (tcp/udp/both): ").lower()

    # Validate scan_type
    if scan_type not in ['tcp', 'udp', 'both']:
        print(f"{BOLD_RED}Invalid scan type: {scan_type}. Please enter 'tcp', 'udp', or 'both'.")
        return

    # Run the nmap scan using the selected file or entered IP/domain
    nmap_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'nmap_scan.py')
    if scan_type in ['tcp', 'both']:
        tcp_command_string = f"echo -ne \"\\033]0;NMAP TCP\\007\"; exec sudo python3 {nmap_script_path} {ip_input} tcp"
        tcp_command = ['gnome-terminal', '--', 'bash', '-c', tcp_command_string]
        subprocess.Popen(tcp_command)
    if scan_type in ['udp', 'both']:
        udp_command_string = f"echo -ne \"\\033]0;NMAP UDP\\007\"; exec sudo python3 {nmap_script_path} {ip_input} udp"
        udp_command = ['gnome-terminal', '--', 'bash', '-c', udp_command_string]
        subprocess.Popen(udp_command)

    print(f"\n{BOLD_GREEN}Nmap {scan_type} scans launched.")
    input(f"{BOLD_GREEN}Press Enter to return to the menu...")


def display_menu(version, project_path, ascii_art):
    clear_screen()
    update_available = check_and_update()
    print(ascii_art)
    print(f"{BOLD_CYAN}========================================================")
    update_msg = "\n                  Update Available!\n  Please exit and run pip install --upgrade infiltra\n" \
        if update_available else ""
    print(f"{BOLD_CYAN}                Current Version: v{version}")
    print(f"{BOLD_MAG}{update_msg}")
    print(f"{BOLD_YELLOW}            https://github.com/jivy26/infiltra")
    print(f"{BOLD_YELLOW}            Author: @jivy26")
    print(f"{BOLD_CYAN}========================================================\n")

    current_directory = project_path if project_path else os.getcwd()
    print(f"{BOLD_GREEN}Current Directory: {current_directory}\n")

    print(f"\n{BOLD_GREEN}Main Menu")
    print(f"{BOLD_GREEN}========================================================\n")
    menu_options = [
        ("1. Projects", f"{DEFAULT_COLOR}Create, Load, or Delete Projects"),
        ("2. Whois", f"{DEFAULT_COLOR}Perform WHOIS lookups and parse results."),
        ("3. ICMP Echo ", f"{DEFAULT_COLOR}Ping requests and parse live hosts."),
        ("4. OSINT and Black Box OSINT", f"{DEFAULT_COLOR}AORT, DNS Recon, BBOT, and EyeWitness available."),
        ("5. NMAP Scans", f"{DEFAULT_COLOR}Discover open ports and services on the network."),
        ("6. Parse NMAP Scans", f"{DEFAULT_COLOR}Parse NMAP TCP/UDP Scans."),
        ("7. SSLScan and Parse", f"{DEFAULT_COLOR}Run SSLScan for Single IP or Range and Parse Findings."),
        ("8. Website Enumeration", f"{DEFAULT_COLOR}Directory brute-forcing, technology identification, and more."),
        ("9. Vulnerability Scanner", f"{BOLD_YELLOW}(In-Progress)")
    ]

    for option, description in menu_options:
        print(f"{BOLD_GREEN}{option.ljust(30)}{description}")

    print(f"\n{BOLD_CYAN}Utilities:")
    print(f"{BOLD_RED}X. Exit".ljust(30) + f"{DEFAULT_COLOR} Exit the application.\n")

    choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()
    return choice


# Main function
def main():
    check_and_install_gnome_terminal()
    projects_base_path = os.path.expanduser('~/projects')  # Define the base projects directory path
    project_path = projects_base_path  # Initialize project_path
    version = get_version()

    # Inside your main function or wherever you need to print the ASCII art
    ascii_art = get_ascii_art('logo.png', columns=80)

    # Check for last used project
    clear_screen()
    if last_project_file_path.exists():
        with last_project_file_path.open() as file:
            last_project = file.read().strip()
        if last_project:
            print()
            use_last_project = input(
                f"\n\n\n{BOLD_GREEN}Do you want to load the last project used '{last_project}'? (Y/n): ").strip().lower()
            if use_last_project in ['', 'y']:
                project_path = os.path.join(projects_base_path, last_project)
                os.chdir(project_path)
                print(f"{BOLD_GREEN}Loaded the recent project: {last_project}")

    while True:
        try:
            choice = display_menu(version, project_path, ascii_art)
            if choice == '1':
                new_project_path = project_submenu()
                if new_project_path is not None:  # Check if a new project path was returned or if it's a deletion
                    project_path = new_project_path
                    os.chdir(project_path)  # Change the working directory
                    print(f"Changed directory to {project_path}")
                else:
                    # If None is returned, reset to the base projects directory (e.g. after deletion)
                    project_path = os.path.expanduser('~/projects')
                    os.chdir(project_path)
                    print(f"Changed directory to the base projects directory {project_path}")
            elif choice == '2':
                run_whois()
            elif choice == '3':
                check_alive_hosts()
            elif choice == '4':
                osint_submenu(project_path)
            elif choice == '5':
                run_nmap()
            elif choice == '6':
                clear_screen()
                print(f"{BOLD_CYAN}NMAP Results Parser\n")
                scan_type = input(f"{BOLD_GREEN}Enter the scan type that you want to parse (TCP/UDP): ").upper()
                run_ngrep(scan_type)
            elif choice == '7':
                run_sslscanparse()
            elif choice == '8':
                website_enumeration_submenu()
            elif choice == '9':
                nuclei_main()
            elif choice == 'u':
                print("Checking for updates...")
                updated = check_and_update()
            elif choice == 'x':
                break
            else:
                print(f"{BOLD_YELLOW}Invalid choice, please try again.")
        except EOFError:
            print(f"{BOLD_RED}EOFError encountered. Exiting...")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"{BOLD_RED}Operation cancelled by user. Exiting...")
            sys.exit(1)


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
