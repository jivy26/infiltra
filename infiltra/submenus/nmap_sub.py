import os
import subprocess

import pkg_resources

from infiltra.utils import (is_valid_ip, list_txt_files, read_file_lines, is_valid_domain, clear_screen, write_to_file,
                            BOLD_RED, BOLD_GREEN, BOLD_YELLOW, BOLD_WHITE, BOLD_CYAN, BOLD_MAG, DEFAULT_COLOR)


def run_ngrep(scan_type):
    clear_screen()
    script_directory = pkg_resources.resource_filename('infiltra', 'nmap-grep.sh')
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


def nmap_submenu(project_path):
    clear_screen()

    while True:
        clear_screen()
        print(f"{BOLD_CYAN}NMAP Menu:")

        menu_options = [
            ("1. Run Scans", f"{DEFAULT_COLOR}Run TCP and/or UDP Scans."),
            ("2. Parse Results", f"{DEFAULT_COLOR}Parse NMAP Results.")
        ]

        for option, description in menu_options:
            print(f"{BOLD_GREEN}{option.ljust(50)}{description}")

        print(f"\n{BOLD_CYAN}Utilities:")
        print(f"{BOLD_RED}X. Return to Main Menu".ljust(50) + f"\n")

        choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()

        if choice == '1':
            run_nmap()
        elif choice == '2':
            clear_screen()
            print(f"{BOLD_CYAN}NMAP Results Parser\n")
            scan_type = input(f"{BOLD_GREEN}Enter the scan type that you want to parse (TCP/UDP): ").upper()
            run_ngrep(scan_type)
        elif choice == 'x':
            return
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.")
            input(f"{BOLD_GREEN}Press Enter to continue...")


if __name__ == '__main__':
    nmap_submenu()
