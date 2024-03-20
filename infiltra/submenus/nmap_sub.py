import os
import subprocess
import sys
import pkg_resources

from infiltra.utils import (
    is_valid_ip, list_txt_files, is_valid_domain, clear_screen,
    console,
    BOLD_RED, BOLD_GREEN, BOLD_YELLOW, BOLD_WHITE, BOLD_CYAN, DEFAULT_COLOR,
    RICH_RED, RICH_YELLOW, RICH_CYAN, RICH_GREEN, RICH_COLOR
)

def check_and_install_at():
    try:
        subprocess.run(["which", "at"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        console.print("at is installed.",  style=RICH_GREEN)
    except subprocess.CalledProcessError:
        console.print("at is not installed. Installing now...",  style=RICH_YELLOW)
        install_command = "sudo apt install at -y"
        try:
            subprocess.run(install_command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            console.print("at installed successfully.",  style=RICH_GREEN)
        except subprocess.CalledProcessError as e:
            console.print(f"Failed to install at: {e}",  style=RICH_RED)
            sys.exit(1)


def run_ngrep(scan_type):
    clear_screen()
    # Define the path to the nmap-grep.sh script
    ngrep_script_path = pkg_resources.resource_filename('infiltra', 'nmap-grep.sh')
    # Define the output directory based on the scan type
    output_path = f"{scan_type.lower()}_parsed/"

    # Check if the output directory exists and handle accordingly
    if os.path.isdir(output_path):
        overwrite = console.input(
            f"The directory [bold cyan]{output_path}[/bold cyan] already exists. Overwrite it? (y/n): ").strip().lower()
        if overwrite != 'y':
            console.print(f"Not overwriting the existing directory {output_path}.", style=RICH_COLOR)
            return

    # List available .txt files in the project directory, excluding specific files
    excluded_files = [
        'whois_',
        'icmpecho_',
        'sslscan.txt',
        'aort_dns.txt',
        'osint_domain.txt'
    ]
    txt_files = list_txt_files(os.getcwd(), exclude_prefixes=excluded_files)

    if txt_files:
        console.print(f"Available .txt Files for {scan_type.upper()} Parsing\n", style=RICH_CYAN)
        for idx, file in enumerate(txt_files, start=1):
            console.print(f"{idx}. {file}", style=RICH_GREEN)

        # Prompt the user to select a file
        selection = console.input(
            f"\n{BOLD_GREEN}Enter the number of the file you wish to parse or 'x' to cancel: {BOLD_WHITE}").strip()
        if selection.lower() == 'x':
            return
        elif selection.isdigit() and 1 <= int(selection) <= len(txt_files):
            file_selected = txt_files[int(selection) - 1]
        else:
            console.print("Invalid selection. Please enter a valid number from the list.", style=RICH_RED)
            return

        # Continue with ngrep script execution for the selected file
        console.print(f"Running nmap-grep.sh on {file_selected} for {scan_type.upper()} parsing", style=RICH_GREEN)
        subprocess.run(
            ['bash', ngrep_script_path, os.path.join(os.getcwd(), file_selected), scan_type.upper(), output_path])

        console.input(f"{BOLD_GREEN}Press Enter to return to the menu...")
    else:
        console.print("No suitable .txt files found for parsing.", style=RICH_RED)


def get_scheduled_scans_status(project_path):
    # Ensure there is a 'tmp' directory in the project path
    tmp_dir = os.path.join(project_path, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)

    # Check for ongoing scans by looking for marker files
    marker_file = os.path.join(tmp_dir, "nmap_scan_ongoing.marker")
    ongoing_scans = "Ongoing Scans: "
    if os.path.exists(marker_file):
        with open(marker_file, "r") as f:
            ongoing_scans += f.read()
    else:
        ongoing_scans += "None"

    # Use 'atq' to list the queued jobs and 'at -c' to inspect a specific job.
    scheduled_scans = subprocess.run(['atq'], capture_output=True, text=True)
    scheduled_scans_output = scheduled_scans.stdout if scheduled_scans.stdout else "No upcoming scans are scheduled."

    return f"{BOLD_GREEN}{ongoing_scans}\n\n{BOLD_YELLOW}Upcoming Scans:\n{scheduled_scans_output}"


def cancel_scheduled_scan():
    clear_screen()
    print(f"{BOLD_CYAN}Cancel a Scheduled Nmap Scan\n")
    # First, show all scheduled scans
    scheduled_scans = subprocess.run(['atq'], capture_output=True, text=True)
    print(scheduled_scans.stdout)

    if scheduled_scans.stdout.strip() == "":
        print(f"{BOLD_YELLOW}No scheduled scans to cancel.")
        input(f"{BOLD_GREEN}Press Enter to return to the menu...")
        return

    # Ask the user to input the job number to cancel
    job_number = input(f"{BOLD_GREEN}Enter the job number to cancel or 'x' to cancel:")
    if job_number.lower() == 'x':
        return

    # Attempt to cancel the job
    try:
        subprocess.run(['atrm', job_number], check=True)
        console.print("Scheduled scan {job_number} cancelled.",  style=RICH_YELLOW)
    except subprocess.CalledProcessError:
        console.print("Failed to cancel scheduled scan {job_number}.",  style=RICH_RED)
    input(f"{BOLD_GREEN}Press Enter to return to the menu...")


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
        f"{BOLD_GREEN}\nEnter a number to select a file, input a single IP address: {BOLD_WHITE}").strip()

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
    print(f"{BOLD_GREEN}NMAP Scans will launch in a separate terminal")
    print(f"{BOLD_CYAN}TCP: {BOLD_WHITE}nmap -sSV --top-ports 4000 -Pn ")
    print(f"{BOLD_CYAN}UDP: {BOLD_WHITE}nmap -sU --top-ports 400 -Pn ")
    scan_type = input(f"\n{BOLD_GREEN}Enter scan type (tcp/udp/both): ").lower()

    # Validate scan_type
    if scan_type not in ['tcp', 'udp', 'both']:
        print(f"{BOLD_RED}Invalid scan type: {scan_type}. Please enter 'tcp', 'udp', or 'both'.")
        return

    # Construct the path to the nmap_script
    nmap_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'nmap_scan.py')

    # Commands to run the nmap scan using qterminal
    if scan_type in ['tcp', 'both']:
        tcp_command = ['qterminal', '-e', f"bash -c 'sudo python3 {nmap_script_path} {ip_input} tcp; bash'"]
        subprocess.Popen(tcp_command)
    if scan_type in ['udp', 'both']:
        udp_command = ['qterminal', '-e', f"bash -c 'sudo python3 {nmap_script_path} {ip_input} udp; bash'"]
        subprocess.Popen(udp_command)

    print(f"\n{BOLD_GREEN}Nmap {scan_type} scans launched.")
    input(f"{BOLD_GREEN}Press Enter to return to the menu...")



def nmap_submenu(project_path):
    clear_screen()
    check_and_install_at()

    while True:
        clear_screen()
        console.print("NMAP Menu:\n", style=RICH_CYAN)
        print("========================================================")
        # Get the status of scheduled scans
        scheduled_scans_status = get_scheduled_scans_status(project_path)
        print(scheduled_scans_status)
        print(f"{BOLD_CYAN}========================================================\n")
        menu_options = [
            ("1. Run Scans", f"{DEFAULT_COLOR}Run or Schedule TCP and/or UDP Scans."),
            ("2. Cancel Scans", f"{DEFAULT_COLOR}Cancel scheduled scans."),
            ("3. Parse Results", f"{DEFAULT_COLOR}Parse NMAP Results.")
        ]

        for option, description in menu_options:
            print(f"{BOLD_GREEN}{option.ljust(50)}{description}")

        print(f"\n{BOLD_CYAN}Utilities:")
        print(f"{BOLD_RED}X. Return to Main Menu".ljust(50) + f"\n")

        choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()

        if choice == '1':
            run_nmap()
        elif choice == '2':
            cancel_scheduled_scan()
        elif choice == '3':
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
    nmap_submenu(os.getcwd())
