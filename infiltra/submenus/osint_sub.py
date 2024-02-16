import os
import subprocess

from colorama import init, Fore, Style
from infiltra.utils import read_file_lines, is_valid_domain, clear_screen, write_to_file
from infiltra.bbot.bbot_parse import bbot_main
from infiltra.bbot.check_bbot import is_bbot_installed, install_bbot

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


# Function to run EyeWitness
def run_eyewitness(domain):
    clear_screen()
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


# AORT Integration
def run_aort(domain):
    clear_screen()

    print(f"{BOLD_CYAN}Running AORT for domain: {BOLD_GREEN}{domain}\n")

    script_directory = os.path.dirname(os.path.realpath(__file__))
    aort_directory = os.path.join(script_directory, '..', 'aort')
    aort_script_path = os.path.join(aort_directory, 'AORT.py')
    aort_command = f"python3 {aort_script_path} -d {domain} -a -w -n --output aort_dns.txt"

    print(f"{BOLD_BLUE}AORT is starting, subdomains will be saved to aort_dns.txt.\n")

    try:
        # Call AORT and let it handle the output directly
        os.system(aort_command)
    except Exception as e:
        print(f"{BOLD_RED}An error occurred while running AORT: {e}")

    input(f"\n{BOLD_GREEN}Press Enter to return to proceed with DNSRecon...")


# Function to check if dnsrecon is installed
def is_dnsrecon_installed():
    try:
        subprocess.run(["dnsrecon", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# DNSRecon Integration
def run_dnsrecon(domain):
    clear_screen()
    print(f"{BOLD_CYAN}Running DNSRecon for domain: {BOLD_GREEN}{domain}\n")

    dnsrecon_command = ["dnsrecon", "-d", domain, "-t", "std"]

    misconfiguration_found = False

    while not misconfiguration_found:
        print(f"{BOLD_GREEN}DNSRecon is starting, only findings will be displayed. If no findings are found recon will "
              f"rerun for screenshotting.\n")

        try:
            process = subprocess.Popen(dnsrecon_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if "[-]" in output.strip():
                    print(output.strip())
                    misconfiguration_found = True

            process.wait()  # Wait for DNSRecon to finish if still running

            if not misconfiguration_found:
                print(f"{BOLD_RED}No misconfigurations found, rerunning DNSRecon for domain: {BOLD_GREEN}{domain}\n")
                # You can add a delay here if you want to wait before rerunning
                # time.sleep(2)

        except Exception as e:
            print(f"{BOLD_RED}An error occurred while running DNSRecon: {e}")
            break  # Exit the loop if there's an error

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...")


def run_bbot(domain, project_path):
    # Make sure the domain is valid before proceeding
    if not is_valid_domain(domain):
        print(f"{BOLD_RED}Invalid domain provided: {domain}")
        return

    # Check if bbot is installed
    if not is_bbot_installed():
        print(f"{BOLD_YELLOW}bbot is not installed, installing now...")
        install_bbot()

    # Clear the screen and display sample commands
    clear_screen()
    print(f"{BOLD_CYAN}Select the bbot command to run:")
    print(f"{BOLD_YELLOW}All output is saved to the bbot/ folder\n")
    print(f"1. Enumerate Subdomains")
    print(f"2. Subdomains, Port Scans, and Web Screenshots")
    print(f"3. Subdomains and Basic Web Scan")
    print(f"4. Full Enumeration {BOLD_YELLOW}--- Enumerates subdomains, emails, cloud buckets, port scan with nmap, "
          f"basic web scan, nuclei scan, and web screenshots")

    # Define bbot commands
    commands = {
        '1': "-f subdomain-enum",
        '2': "-f subdomain-enum -m nmap gowitness",
        '3': "-f subdomain-enum web-basic",
        '4': "-f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly",
    }

    choice = input(f"{BOLD_GREEN}Enter your choice (1-4): ").strip()

    # Notification message setup
    notification_title = "BBOT scan completed."
    notification_body = "BBOT scan completed."

    if choice in commands:
        command = commands[choice]
        bbot_command = (f"echo -ne \"\\033]0;BBOT\\007\"; exec bbot -t {domain} {command} -o . --name bbot; "
                        f"notify-send \"{notification_title}\" \"{notification_body}\"")
        full_command = ['gnome-terminal', '--', 'bash', '-c', bbot_command]

        # Change directory to the project path
        os.chdir(project_path)

        # Print the command being executed for the user's reference
        print(f"{BOLD_YELLOW}Executing: {full_command}")

        # Run the bbot command
        subprocess.Popen(full_command)
        # exit_status = os.system(full_command)
        #
        # # Check exit status
        # if exit_status != 0:
        #     print(f"{BOLD_RED}bbot command failed with exit status {exit_status}")
    else:
        print(f"{BOLD_RED}Invalid choice, please enter a number from 1 to 4.")

    # Wait for the user to acknowledge before returning to the menu
    input(f"{BOLD_GREEN}Press Enter to return to the menu...")


def osint_submenu(project_path):
    clear_screen()
    domain = ''
    osint_domain_file = 'osint_domain.txt'  # File to store the domain

    # Check if osint_domain.txt exists and read the domain from it
    domain_lines = read_file_lines(osint_domain_file)
    if domain_lines:
        domain = domain_lines[0].strip()

    while True:
        clear_screen()
        print(f"{BOLD_CYAN}OSINT Menu:")
        print(f"{BOLD_CYAN}Domain: {BOLD_GREEN}{domain}\n")
        menu_options = [
            ("1. Set Domain", f"{DEFAULT_COLOR}Define the domain to be used for OSINT."),
            ("2. Run AORT and DNSRecon", f"{DEFAULT_COLOR}Enumerate DNS information."),
            ("3. Run BBOT", f"{DEFAULT_COLOR}Black-box testing for domain and network analysis."),
            ("4. Parse BBOT Results", f"{DEFAULT_COLOR}Interpret the output from BBOT."),
            ("5. Run EyeWitness", f"{DEFAULT_COLOR}Visual inspection tool for web domains.")
        ]

        for option, description in menu_options:
            print(f"{BOLD_GREEN}{option.ljust(50)}{description}")

        print(f"\n{BOLD_CYAN}Utilities:")
        print(f"{BOLD_RED}X. Return to Main Menu".ljust(50) + f"\n")

        choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()

        if choice == '1':
            domain_input = input(f"{BOLD_CYAN}Please Input the Domain (i.e. google.com): ").strip()
            if is_valid_domain(domain_input):
                domain = domain_input
                print(f"{BOLD_GREEN}Domain set to: {domain}")
                write_to_file(osint_domain_file, domain)
            else:
                print(f"{BOLD_RED}Invalid domain name. Please enter a valid domain.")
            input(f"{BOLD_CYAN}Press Enter to continue...")
        elif choice == '2':
            if domain:
                run_aort(domain)
                if is_dnsrecon_installed():
                    run_dnsrecon(domain)
                else:
                    print(f"{BOLD_RED}DNSRecon is not installed. Please install it to use this feature.")
            else:
                print(f"{BOLD_RED}Please set a domain first using option 1.")
            input(f"{BOLD_GREEN}Press Enter to return to the submenu...")
        elif choice == '3':
            if domain:
                run_bbot(domain, project_path)
            else:
                print(f"{BOLD_RED}Please set a domain first using option 1.")
        elif choice == '4':
            bbot_main()
        elif choice == '5':
            if domain:
                run_eyewitness(domain)
            else:
                print(f"{BOLD_RED}Please set a domain first using option 1.")
        elif choice == 'x':
            return
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.")
            input(f"{BOLD_GREEN}Press Enter to continue...")


if __name__ == '__main__':
    osint_submenu()
