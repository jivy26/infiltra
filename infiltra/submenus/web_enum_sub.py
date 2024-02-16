import os
import subprocess

from colorama import init, Fore, Style
from infiltra.utils import read_file_lines, is_valid_domain, clear_screen, is_valid_ip, is_valid_hostname
from infiltra.website_enum.feroxbuster import main as run_feroxbuster
from infiltra.website_enum.wpscan import main as run_wpscan

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


def get_domains_string(file_path):
    domains = read_file_lines(file_path)
    if domains:
        # Join the list of domains into a string, separated by comma and space
        return ', '.join(domains)
    else:
        return None


def create_domains_file():
    website_enum_domain_file = 'website_enum_domain.txt'
    print(f"{BOLD_GREEN}Please enter the domains (one per line). Press CTRL+D when done:")
    try:
        with open(website_enum_domain_file, 'w') as file:
            while True:
                try:
                    domain = input()
                    if not is_valid_domain(domain):
                        print(f"{BOLD_RED}Invalid domain format. Please try again.")
                    else:
                        file.write(domain + '\n')
                except EOFError:  # This is triggered by pressing CTRL+D or CTRL+Z
                    break
        print(f"{BOLD_GREEN}Domains have been saved to {website_enum_domain_file}")
    except Exception as e:
        print(f"{BOLD_RED}An error occurred while saving domains: {e}")


def run_nikto(targets):
    clear_screen()
    nikto_dir = 'website_enum'
    os.makedirs(nikto_dir, exist_ok=True)  # Create the nikto directory if it doesn't exist
    hosts = targets
    # Check if the input is a file or a single host
    if os.path.isfile(targets):
        hosts = read_file_lines(targets)
    elif is_valid_ip(targets) or is_valid_hostname(targets):
        hosts = [targets]  # If it's a single host, put it in a list
    else:
        print(f"{BOLD_RED}Invalid target: {targets} is not a valid IP, hostname, or file.")
        return

    for host in hosts:
        title_command = f"echo -ne \"\\033]0;Nikto Scan for {host}\\007\"; "
        output_filename = f"nikto_{host.replace(':', '_').replace('/', '_')}.txt"  # Replace special characters
        output_path = os.path.join(nikto_dir, output_filename)

        print(f"{BOLD_CYAN}Running Nikto for {host} in a new window.")
        nikto_command = f"nikto -h {host} -C all -Tuning 13 -o {output_path} -Format txt"

        # Open a new terminal window to run Nikto
        terminal_command = ['gnome-terminal', '--', 'bash', '-c', title_command + f'sudo {nikto_command}']
        subprocess.Popen(terminal_command)

    print(f"{BOLD_GREEN}Nikto scans launched in separate windows.")
    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...")


def website_enumeration_submenu():
    clear_screen()
    website_enum_domain_file = 'website_enum_domain.txt'
    domain_string = get_domains_string(website_enum_domain_file)
    domain_files = {
        'osint_domain.txt': None,
        'website_enum_domain.txt': None,
    }
    choices = []

    # Check for existing domain files and list them
    for idx, (filename, _) in enumerate(domain_files.items(), start=1):
        if os.path.exists(filename):
            with open(filename, 'r') as file:
                domain = file.read().strip()
            print(f"{idx}. Use domain from {filename}: {domain}")
            choices.append((str(idx), filename))
            domain_files[filename] = domain

    # Determine the new choice index based on existing files
    new_choice_index = str(len(choices) + 1)
    print(f"{new_choice_index}. Enter a new domain for website enumeration")
    choices.append((new_choice_index, "new_domain"))

    choice = input("\nEnter your choice: ").strip()

    # Validate choice
    if choice not in [idx for idx, _ in choices]:
        print(f"{BOLD_RED}Invalid choice, please try again.")
        return

    # Use domain from selected file
    domain = ""
    if choice in [idx for idx, _ in choices if idx != new_choice_index]:
        domain = domain_files[choices[int(choice) - 1][1]]

    # Enter a new domain
    elif choice == new_choice_index:
        create_domains_file()

    while True:
        clear_screen()
        domain_set_status = f"{BOLD_GREEN}Domain is set for: {domain_string}" if domain_string else f"{BOLD_YELLOW}Domain is not set."
        domain_status_menu = f"{BOLD_CYAN}1. Change Domain" if domain_string else f"{BOLD_RED}1. Set Domain"
        print(f"{BOLD_CYAN}Website Enumeration Menu: {domain_set_status}\n")
        menu_options = [
            (f"{domain_status_menu}",
             f"         {DEFAULT_COLOR}Checks if domain is set or not. Yellow means a domain needs to be set."),
            (
            "2. Run Feroxbuster for Directory Brute Forcing", f"{DEFAULT_COLOR}Discover hidden directories and files."),
            ("3. Identify Technologies with Wappalyzer",
             f"{BOLD_YELLOW}Not working {DEFAULT_COLOR}Uncover technologies used on websites."),
            ("4. Perform OWASP ZAP Scan",
             f"{BOLD_YELLOW}Not working {DEFAULT_COLOR}Find vulnerabilities in web applications."),
            ("5. Run WPScan for WordPress Sites", f"{BOLD_YELLOW}Not working {DEFAULT_COLOR}Check for vulnerabilities "
                                                  f"in WordPress sites."),
            ("6. Nikto Web Scans", f"{DEFAULT_COLOR}Scan web servers to identify potential security issues.")
        ]

        for option, description in menu_options:
            print(f"{BOLD_GREEN}{option.ljust(50)}{description}")

        print(f"\n{BOLD_CYAN}Utilities:")
        print(f"{BOLD_RED}X. Return to Main Menu".ljust(30) + f"\n")

        choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()

        if choice == '1':
            domain_input = input(f"{BOLD_CYAN}Please input the domain for website enumeration: ").strip()
            if is_valid_domain(domain_input):
                domain = domain_input
                with open(website_enum_domain_file, 'w') as file:
                    file.write(domain)
                print(f"{BOLD_GREEN}Domain set to: {domain}")
            else:
                print(f"{BOLD_RED}Invalid domain name. Please enter a valid domain.")
            input(f"{BOLD_CYAN}Press Enter to continue...")
        elif choice == '2':
            run_feroxbuster(domain)
        elif choice == '3':
            # Placeholder for Wappalyzer integration
            print(f"{BOLD_YELLOW}Wappalyzer integration is in progress...")
            # run_wappalyzer()
        elif choice == '4':
            # Placeholder for OWASP ZAP integration
            print(f"{BOLD_YELLOW}OWASP ZAP integration is in progress...")
            # run_owasp_zap()
        elif choice == '5':
            run_wpscan(domain)
        elif choice == '6':
            print(f"{BOLD_CYAN}Nikto Scanner")
            clear_screen()
            target_input = input(
                f"{BOLD_GREEN}Enter a single IP/domain or path to a file with IPs/domains: ")
            run_nikto(target_input)
        elif choice == 'x':
            # Return to the main menu
            return
        else:
            print(f"{BOLD_RED}Invalid choice, please try again.")
            input(f"{BOLD_GREEN}Press Enter to continue...")
            website_enumeration_submenu()


if __name__ == "__main__":
    website_enumeration_submenu()
