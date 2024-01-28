#!/usr/bin/env python3
import os
import subprocess
from colorama import init, Fore, Style

# Initialize Colorama with autoreset
init(autoreset=True)

# Define colors using Colorama, matching ept.py
DEFAULT_COLOR = Fore.WHITE
BOLD_BLUE = Fore.BLUE + Style.BRIGHT
BOLD_CYAN = Fore.CYAN + Style.BRIGHT
BOLD_GREEN = Fore.GREEN + Style.BRIGHT
BOLD_RED = Fore.RED + Style.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style.BRIGHT

def is_go_installed():
    """ Check if Go is installed """
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def install_go():
    """ Install Go language """
    print(f"{BOLD_YELLOW}Updating package list and installing Go...")
    os.system("sudo apt update && sudo apt install -y golang")

def setup_go_environment():
    """ Set up Go environment variables """
    print(f"{BOLD_CYAN}Setting up Go environment...")
    gopath = subprocess.check_output("go env GOPATH", shell=True).decode().strip()
    bashrc_update = f"\nexport GOPATH={gopath}\nexport PATH=$PATH:$GOPATH/bin\n"
    with open(os.path.expanduser("~/.bashrc"), "a") as bashrc:
        bashrc.write(bashrc_update)
    if os.path.exists(os.path.expanduser("~/.zshrc")):
        with open(os.path.expanduser("~/.zshrc"), "a") as zshrc:
            zshrc.write(bashrc_update)
    os.system("source ~/.bashrc")

def install_nuclei():
    """ Install Nuclei """
    print(f"{BOLD_GREEN}Installing Nuclei...")
    os.system("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

def nuclei_submenu():
    """ Nuclei submenu """
    while True:
        print(f"\n{BOLD_CYAN}Nuclei Submenu:")
        print(f"{BOLD_GREEN}1. Basic Vulnerability Scan")
        print(f"{BOLD_GREEN}2. [Placeholder for future functionality]")
        print(f"{BOLD_GREEN}3. [Placeholder for future functionality]")
        print(f"{BOLD_GREEN}4. [Placeholder for future functionality]")
        print(f"{BOLD_RED}X. Exit Submenu")

        choice = input(f"\n{BOLD_YELLOW}Enter your choice: ").strip().lower()

        if choice == '1':
            print(f"{BOLD_BLUE}Running Basic Vulnerability Scan...")
            # Add your logic for Basic Vulnerability Scan here
        elif choice in ['2', '3', '4']:
            print(f"{BOLD_RED}This feature is not yet implemented.")
        elif choice == 'x':
            print(f"{BOLD_RED}Exiting Nuclei Submenu...")
            break
        else:
            print(f"{BOLD_RED}Invalid choice, please try again.")

def main():
    if not is_go_installed():
        print(f"{BOLD_RED}Go is not installed. Installing Go...")
        install_go()
        setup_go_environment()
    else:
        print(f"{BOLD_GREEN}Go is already installed.")

    install_nuclei()
    nuclei_submenu()

if __name__ == "__main__":
    main()
