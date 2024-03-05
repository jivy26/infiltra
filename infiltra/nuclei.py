'''
Nuclei Functionality, currently limited
'''

import os
import subprocess
from colorama import init, Fore, Style
import pkg_resources


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


# This will give you the path to where the 'infiltra' package is installed
infiltra_path = pkg_resources.resource_filename('infiltra', '')

# Construct the path to the 'nuclei-templates' directory
nuclei_templates_path = os.path.join(infiltra_path, 'nuclei-templates')
ssl_templates_path = os.path.join(nuclei_templates_path, 'ssl')
fuzzing_templates_path = os.path.join(nuclei_templates_path, 'http/fuzzing/')

# Now you can use this path in your nuclei command
nuclei_command = f"nuclei -t {nuclei_templates_path}"

# Initialize Colorama with autoreset
init(autoreset=True)

# Define colors using Colorama, matching infiltra.py
DEFAULT_COLOR = Fore.WHITE
BOLD_BLUE = Fore.BLUE + Style.BRIGHT
BOLD_CYAN = Fore.CYAN + Style.BRIGHT
BOLD_GREEN = Fore.GREEN + Style.BRIGHT
BOLD_RED = Fore.RED + Style.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style.BRIGHT


def check_and_install_go():
    try:
        # Check if Go is installed
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{BOLD_GREEN}Go is installed.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Go is not installed; proceed with installation
        print(f"{BOLD_YELLOW}Go is not installed. Updating package list and installing Go... Please wait.")
        subprocess.run(["sudo", "apt", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "apt", "install", "-y", "golang-go"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{BOLD_GREEN}Go installed successfully.")

        print(f"{BOLD_CYAN}Setting up Go environment...")
        gopath = subprocess.check_output("go env GOPATH", shell=True).decode().strip()
        bashrc_update = f"\nexport GOPATH={gopath}\nexport PATH=$PATH:$GOPATH/bin\n"
        with open(os.path.expanduser("~/.bashrc"), "a") as bashrc:
            bashrc.write(bashrc_update)
        if os.path.exists(os.path.expanduser("~/.zshrc")):
            with open(os.path.expanduser("~/.zshrc"), "a") as zshrc:
                zshrc.write(bashrc_update)
        print(f"{BOLD_GREEN}Go environment setup complete.")

def check_and_install_nuclei():
    try:
        # Check if Nuclei is installed
        subprocess.run(["nuclei", "-version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{BOLD_GREEN}Nuclei is installed.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Nuclei is not installed; proceed with installation
        print(f"{BOLD_YELLOW}Nuclei is not installed. Installing now... Please wait.")
        subprocess.run(["sudo", "apt", "install", "-y", "nuclei"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{BOLD_GREEN}Nuclei installed successfully.")


def nuclei_submenu():
    while True:
        clear_screen()
        print(f"\n{BOLD_CYAN}Nuclei Scanner\n")
        print(f"{BOLD_GREEN}1. Basic Vulnerability Scan")
        print(f"{BOLD_GREEN}2. Moderate Scan")
        print(f"{BOLD_GREEN}3. Advanced Invasive Scan")
        print(f"{BOLD_GREEN}4. [Placeholder for future functionality]")
        print(f"{BOLD_GREEN}5. Check for Updates")
        print(f"{BOLD_RED}X. Exit Submenu")

        choice = input(f"\n{BOLD_YELLOW}Enter your choice: ").strip().lower()

        if choice == '1':
            domain = input(f"{BOLD_GREEN} Enter the domain: ").strip().lower()
            print(f"{BOLD_BLUE}Running Basic Vulnerability Scan...")
            command = f"nuclei -u https://{domain} -t {ssl_templates_path} -t {fuzzing_templates_path} -severity low,medium -o basic_scan_results.txt"
            os.system(f"qterminal -e bash -c '{command}; echo \"Press enter to close...\"; read'")
        elif choice == '2':
            domain = input(f"{BOLD_GREEN} Enter the domain: ").strip().lower()
            print(f"{BOLD_BLUE}Running Moderate Scan...")
            command = f"nuclei -u https://{domain} -t {nuclei_templates_path} -severity low,medium -o moderate_scan_results.txt"
            os.system(f"qterminal -e bash -c '{command}; echo \"Press enter to close...\"; read'")
        elif choice == '3':
            domain = input(f"{BOLD_GREEN} Enter the domain: ").strip().lower()
            print(f"{BOLD_BLUE}Running Advanced Invasive Scan...")
            command = f"nuclei -u https://{domain} -t {nuclei_templates_path} -severity high,critical -o advanced_scan_results.txt"
            os.system(f"qterminal -e bash -c '{command}; echo \"Press enter to close...\"; read'")
        elif choice == '5':
            subprocess.run(["sudo apt update && sudo apt upgrade -y"], check=True)
        elif choice == 'x':
            print(f"{BOLD_RED}Exiting Nuclei Submenu...")
            break
        else:
            print(f"{BOLD_RED}Invalid choice, please try again.")

def nuclei_main():
    clear_screen()
    check_and_install_go()
    print("\n")
    check_and_install_nuclei()
    nuclei_submenu()

if __name__ == "__main__":
    nuclei_main()
