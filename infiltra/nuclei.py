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
    try:
        subprocess.run(["go", "version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_go():
    print(f"{BOLD_YELLOW}Updating package list and installing Go...")
    os.system("sudo apt update && sudo apt install -y golang-go")


def setup_go_environment():
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
    print(f"{BOLD_GREEN}Installing Nuclei...")
    os.system("sudo apt install nuclei")

def update_nuclei():
    print(f"{BOLD_YELLOW}Checking for Nuclei updates...")
    try:
        subprocess.run(["nuclei", "-update"], check=True)
        print(f"{BOLD_GREEN}Nuclei has been updated to the latest version.")
    except subprocess.CalledProcessError as e:
        print(f"{BOLD_RED}An error occurred during Nuclei update: {e}")
    except FileNotFoundError:
        print(f"{BOLD_RED}Nuclei is not installed.")


def nuclei_submenu():
    os.system('clear')
    while True:
        print(f"\n{BOLD_CYAN}Nuclei Scanner\n")
        print(f"{BOLD_GREEN}1. Basic Vulnerability Scan")
        print(f"{BOLD_GREEN}2. [Placeholder for future functionality]")
        print(f"{BOLD_GREEN}3. [Placeholder for future functionality]")
        print(f"{BOLD_GREEN}4. [Placeholder for future functionality]")
        print(f"{BOLD_GREEN}5. Check for Updates")
        print(f"{BOLD_RED}X. Exit Submenu")

        choice = input(f"\n{BOLD_YELLOW}Enter your choice: ").strip().lower()

        if choice == '1':
            domain = input(f"{BOLD_GREEN} Enter the domain: ").strip().lower()
            print(f"{BOLD_BLUE}Running Basic Vulnerability Scan...")
            #os.system(f"nuclei -u https://{domain}")
            command = f"""qterminal -e bash -c 'nuclei -u https://{domain} -o nuclei.txt; echo "Press enter to close..."; read'"""
            subprocess.Popen(command, shell=True)
        elif choice in ['2', '3', '4']:
            print(f"{BOLD_RED}This feature is not yet implemented.")
        elif choice == '5':
            update_nuclei()
        elif choice == 'x':
            print(f"{BOLD_RED}Exiting Nuclei Submenu...")
            break
        else:
            print(f"{BOLD_RED}Invalid choice, please try again.")

def nuclei_main():
    os.system('clear')
    if not is_go_installed():
        print(f"{BOLD_RED}Go is not installed. Installing Go...")
        install_go()
    else:
        print(f"{BOLD_GREEN}Go is already installed.")

    setup_go_environment()

    os.system('clear')
    install_nuclei()
    os.system('clear')
    nuclei_submenu()

if __name__ == "__main__":
    nuclei_main()
