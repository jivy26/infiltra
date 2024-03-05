import subprocess
import os
from infiltra.utils import BOLD_GREEN, BOLD_YELLOW, BOLD_RED

# Define the command to check if feroxbuster is installed
check_command = "feroxbuster --version"

# Define the command to install feroxbuster
install_command = "sudo apt install feroxbuster -y"

# Define the path to the osint_domain.txt and website_enum_domain.txt
osint_domain_file = 'osint_domain.txt'
website_enum_domain_file = 'website_enum_domain.txt'


# Function to check if feroxbuster is installed
def check_and_install_feroxbuster():
    try:
        # Check if feroxbuster is installed
        subprocess.run(["feroxbuster", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{BOLD_GREEN}Feroxbuster is installed.")
    except subprocess.CalledProcessError:
        # Feroxbuster is installed but returned a non-zero exit status
        print("Feroxbuster is installed but returned a non-zero exit status when checking version.")
    except FileNotFoundError:
        # Feroxbuster is not installed; proceed with installation
        print(f"{BOLD_YELLOW}Feroxbuster is not installed. Installing now...")
        install_command = "sudo apt install feroxbuster -y"
        try:
            subprocess.run(install_command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print(f"{BOLD_GREEN}Feroxbuster installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"{BOLD_RED}Failed to install Feroxbuster: {e}")
            sys.exit(1)


def get_domain_to_use():
    domain_to_use = ''
    if os.path.exists(website_enum_domain_file):
        with open(website_enum_domain_file, 'r') as file:
            domain_to_use = file.read().strip()
    elif os.path.exists(osint_domain_file):
        with open(osint_domain_file, 'r') as file:
            domain_to_use = file.read().strip()
    return domain_to_use


# Function to run feroxbuster with a given domain
def run_feroxbuster(domain):
    output_dir = 'website_enum'
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'ferox.txt')

    # Construct the command to run feroxbuster within gnome-terminal
    feroxbuster_command = f"echo -ne \"\\033]0;Feroxbuster\\007\"; exec feroxbuster -u {domain} -s 200,301,302 -k -o {output_file}"
    full_command = ['gnome-terminal', '--', 'bash', '-c', feroxbuster_command]

    # Execute the command
    try:
        subprocess.Popen(full_command)
        print(f"Executing Feroxbuster in a new GNOME Terminal window with title 'Feroxbuster'")
    except Exception as e:
        print(f"An error occurred while attempting to run Feroxbuster: {e}")


# Main function
def main(domain=None):
    check_and_install_feroxbuster()


if __name__ == "__main__":
    import sys
    # Pass the domain from the command line argument if provided, else None
    domain_arg = sys.argv[1] if len(sys.argv) > 1 else None
    main(domain_arg)