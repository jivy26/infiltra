import subprocess
import os

# Define the command to check if feroxbuster is installed
check_command = "feroxbuster --version"

# Define the command to install feroxbuster
install_command = "sudo apt install feroxbuster -y"

# Define the path to the osint_domain.txt and website_enum_domain.txt
osint_domain_file = 'osint_domain.txt'
website_enum_domain_file = 'website_enum_domain.txt'


# Function to check if feroxbuster is installed
def is_feroxbuster_installed():
    check_command = "feroxbuster --version"
    try:
        subprocess.run(check_command.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("Feroxbuster is installed but returned a non-zero exit status when checking version.")
        return False
    except FileNotFoundError:
        print("Feroxbuster is not installed or not found in the PATH.")
        return False


# Function to install feroxbuster
def install_feroxbuster():
    try:
        subprocess.run(install_command.split(), check=True)
        print("Feroxbuster installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing feroxbuster: {e}")


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
    feroxbuster_installed = is_feroxbuster_installed()
    if not feroxbuster_installed:
        print("Feroxbuster is not installed. Installing now...")
        install_feroxbuster()
        feroxbuster_installed = is_feroxbuster_installed()  # Check again after attempting to install

    if feroxbuster_installed:
        if not domain:
            domain = get_domain_to_use()

        if domain:
            run_feroxbuster(domain)
        else:
            print("No domain is set for enumeration. Please set a domain first.")
    else:
        print("Failed to install Feroxbuster. Please install it manually.")


if __name__ == "__main__":
    import sys
    # Pass the domain from the command line argument if provided, else None
    domain_arg = sys.argv[1] if len(sys.argv) > 1 else None
    main(domain_arg)