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


# Function to run feroxbuster with a given domain
def run_feroxbuster(domain):
    output_dir = 'website_enum'
    os.makedirs(output_dir, exist_ok=True)  # Create the directory if it doesn't exist
    output_file = os.path.join(output_dir, 'ferox.txt')

    # Construct the feroxbuster command
    feroxbuster_command = f"feroxbuster -u {domain} -s 200,301,302 -k -o {output_file}"

    # Open a new terminal window to run Feroxbuster, naming the window if possible
    try:
        subprocess.run(f"gnome-terminal --title=Feroxbuster -e '{feroxbuster_command}'", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running feroxbuster: {e}")


# Main function
def main(domain=None):
    # Check if feroxbuster is installed
    if not is_feroxbuster_installed():
        print("Feroxbuster is not installed. Installing now...")
        install_feroxbuster()

    # Use the domain argument if it was passed, otherwise determine the domain to use
    domain_to_use = domain
    if not domain_to_use:
        if os.path.exists(website_enum_domain_file):
            with open(website_enum_domain_file, 'r') as file:
                domain_to_use = file.read().strip()
        elif os.path.exists(osint_domain_file):
            with open(osint_domain_file, 'r') as file:
                domain_to_use = file.read().strip()

    if domain_to_use:
        run_feroxbuster(domain_to_use)
    else:
        print("No domain is set for enumeration. Please set a domain first.")


if __name__ == "__main__":
    main()
