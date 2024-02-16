import pathlib
import subprocess
import os
import getpass
import json
from infiltra.utils import is_valid_domain

# Define the base directory for storing application data
app_data_directory = pathlib.Path.home().joinpath('.config', 'infiltra')

# Ensure the directory exists
app_data_directory.mkdir(parents=True, exist_ok=True)

# Define the path for WPScan API Storage
api_key_file = app_data_directory.joinpath('wpscan_api_key.json')

# Define the command to check if WPScan is installed
check_command = "wpscan --version"

# Define the command to install WPScan
install_command = "sudo apt install wpscan -y"

# Define the path to the osint_domain.txt and website_enum_domain.txt
osint_domain_file = 'osint_domain.txt'
website_enum_domain_file = 'website_enum_domain.txt'


# Check if WPScan is installed
def is_wpscan_installed():
    try:
        subprocess.run(check_command.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("WPScan is installed but returned a non-zero exit status when checking version.")
        return False
    except FileNotFoundError:
        print("WPScan is not installed or not found in the PATH.")
        return False

# Install WPScan
def install_wpscan():
    try:
        subprocess.run(install_command.split(), check=True)
        print("WPScan installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing WPScan: {e}")


# Retrieve or ask for WPScan API key
def get_wpscan_api_key():
    if os.path.exists(api_key_file):
        with open(api_key_file, 'r') as file:
            data = json.load(file)
            return data.get('api_key')
    else:
        print("Please visit https://wpscan.com/ and register for free then visit your profile to copy the API key.")
        api_key = getpass.getpass("Paste your WPScan API key here and press enter: ")
        with open(api_key_file, 'w') as file:
            json.dump({'api_key': api_key}, file)
        return api_key


# Run WPScan with API Key
def run_wpscan(domain, api_key):
    output_dir = 'website_enum'
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, 'wpscan.txt')
    notification_title = "WPScan Complete"
    notification_body = f"WPScan for {domain} completed."
    wpscan_command = f"wpscan --url {domain} --api-token {api_key} --rua | tee {output_file}; notify-send \"{notification_title}\" \"{notification_body}\"; echo 'Scan complete. Press Enter to exit.'; read"
    try:
        subprocess.run(['gnome-terminal', '--', 'bash', '-c', wpscan_command], check=True)
        print(f"WPScan is executing against {domain}. Results will be saved to {output_file}.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while attempting to run WPScan: {e}")

def main(domain=None):
    if not is_wpscan_installed():
        print("WPScan is not installed. Installing now...")
        install_wpscan()

    api_key = get_wpscan_api_key()
    if not domain:
        domain_input = input("Please enter the domain(s) to scan (comma-separated if multiple): ")
        domains = [d.strip() for d in domain_input.split(',')]
    else:
        domains = [domain.strip()]

    if api_key:
        for domain in domains:
            if is_valid_domain(domain):
                run_wpscan(domain, api_key)
            else:
                print(f"Invalid domain: {domain}")
    else:
        print("WPScan API key is missing.")

if __name__ == "__main__":
    import sys
    domain_arg = sys.argv[1] if len(sys.argv) > 1 else None
    main(domain_arg)
