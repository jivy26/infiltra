import os
import subprocess
import re

from infiltra.utils import clear_screen, BOLD_GREEN, BOLD_CYAN


# Regex for validating a domain
domain_regex = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def is_installed(command):
    return subprocess.run(["which", command], stdout=subprocess.PIPE).returncode == 0

def install_required_tools():
    # Check for and install 'pup' if necessary
    if not is_installed("pup"):
        print(f"{BOLD_CYAN}Installing 'pup'...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "pup"], check=True)

    # Check for and install 'httprobe' if necessary
    if not is_installed("httprobe"):
        print(f"{BOLD_CYAN}Installing 'httprobe'...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "httprobe"], check=True)


def is_valid_domain(domain):
    return re.match(domain_regex, domain) is not None

def enumerate_and_screenshot_domain(domain):
    rand = os.urandom(4).hex()  # Using random hex instead of RANDOM for better uniqueness
    temp_output_file = f"/tmp/enum_tmp_{rand}.txt"
    crtsh_command = (
        f"curl -fsSL 'https://crt.sh/?q={domain}' | pup 'td text{{}}' | "
        f"grep '{domain}' | sort -n | uniq | httprobe > {temp_output_file}"
    )
    subprocess.run(crtsh_command, shell=True, check=True)
    eyewitness_command = ['eyewitness', '-f', temp_output_file, '--web']
    subprocess.run(eyewitness_command, check=True)
    os.remove(temp_output_file)  # Clean up the temp file

def run_eyewitness(input_path):
    subprocess.run(['eyewitness', '-f', input_path, '--web'], check=True)

def main():
    clear_screen()
    install_required_tools()
    clear_screen()

    # Set default file path
    default_file = 'aort_dns.txt'

    # Prompt user for input
    print(
        f"\n{BOLD_CYAN}If you provide a domain, it will enumerate subdomains and attempt to screenshot them after enumeration."
    )
    user_input = input(
        f"\n{BOLD_GREEN}Enter a single IP, domain, or path to a file with domains (leave blank to use default aort_dns.txt from nmap_grep): "
    ).strip()

    # If user input is a valid domain, perform enumeration and screenshot process
    if is_valid_domain(user_input):
        enumerate_and_screenshot_domain(user_input)
    # If user input is a path to a file or left blank, use the normal EyeWitness process
    elif os.path.isfile(user_input) or not user_input:
        run_eyewitness(user_input or default_file)
    else:
        print(f"{BOLD_GREEN}Invalid input. Please enter a valid domain or file path.")

    input(f"{BOLD_GREEN}Press Enter to return to the menu...")

if __name__ == "__main__":
    main()