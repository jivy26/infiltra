import subprocess
import os
import re

from infiltra.utils import clear_screen, BOLD_GREEN, BOLD_CYAN, BOLD_YELLOW, BOLD_RED


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
def main(project_path):
    while True:
        clear_screen()
        print(f"{BOLD_CYAN}EyeWitness Menu:")
        print(f"1. Use AORT Subdomains")
        print(f"2. Enumerate and Screenshot a Domain")
        print(f"3. Use Custom Subdomain File")
        print(f"\n{BOLD_RED}X. Return to OSINT Menu")

        choice = input(f"\n{BOLD_GREEN}Enter your choice: ").lower()

        if choice == '1':
            aort_file_path = os.path.join(project_path, 'aort_dns.txt')
            if os.path.isfile(aort_file_path):
                run_eyewitness(aort_file_path)
            else:
                print(f"{BOLD_RED}AORT has not been run. Please go back a menu and run AORT, then try again.")
                input(f"{BOLD_GREEN}Press Enter to continue...")

        elif choice == '2':
            domain = input(f"{BOLD_GREEN}Please enter a domain to enumerate and screenshot: ").strip()
            if is_valid_domain(domain):
                enumerate_and_screenshot_domain(domain)
            else:
                print(f"{BOLD_RED}Invalid domain. Please enter a valid domain.")
                input(f"{BOLD_GREEN}Press Enter to continue...")

        elif choice == '3':
            custom_file = input(f"{BOLD_GREEN}Please enter the full path to your custom subdomain file: ").strip()
            if os.path.isfile(custom_file):
                run_eyewitness(custom_file)
            else:
                print(f"{BOLD_RED}File does not exist or invalid path.")
                input(f"{BOLD_GREEN}Press Enter to continue...")

        elif choice == 'x':
            break
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.")
            input(f"{BOLD_GREEN}Press Enter to continue...")

if __name__ == '__main__':
    main()