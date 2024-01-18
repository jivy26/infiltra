import os
import subprocess
import sys
from updater import check_and_update


UPDATE_EXIT_CODE = 85


# Define color constants
BOLD_BLUE = "\033[34;1m"
COLOR_RESET = "\033[0m"
BOLD_CYAN = "\033[36;1m"
BOLD_GREEN = "\033[32;1m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[33;1m"


# Function to get the current version from a file
def get_version():
    # Get the directory in which the script is located
    dir_of_script = os.path.dirname(os.path.realpath(__file__))
    # Construct the full path to the version.txt file
    version_file_path = os.path.join(dir_of_script, "version.txt")
    with open(version_file_path, "r") as file:
        return file.read().strip()


# Function to run EyeWitness
def run_eyewitness():
    os.system('clear')  # Clear the screen at the beginning of the function
    script_directory = os.path.dirname(os.path.realpath(__file__))
    eyewitness_script_path = os.path.join(script_directory, 'eyewitness.py')
    
    # Set default file path
    default_file = 'tcp_parsed/https-hosts.txt'
    
    # Prompt user for input
    print(f"\n{BOLD_CYAN}If you provide a domain, it will enumerate subdomains and attempt to screenshot them after enumeration.{COLOR_RESET}")
    user_input = input(f"\n{BOLD_GREEN}Enter a single IP, domain, or path to a file with domains (leave blank to use default https-hosts.txt from nmap_grep): {COLOR_RESET}").strip()
    
    # Determine which file or IP to use
    if user_input:
        input_file = user_input  # Use the user-provided file or IP
    else:
        input_file = default_file  # Use the default https-hosts.txt file
    
    # Inform the user which input will be used
    if os.path.isfile(input_file):
        print(f"Using file: {input_file}")
    else:
        print(f"Using IP/domain: {input_file}")
    
    # Run the EyeWitness Python script
    subprocess.run(['python3', eyewitness_script_path, input_file])

    input(f"{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu


# Function to run sslscan and parse results
def run_sslscanparse():
    os.system('clear')  # Clear the screen at the beginning of the function
    sslscan_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'sslscanparse.py')
    default_file = 'tcp_parsed/https-hosts.txt'

    # Module Info Box
    message_lines = [
        "This module will run SSLScans on all IPs provided",
        "and use regex to only parse SSLScans with findings."
    ]

    # Determine the width of the box based on the longest message line
    width = max(len(line) for line in message_lines) + 4  # padding for the sides of the box

    # Print the top border of the box
    print("+" + "-" * (width - 2) + "+")

    # Print each line of the message, centered within the box
    for line in message_lines:
        print("| " + line.center(width - 4) + " |")

    # Print the bottom border of the box
    print("+" + "-" * (width - 2) + "+")
    # End Module Info Box

    print(f"\n{BOLD_RED}By default, this scans 'https-hosts.txt' which might not include all forward-facing web servers on non-standard ports such as 10443, etc.{COLOR_RESET}")
    use_default = input(f"\n{BOLD_BLUE}Do you want to use the default https-hosts.txt file? (Y/n): {COLOR_RESET}").strip().lower()
    
    if use_default == '' or use_default.startswith('y'):
        input_file = default_file
    else:
        input_file = input(f"{BOLD_BLUE}Enter the path to your custom .txt file with HTTPS hosts: {COLOR_RESET}").strip()
    
    # Check if the file exists
    if not os.path.isfile(input_file):
        print(f"{BOLD_RED}The file {input_file} does not exist. Please enter a valid file name.{COLOR_RESET}")
        return
    
    # Run the sslscanparse script
    print(f"\n{BOLD_GREEN}Running sslscanparse.py on {input_file}{COLOR_RESET}")
    process = subprocess.Popen(['python3', sslscan_script_path, input_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()  # Wait for the subprocess to finish
    
    # Display the output
    print(stdout.decode())

    # Check for errors
    if stderr:
        print(f"{BOLD_RED}An error occurred:\n" + stderr.decode())

    input(f"{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu


# Function to run whois script
def run_whois():
    os.system('clear')  # Clear the screen at the beginning of the function
    whois_script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'whois_script.sh')

    # Module Info Box
    message_lines = [
        "This module will look for OrgName in all whois requests",
        "and parse the names 1 per line."
    ]

    # Determine the width of the box based on the longest message line
    width = max(len(line) for line in message_lines) + 4  # padding for the sides of the box

    # Print the top border of the box
    print("+" + "-" * (width - 2) + "+")

    # Print each line of the message, centered within the box
    for line in message_lines:
        print("| " + line.center(width - 4) + " |")

    # Print the bottom border of the box
    print("+" + "-" * (width - 2) + "+")
    # End Module Info Box

    ip_input = input(f"\n{BOLD_GREEN}Enter a single IP or path to a file with IPs: {COLOR_RESET}").strip()
    
    # Run the whois script
    print(f"\n{BOLD_GREEN}Running whois_script.sh on {ip_input}{COLOR_RESET}")
    process = subprocess.Popen(['bash', whois_script_path, ip_input], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()  # Wait for the subprocess to finish
    
    # Display the output
    print(stdout.decode())

    # Check for errors
    if stderr:
        print(f"{BOLD_RED}An error occurred:\n" + stderr.decode())

    input(f"{BOLD_GREEN}Press any key to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu


def run_ngrep(scan_type):
    os.system('clear')  # Clear the screen at the beginning of the function
    script_directory = os.path.dirname(os.path.realpath(__file__))
    ngrep_script_path = os.path.join(script_directory, 'nmap-grep.sh')
    output_file = f"{scan_type.lower()}.txt"  # Assume the output file is named tcp.txt or udp.txt based on the scan_type
    output_path = f"{scan_type.lower()}_parsed/"  # Assume the output folder is named tcp_parsed/ or udp_parsed/ based on the scan_type

    # Check if the output directory already exists
    if os.path.isdir(output_path):
        overwrite = input(f"The directory {output_path} already exists. Overwrite it? (y/n): ").strip().lower()
        if overwrite == 'y':
            subprocess.run(['rm', '-rf', output_path])  # Removes the directory recursively
        else:
            print(f"Not overwriting the existing directory {output_path}.")
            return  # Exit the function if the user does not want to overwrite

    # Continue with running the nmap-grep.sh script
    print(f"{BOLD_GREEN}Running nmap-grep.sh on {output_file} for {scan_type.upper()} scans{COLOR_RESET}")
    subprocess.run(['bash', ngrep_script_path, output_file, scan_type.upper()])
    input(f"{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu


# Function to display the menu
def display_menu(version):
    os.system('clear')  # Clear the screen
    print(f"{BOLD_CYAN}TraceSecurity External Penetration Test Script{COLOR_RESET}{BOLD_GREEN} v{version}{COLOR_RESET}")
    print(f"\n{BOLD_GREEN}Menu Options:{COLOR_RESET}\n")
    print("1. Run Whois")
    print("2. Run Nmap Scan")
    print("3. Run Ngrep on Nmap Output")
    print("4. Run SSLScans and Parse Findings")
    print("5. Run EyeWitness")
    print(f"\n{BOLD_CYAN}U. Check For Updates{COLOR_RESET}")
    print(f"{BOLD_RED}X. Exit{COLOR_RESET}")


# Function to run nmap scan
def run_nmap():
    os.system('clear')  # Clear the screen at the beginning of the function
    ip_input = input(f"\n{BOLD_GREEN}Enter a single IP or path to a file with IPs: {COLOR_RESET}")
    print(f"\n{BOLD_CYAN} NMAP Scans will run the following commands for TCP and UDP: {COLOR_RESET}")
    print(f"\n{BOLD_CYAN} TCP: nmap -sSV --top-ports 4000 -Pn {COLOR_RESET}")
    print(f"{BOLD_CYAN} UDP: nmap -sU --top-ports 400 -Pn {COLOR_RESET}")
    scan_type = input(f"\n{BOLD_GREEN}Enter scan type (tcp/udp/both): {COLOR_RESET}").lower()
    script_directory = os.path.dirname(os.path.realpath(__file__))
    nmap_script_path = os.path.join(script_directory, 'nmap_scan.py')

    # Make sure the input is not empty
    if ip_input and scan_type in ['tcp', 'udp', 'both']:
        print(f"\n{BOLD_GREEN}Running nmap_scan.py from {nmap_script_path}{COLOR_RESET}")
        if scan_type in ['tcp', 'both']:
            tcp_command = ['qterminal', '-e', f'sudo python3 {nmap_script_path} {ip_input} tcp']
            subprocess.Popen(tcp_command)
        if scan_type in ['udp', 'both']:
            udp_command = ['qterminal', '-e', f'sudo python3 {nmap_script_path} {ip_input} udp']
            subprocess.Popen(udp_command)
        print(f"\n{BOLD_GREEN}Nmap {scan_type} scans launched in separate windows.{COLOR_RESET}")
    else:
        print(f"{BOLD_YELLOW}Invalid input. Make sure you enter a valid IP, file path, and scan type.{COLOR_RESET}")

    input(f"\n{BOLD_GREEN}Press Enter to return to the menu...{COLOR_RESET}")  # Allow users to see the message before returning to the menu



# Main function
def main():
    version = get_version()
    while True:
        display_menu(version)
        choice = input(f"\n{BOLD_GREEN}Enter your choice: {COLOR_RESET}").lower()
        if choice == '1':
            run_whois()
        elif choice == '2':
            run_nmap()
        elif choice == '3':  # Call run_ngrep when the user selects option 2
            scan_type = input(f"{BOLD_GREEN}Enter the scan type that was run (TCP/UDP): {COLOR_RESET}").upper()
            run_ngrep(scan_type)
        elif choice == '4':
            run_sslscanparse()
        elif choice == '5':
            run_eyewitness()
        elif choice == 'u':
            print("Checking for updates...")
            check_and_update()
            updated = check_and_update()
            if updated:
                # Exit with a special code to signal the wrapper to restart
                sys.exit(UPDATE_EXIT_CODE)
        elif choice == 'x':
            break
        else:
            print(f"{BOLD_YELLOW}Invalid choice, please try again.{COLOR_RESET}")


# Ensure the `packaging` library is installed
try:
    from packaging import version
except ImportError:
    print(f"{BOLD_RED}The 'packaging' library is required for version comparison. Please install it using 'pip install packaging'.{COLOR_RESET}")
    exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting...")
        sys.exit()