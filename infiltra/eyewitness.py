import os
import subprocess

from infiltra.utils import clear_screen, BOLD_GREEN, BOLD_CYAN

def main():
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

    # Determine which file or IP to use
    input_file = user_input if user_input else default_file

    # Inform the user which input will be used
    print(f"Using file: {input_file}" if os.path.isfile(input_file) else f"Using IP/domain: {input_file}")

    # Run the EyeWitness system command
    subprocess.run(['eyewitness', '-f', input_file, '--web'])  # Modify the arguments as needed for EyeWitness

    input(f"{BOLD_GREEN}Press Enter to return to the menu...")  # Allow users to see the message before returning to the menu

if __name__ == "__main__":
    main()