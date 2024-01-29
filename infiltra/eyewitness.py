import subprocess
import sys
import os
import random
import re

def check_install_dependencies():
    # Check for httprobe
    result = subprocess.run(['which', 'httprobe'], capture_output=True, text=True)
    if result.returncode != 0:
        print("Error: 'httprobe' is not installed. Please install it before running this script.")
        sys.exit(1)

    # Check for pup
    result = subprocess.run(['which', 'pup'], capture_output=True, text=True)
    if result.returncode != 0:
        print("Error: 'pup' is not installed. Please install it before running this script.")
        sys.exit(1)

def is_valid_domain(domain):
    # Regex for validating a domain (simple version, consider using a more complex regex for production use)
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return re.match(domain_regex, domain) is not None

def run_eyewitness(input_file):
    script_directory = os.path.dirname(os.path.realpath(__file__))
    eyewitness_dir = os.path.join(script_directory, 'eyewitness')
    eyewitness_path = os.path.join(eyewitness_dir, 'Python/EyeWitness.py')

    # Check if EyeWitness.py is present
    if not os.path.exists(eyewitness_path):
        print(f"Error: EyeWitness.py not found in {eyewitness_dir}")
        sys.exit(1)

    # Determine if input is a domain, single IP, or file
    if is_valid_domain(input_file):
        # Handle domain input
        temp_output_file = f"/tmp/enum_tmp_{str(random.randint(10000, 99999))}.txt"
        command = f'curl -fsSL "https://crt.sh/?q={input_file}" | pup "td text{{}}" | grep "{input_file}" | sort -n | uniq | httprobe > {temp_output_file}'
        subprocess.run(command, shell=True, check=True)
    elif os.path.isfile(input_file):
        # Handle file input
        temp_output_file = input_file
    else:
        # Handle single IP input
        temp_output_file = f"/tmp/enum_tmp_{str(random.randint(10000, 99999))}.txt"
        with open(temp_output_file, 'w') as file:
            file.write(input_file + '\n')

    # Run EyeWitness
    print(f"Running EyeWitness on {input_file}")
    subprocess.run(["python3", eyewitness_path, "-f", temp_output_file, "--web"], check=True)

    # Cleanup the temporary file if it was created for a domain or single IP
    if temp_output_file != input_file:
        os.remove(temp_output_file)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 eyewitness.py <domain or file>")
        sys.exit(1)

    input_file = sys.argv[1]
    check_install_dependencies()
    run_eyewitness(input_file)
