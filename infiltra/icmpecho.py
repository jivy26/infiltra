import subprocess
import re
from datetime import datetime
from screenshot import take_screenshot

def run_fping(hosts_input):
    # Get the current date to include in the filename
    current_date = datetime.now().strftime("%Y-%m-%d")
    filename = f"icmpecho_{current_date}.txt"
    alive_hosts_filename = "alivehosts.txt"  # File to store alive hosts

    # Command to execute fping
    command = ['fping', '-s', '-c', '1', '-f', hosts_input] if isinstance(hosts_input, str) else ['fping', '-s', '-c',
                                                                                                  '1'] + hosts_input

    # Running the fping command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, _ = process.communicate()

    # Decode and process the output
    alive_hosts = []
    alive_ips = []  # List to store alive IPs
    with open(filename, 'w') as file, open(alive_hosts_filename, 'w') as alive_file:
        for line in output.decode().split('\n'):
            # Check if the line contains the loss pattern and is not 100% loss
            if 'xmt/rcv/%loss' in line and '1/0/100%' not in line:
                alive_hosts.append(line)  # Append the entire line
                file.write(line + '\n')  # Write to file with a newline
                # Extract IP address from line and write to alivehosts.txt
                match = re.search(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', line)
                if match:
                    alive_ip = match.group(1)
                    alive_ips.append(alive_ip)
                    alive_file.write(alive_ip + '\n')
    module_name = "icmpechho"
    take_screenshot(module_name)
    return alive_hosts
