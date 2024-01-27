import subprocess
from datetime import datetime


def run_fping(hosts_input):
    # Get the current date to include in the filename
    current_date = datetime.now().strftime("%Y-%m-%d")
    filename = f"icmpecho_{current_date}.txt"

    # Command to execute fping
    command = ['fping', '-s', '-c', '1', '-f', hosts_input] if isinstance(hosts_input, str) else ['fping', '-s', '-c',
                                                                                                  '1'] + hosts_input

    # Running the fping command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, _ = process.communicate()

    # Decode and process the output
    alive_hosts = []
    with open(filename, 'w') as file:
        for line in output.decode().split('\n'):
            if 'xmt/rcv/%loss' in line and '1/0/100%' not in line:  # Check if the line contains the loss pattern and is not 100% loss
                alive_hosts.append(line)  # Append the entire line
                file.write(line + '\n')  # Write to file with a newline

    return alive_hosts