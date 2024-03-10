import subprocess
import os
import time

from pymetasploit3.msfrpc import MsfRpcClient
from infiltra.utils import RICH_CYAN, RICH_RED, RICH_GREEN, console, clear_screen


def start_metasploit_rpc(password):
    clear_screen()
    console.print("[+] Starting Metaploit RPC daemon please wait...\n", style=RICH_GREEN)
    msf_rpcd_command = [
        'msfrpcd',
        '-P', password,  # Set the RPC password
        '-S',           # Start with SSL
        '-a', '127.0.0.1',  # Bind to localhost
        # '-n',         # Uncomment if you do not want to use SSL
    ]

    try:
        # Start msfrpcd as a background process
        subprocess.Popen(msf_rpcd_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(10)  # Give msfrpcd some time to start up
        console.print("[+] Metasploit RPC daemon started successfully.", style=RICH_GREEN)
    except Exception as e:
        console.print(f"[-] Failed to start Metasploit RPC daemon: {e}", style=RICH_RED)
        exit(1)  # Exit if cannot start msfrpcd


def run_ntpq(hosts, output_dir):
    clear_screen()
    output_file = os.path.join(output_dir, 'ntpq.txt')
    with open(output_file, 'w') as file:
        for host in hosts:
            print(f"Running ntpq -p on {host}")
            try:
                result = subprocess.run(['ntpq', '-p', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                if "**Request timed out" in result.stderr:
                    # Handle timeout specifically if stderr contains the timeout message
                    timeout_msg = f"ntpq request timed out for {host}\n\n"
                    print(timeout_msg)  # Print to the console
                    file.write(timeout_msg)  # Write to the file
                else:
                    # If no timeout, write the standard output to file
                    output = f"Results for {host}:\n{result.stdout}\n\n"
                    print(output)  # Print to the console
                    file.write(output)  # Write to the file
            except subprocess.CalledProcessError as e:
                error_msg = f"Failed to execute ntpq for {host}: {e}\n\n"
                print(error_msg)  # Print to the console
                file.write(error_msg)  # Write to the file


def run_ntp_fuzzer(hosts, output_dir, password):
    output_file = os.path.join(output_dir, 'ntp_fuzzer.txt')

    # Connect to the Metasploit RPC server
    client = MsfRpcClient(password, port=55553)

    with open(output_file, 'w') as file:
        for host in hosts:
            try:
                # Create a new console
                console_id = client.consoles.console()
                # Write commands to the console
                console.write('use auxiliary/fuzzers/ntp/ntp_protocol_fuzzer\n')
                console.write('set RHOSTS {}\n'.format(host))
                console.write('set VERBOSE true\n')
                console.write('run\n')

                # Wait for the job to finish, this is just an example, may need to adjust the timing
                time.sleep(5)  # Give some time for the command to run
                # Read console output
                result = client.consoles.console(console_id).read()

                file.write(f"Fuzzer results for {host}:\n{result['data']}\n\n")
                print(f"Fuzzer results for {host}:\n{result['data']}\n")

                # Destroy the console when done
                client.consoles.console(console_id).destroy()

            except Exception as e:
                error_msg = f"Failed to run NTP fuzzer for {host}: {e}\n\n"
                print(error_msg)  # Print to the console
                file.write(error_msg)  # Write to the file
