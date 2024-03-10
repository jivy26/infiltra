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
    client = MsfRpcClient(password, ssl=True)  # Make sure to set ssl=True if msfrpcd is running with SSL
    console_id = client.consoles.console().cid  # Create a new console and get its ID

    for host in hosts:
        # Run the fuzzer for each host
        client.consoles.console(console_id).write('use auxiliary/fuzzers/ntp/ntp_protocol_fuzzer\n')
        client.consoles.console(console_id).write(f'set RHOSTS {host}\n')
        client.consoles.console(console_id).write('set VERBOSE true\n')
        client.consoles.console(console_id).write('run\n')

        # Allow some time for the command to execute, may require tuning
        time.sleep(5)

        # Read the output
        output = client.consoles.console(console_id).read()['data']
        print(output)  # Print to the console

        # Save the output to a file
        with open(f"{output_dir}/ntp_fuzzer_{host}.txt", 'w') as file:
            file.write(output)

        # Clean up the console, if you are done with it
        client.consoles.console(console_id).destroy()
