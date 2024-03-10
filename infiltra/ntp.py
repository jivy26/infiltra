import subprocess
import os

from infiltra.utils import RICH_CYAN, RICH_RED, RICH_GREEN, console, clear_screen

def run_ntpq(hosts, output_dir):
    clear_screen()
    output_file = os.path.join(output_dir, 'ntpq.txt')
    with open(output_file, 'w') as file:
        for host in hosts:
            try:
                console.print(f"Running ntpq -p on {host}", style=RICH_CYAN)
                result = subprocess.run(['ntpq', '-p', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                output = f"Results for {host}:\n{result.stdout}\n\n"
                print(output)  # Print to the console
                file.write(output)  # Write to the file
            except subprocess.CalledProcessError as e:
                error_msg = f"Failed to execute ntpq for {host}: {e}\n\n"
                print(error_msg)  # Print to the console
                file.write(error_msg)  # Write to the file

def run_ntp_fuzzer(hosts, output_dir):
    output_file = os.path.join(output_dir, 'ntp_fuzzer.txt')
    with open(output_file, 'w') as file:
        for host in hosts:
            print(f"Running Metasploit NTP fuzzer on {host}")
            # Add 'set VERBOSE true' to the Metasploit command string
            command = (
                f"msfconsole -q -x '"
                f"use auxiliary/fuzzers/ntp/ntp_protocol_fuzzer; "
                f"set RHOSTS {host}; "
                f"set VERBOSE true; "
                f"run; exit'"
            )
            try:
                result = subprocess.run(['bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                output = f"Fuzzer results for {host}:\n{result.stdout}\n\n"
                print(output)  # Print to the console
                file.write(output)  # Write to the file
            except subprocess.CalledProcessError as e:
                error_msg = f"Failed to run NTP fuzzer for {host}: {e}\n\n"
                print(error_msg)  # Print to the console
                file.write(error_msg)  # Write to the file