import subprocess
import os

def run_ntpq(hosts, output_dir):
    output_file = os.path.join(output_dir, 'ntpq.txt')
    with open(output_file, 'w') as file:
        for host in hosts:
            try:
                print(f"Running ntpq -p on {host}")
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
            # Assuming the Metasploit framework is initialized and msfconsole is available in the PATH
            print(f"Running Metasploit NTP fuzzer on {host}")
            command = f"msfconsole -q -x 'use auxiliary/fuzzers/ntp/ntp_protocol_fuzzer; set RHOSTS {host}; run; exit'"
            try:
                result = subprocess.run(['bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                output = f"Fuzzer results for {host}:\n{result.stdout}\n\n"
                print(output)  # Print to the console
                file.write(output)  # Write to the file
            except subprocess.CalledProcessError as e:
                error_msg = f"Failed to run NTP fuzzer for {host}: {e}\n\n"
                print(error_msg)  # Print to the console
                file.write(error_msg)  # Write to the file