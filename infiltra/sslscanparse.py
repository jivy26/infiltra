'''
SSLScanner and Parser
Author: Joshua Ivy
Modified: 1/1/2024
'''

import subprocess
import re
import datetime
import sys


# Default path to the file containing IP addresses if no command-line argument is provided
default_ip_file_path = 'tcp_parsed/https-hosts.txt'  # Define this before using it in the conditional statement below

# Check if a command-line argument was provided for the IP file path
if len(sys.argv) > 1:
    ip_file_path = sys.argv[1]
else:
    ip_file_path = default_ip_file_path  # Use the default IP file path

# Vulnerability criteria
vulnerabilities = {
    #'Weak Protocols': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
    'Weak Ciphers': ["DES", "3DES", "RC4", "RC2", "MD5", "EXPORT", "NULL", "IDEA", "SEED", "PSK", "SRP", "KRB5"],
    'StartTLS Enabled': 'StartTLS',
    'Anonymous Diffie-Helman Ciphers': 'ADH',
    'TLS Fallback Not Enabled': 'Server does not support TLS Fallback SCSV',
    'Insecure Hashing Algorithm': ['MD5', 'SHA-1', 'RC4']
}

# ANSI Escape Code for Bold Text
GREEN = '\033[92m'
BLUE = '\033[34;1m'
YELLOW = '\033[33;1m'
MAGENTA = '\033[35;1m'
BOLD = '\033[1m'
END = '\033[0m'


# Command to open a new terminal window and run sslscan
def open_new_terminal_and_run_sslscan(target):
    # Split the target into IP and port
    if ':' in target:
        ip, port = target.split(':')
    else:
        ip, port = target, '443'

    # Command to open a new terminal window and run sslscan
    command = f"""qterminal -e bash -c 'sslscan --port={port} {ip}; echo "Press enter to close..."; read'"""
    subprocess.Popen(command, shell=True)


# Function to remove ANSI escape codes
def remove_ansi_escape_sequences(text):
    ansi_escape_pattern = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)


# Function to run sslscan and parse output
def ssl_scan(ip):
    findings = {key: [] for key in vulnerabilities.keys()}
    dheater_findings = []
    rsa_findings = []
    expired_cert_findings = []
    self_signed_findings = []
    long_lived_cert_findings = []
    crime_findings = []
    weak_keyspace_findings = []
    protocol_findings = []
    fallback_scsv_findings = []
    session_renegotiation_findings = []

    # Current date for comparison
    current_date = datetime.datetime.now()

    # Variable to store 'Not valid before' date
    not_valid_before = None

    #
    self_signed_found = False

    # Variable to store if TLS Fallback SCSV is found
    tls_fallback_scsv_found = False

    try:
        result = subprocess.run(['sslscan', ip], capture_output=True, text=True, timeout=60)
        output_lines = result.stdout.split('\n')

        # Debug: Print raw output to check for ANSI codes
        # print("Raw sslscan output:")
        # print(result.stdout)

        # Variables to store subject and issuer for comparison
        subject = ""
        issuer = ""

        for line in output_lines:
            # Debug: Print the line after removing ANSI escape sequences
            cleaned_line = remove_ansi_escape_sequences(line)
            # print(f"Processed line: {cleaned_line}")

            for vuln, criteria in vulnerabilities.items():
                if isinstance(criteria, list):
                    # Check if any weak cipher is in the line
                    if vuln == 'Weak Ciphers' and any(cipher in line for cipher in criteria):
                        findings[vuln].append(line)
                    # Check if weak protocol is enabled
                    elif any(crit in line and 'enabled' in line.lower() for crit in criteria):
                        findings[vuln].append(line)
                else:
                    # This is the important check for TLS Fallback
                    if criteria in cleaned_line:
                        findings[vuln].append(cleaned_line)

            # Check each protocol for 'enabled' status
            for protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                protocol_match = re.search(rf"{protocol}\s+(enabled)", cleaned_line)
                if protocol_match:
                    protocol_findings.append(f"{protocol} is enabled - Found on {ip}")

            # Check for TLS Fallback SCSV support
            fallback_scsv_match = re.search(r"Server does not support TLS Fallback SCSV", cleaned_line)
            if fallback_scsv_match:
                # If the line saying server supports TLS Fallback SCSV is found, and it has not been set to True yet
                if not tls_fallback_scsv_found:
                    fallback_scsv_findings.append(f"Server does not support TLS Fallback SCSV - Found on {ip}")
                    tls_fallback_scsv_found = True  # Set the flag to True so this block won't run again

            # Check for session renegotiation support
            session_renegotiation_match = re.search(r"Session renegotiation (supported)", cleaned_line)
            if session_renegotiation_match:
                session_renegotiation_findings.append(f"Session renegotiation supported - Found on {ip}")

            # Check for weak key space in ciphers
            cipher_line_match = re.search(r'Accepted\s+\S+\s+(\d+)\s+bits', line)
            if cipher_line_match:
                key_strength = int(cipher_line_match.group(1))
                if key_strength < 128:
                    weak_keyspace_findings.append(f"Weak Key Space (<128 bits): {line}")

            # Check for TLS Compression
            tls_compression_match = re.search(r'TLS Compression:\s+(.*)', line)
            if tls_compression_match:
                tls_compression_status = remove_ansi_escape_sequences(tls_compression_match.group(1)).strip()
                if tls_compression_status != 'Compression disabled':
                    crime_findings.append(f"TLS Compression (CRIME) Vulnerability: {line}")

            # Check for 'Not valid before' date
            not_valid_before_match = re.search(r'Not valid before:\s+(.+)', line)
            if not_valid_before_match:
                not_valid_before_str = remove_ansi_escape_sequences(not_valid_before_match.group(1))
                not_valid_before = datetime.datetime.strptime(not_valid_before_str, "%b %d %H:%M:%S %Y GMT")

            # Check for 'Not valid after' date and compare with 'Not valid before'
            not_valid_after_match = re.search(r'Not valid after:\s+(.+)', line)
            if not_valid_after_match and not_valid_before:
                not_valid_after_str = remove_ansi_escape_sequences(not_valid_after_match.group(1))
                not_valid_after = datetime.datetime.strptime(not_valid_after_str, "%b %d %H:%M:%S %Y GMT")

                # Check if the validity period is longer than three years
                validity_period = not_valid_after - not_valid_before
                if validity_period.days > 3 * 365:
                    long_lived_cert_findings.append(f"{line}")

            # Check for Subject
            subject_match = re.search(r'Subject:\s+(.*)', line)
            if subject_match and not self_signed_found:
                subject = remove_ansi_escape_sequences(subject_match.group(1)).strip()

            # Check for Issuer
            issuer_match = re.search(r'Issuer:\s+(.*)', line)
            if issuer_match and not self_signed_found:
                issuer = remove_ansi_escape_sequences(issuer_match.group(1)).strip()

            # Compare Subject and Issuer for self-signed certificate
            if subject and issuer and subject == issuer and not self_signed_found:
                self_signed_findings.append(f"Self-Signed Certificate: {subject}")
                self_signed_found = True

            # Check for expired certificates
            expired_match = re.search(r'Not valid after:\s+(.+)', line)
            if expired_match:
                # Only remove ANSI codes from the expiry date string
                expiry_date_str = remove_ansi_escape_sequences(expired_match.group(1))
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y GMT")
                if expiry_date < current_date:
                    expired_cert_findings.append(f"{line}")

            # Additional regex check for 'DHE' with 2048 bits or less
            dhe_match = re.search(r'DHE.*?(\d+) bits', cleaned_line)
            if dhe_match:
                dhe_bits = int(dhe_match.group(1))
                if dhe_bits <= 2048:
                    dheater_findings.append(line)

            # Additional regex check for 'RSA' with less than 2048 bits on the cleaned line
            rsa_match = re.search(r'RSA Key Strength:\s+(\d+)', cleaned_line)
            if rsa_match:
                rsa_bits = int(rsa_match.group(1))
                if rsa_bits < 2048:
                    # Append finding to the rsa_findings list in the desired format
                    rsa_findings.append(f"{rsa_bits} bits")

        if protocol_findings:
            findings['Weak Protocols'] = protocol_findings

        if crime_findings:
            findings['TLS Compression (CRIME)'] = crime_findings

        if weak_keyspace_findings:
            findings['Weak Key Space'] = weak_keyspace_findings

        if dheater_findings:
            findings['DHeater'] = dheater_findings

        if rsa_findings:
            findings['Weak RSA Key'] = rsa_findings

        if expired_cert_findings:
            findings['Expired Certification'] = expired_cert_findings

        if long_lived_cert_findings:
            findings['Long-Lived Certificate'] = long_lived_cert_findings

        if self_signed_findings:
            findings['Self-Signed Certificate Signatures'] = self_signed_findings

        if fallback_scsv_findings:
            findings['TLS Fallback SCSV'] = fallback_scsv_findings

        if session_renegotiation_findings:
            findings['Session Renegotiation'] = session_renegotiation_findings

        return {vuln: lines for vuln, lines in findings.items() if lines}
    except Exception as e:
        return {f"Error scanning {ip}": [str(e)]}


# Read IPs from file and run sslscan, output to sslscan.txt
with open(ip_file_path, 'r') as file, open('sslscan.txt', 'w') as output_file:
    for ip in file:
        ip = ip.strip()
        if ip:
            # Initialize (or reset) the flag for each IP address before processing it
            self_signed_found = False
            tls_fallback_scsv_found = False

            output_file.write(f"\n\n=============[Scanning {ip}]=============\n")
            print(f"\n\n{BLUE}=============[{END}{GREEN}Scanning {ip}{END}{BLUE}]============={END}", flush=True)
            scan_results = ssl_scan(ip)
            if scan_results:
                for vuln, lines in scan_results.items():
                    output_file.write(f"\n- {vuln} Found on {ip}\n\n")
                    output_file.writelines('\n'.join(lines) + '\n')
                    print(f"\n{GREEN}{BOLD}- {vuln} Found on {ip}{END}\n", flush=True)
                    for line in lines:
                        print(line)
            else:
                # No findings, so automatically open sslscan in a new window
                output_file.write(f"\nNo findings for {ip}, automatically loading a window to run scans for a screenshot.\n")
                print(f"\n{YELLOW}No findings for {ip}, automatically loading a window to run scans for a screenshot.{END}", flush=True)
                open_new_terminal_and_run_sslscan(ip)
                # Pause the script to allow the user to take a screenshot
                input(f"{GREEN}A new window has been opened. Press Enter after taking a screenshot to continue...{END}")