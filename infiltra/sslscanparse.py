'''
SSLScanner and Parser
Author: Joshua Ivy
Modified: 1/1/2024
'''

import subprocess
import re
import datetime
import sys
import logging

# Configure logging
logging.basicConfig(filename='sslscan_parser.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Default path to the file containing IP addresses if no command-line argument is provided
default_ip_file_path = 'tcp_parsed/https-hosts.txt'

# Check if a command-line argument was provided for the IP file path
ip_file_path = sys.argv[1] if len(sys.argv) > 1 else default_ip_file_path

# Vulnerability criteria
vulnerabilities = {
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


# Function to remove ANSI escape codes
def remove_ansi_escape_sequences(text):
    ansi_escape_pattern = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)


# Function to run sslscan and parse output
def ssl_scan(ip, port):
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

    current_date = datetime.datetime.now()
    not_valid_before = None
    self_signed_found = False
    tls_fallback_scsv_found = False

    try:
        if port == '443':
            result = subprocess.run(['sslscan', ip], capture_output=True, text=True, timeout=60)
        else:
            result = subprocess.run(['sslscan', f'https://{ip}:{port}'], capture_output=True, text=True, timeout=60)

        output_lines = result.stdout.split('\n')

        subject = ""
        issuer = ""

        for line in output_lines:
            cleaned_line = remove_ansi_escape_sequences(line)

            for vuln, criteria in vulnerabilities.items():
                if isinstance(criteria, list):
                    if vuln == 'Weak Ciphers' and any(cipher in line for cipher in criteria):
                        findings[vuln].append(line)
                    elif any(crit in line and 'enabled' in line.lower() for crit in criteria):
                        findings[vuln].append(line)
                else:
                    if criteria in cleaned_line:
                        findings[vuln].append(cleaned_line)

            for protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                protocol_match = re.search(rf"{protocol}\s+(enabled)", cleaned_line)
                if protocol_match:
                    protocol_findings.append(f"{protocol} is enabled - Found on {ip}:{port}")

            fallback_scsv_match = re.search(r"Server does not support TLS Fallback SCSV", cleaned_line)
            if fallback_scsv_match and not tls_fallback_scsv_found:
                fallback_scsv_findings.append(f"Server does not support TLS Fallback SCSV - Found on {ip}:{port}")
                tls_fallback_scsv_found = True

            session_renegotiation_match = re.search(r"Session renegotiation (supported)", cleaned_line)
            if session_renegotiation_match:
                session_renegotiation_findings.append(f"Session renegotiation supported - Found on {ip}:{port}")

            cipher_line_match = re.search(r'Accepted\s+\S+\s+(\d+)\s+bits', line)
            if cipher_line_match:
                key_strength = int(cipher_line_match.group(1))
                if key_strength < 128:
                    weak_keyspace_findings.append(f"Weak Key Space (<128 bits): {line}")

            tls_compression_match = re.search(r'TLS Compression:\s+(.*)', line)
            if tls_compression_match:
                tls_compression_status = remove_ansi_escape_sequences(tls_compression_match.group(1)).strip()
                if tls_compression_status != 'Compression disabled':
                    crime_findings.append(f"TLS Compression (CRIME) Vulnerability: {line}")

            not_valid_before_match = re.search(r'Not valid before:\s+(.+)', line)
            if not_valid_before_match:
                not_valid_before_str = remove_ansi_escape_sequences(not_valid_before_match.group(1))
                not_valid_before = datetime.datetime.strptime(not_valid_before_str, "%b %d %H:%M:%S %Y GMT")

            not_valid_after_match = re.search(r'Not valid after:\s+(.+)', line)
            if not_valid_after_match and not_valid_before:
                not_valid_after_str = remove_ansi_escape_sequences(not_valid_after_match.group(1))
                not_valid_after = datetime.datetime.strptime(not_valid_after_str, "%b %d %H:%M:%S %Y GMT")
                validity_period = not_valid_after - not_valid_before
                if validity_period.days > 3 * 365:
                    long_lived_cert_findings.append(f"{line}")

            subject_match = re.search(r'Subject:\s+(.*)', line)
            if subject_match and not self_signed_found:
                subject = remove_ansi_escape_sequences(subject_match.group(1)).strip()

            issuer_match = re.search(r'Issuer:\s+(.*)', line)
            if issuer_match and not self_signed_found:
                issuer = remove_ansi_escape_sequences(issuer_match.group(1)).strip()

            if subject and issuer and subject == issuer and not self_signed_found:
                self_signed_findings.append(f"Self-Signed Certificate: {subject}")
                self_signed_found = True

            expired_match = re.search(r'Not valid after:\s+(.+)', line)
            if expired_match:
                expiry_date_str = remove_ansi_escape_sequences(expired_match.group(1))
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y GMT")
                if expiry_date < current_date:
                    expired_cert_findings.append(f"{line}")

            dhe_match = re.search(r'DHE.*?(\d+) bits', cleaned_line)
            if dhe_match:
                dhe_bits = int(dhe_match.group(1))
                if dhe_bits <= 2048:
                    dheater_findings.append(line)

            rsa_match = re.search(r'RSA Key Strength:\s+(\d+)', cleaned_line)
            if rsa_match:
                rsa_bits = int(rsa_match.group(1))
                if rsa_bits < 2048:
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
        logging.error(f"Error scanning {ip}:{port} - {str(e)}")
        return {f"Error scanning {ip}:{port}": [str(e)]}


# Read IPs from file and run sslscan, output to sslscan.txt
with open(ip_file_path, 'r') as file, open('sslscan.txt', 'w') as output_file:
    for line in file:
        target = line.strip()
        if target:
            if ':' in target:
                ip, port = target.split(':')
            else:
                ip, port = target, '443'

            logging.info(f"Starting scan for {ip}:{port}")

            self_signed_found = False
            tls_fallback_scsv_found = False

            output_file.write(f"\n\n=============[Scanning {ip}:{port}]=============\n")
            print(f"\n\n{BLUE}=============[{END}{GREEN}Scanning {ip}:{port}{END}{BLUE}]============={END}", flush=True)
            scan_results = ssl_scan(ip, port)
            if scan_results:
                for vuln, lines in scan_results.items():
                    output_file.write(f"\n- {vuln} Found on {ip}:{port}\n\n")
                    for line in lines:
                        output_file.write(line + '\n')
                        print(f"\n{GREEN}{BOLD}- {line}{END}\n", flush=True)
            else:
                output_file.write(f"\nNo findings for {ip}:{port}\n")
                print(f"\n{YELLOW}No findings for {ip}:{port}{END}", flush=True)
