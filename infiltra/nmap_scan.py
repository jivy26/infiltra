import os
import subprocess
import ipaddress
import sys

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def nmap_is_installed():
    return subprocess.run(['which', 'nmap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0

def run_nmap_scan(ip_list, scan_type):
    if scan_type not in ["tcp", "udp", "both"]:
        print("Invalid scan type: Choose 'tcp', 'udp', or 'both'.")
        sys.exit(1)

    if not nmap_is_installed():
        print("Nmap is not installed or not found in PATH.")
        sys.exit(1)

    # Prepare command strings
    tcp_scan_command = f"sudo nmap -sSV --top-ports 4000 -Pn -oG tcp.txt {' '.join(ip_list)}"
    udp_scan_command = f"sudo nmap -sU --top-ports 400 -Pn -oG udp.txt {' '.join(ip_list)}"

    # For immediate execution, use gnome-terminal
    if scan_type == "tcp" or scan_type == "both":
        tcp_command = ['gnome-terminal', '--', 'bash', '-c',
                       f"{tcp_scan_command} || echo 'An error occurred with the TCP scan.'; read"]
        subprocess.Popen(tcp_command)

    if scan_type == "udp" or scan_type == "both":
        udp_command = ['gnome-terminal', '--', 'bash', '-c',
                       f"{udp_scan_command} || echo 'An error occurred with the UDP scan.'; read"]
        subprocess.Popen(udp_command)

def main():
    if len(sys.argv) < 3:
        print("Usage: nmap_scan.py [single_ip/ip_file_path] [tcp/udp/both]")
        sys.exit(1)

    input_arg = sys.argv[1]
    scan_type = sys.argv[2].lower()

    try:
        if os.path.isfile(input_arg):
            with open(input_arg, 'r') as file:
                ip_list = file.read().splitlines()
                ip_list = [ip for ip in ip_list if is_valid_ip(ip)]
            # Run scan with file input
            run_nmap_scan(["-iL", input_arg], scan_type)
        elif is_valid_ip(input_arg):
            # Run scan with single IP
            run_nmap_scan([input_arg], scan_type)
        else:
            print("Invalid input: Please provide a valid single IP or a path to a text file with IPs.")
            sys.exit(1)

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
