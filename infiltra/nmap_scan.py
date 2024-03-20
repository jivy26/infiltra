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


def run_nmap_scan(ip_list, scan_type, project_path, schedule=False):
    # Create the 'tmp' directory within the project path if it doesn't exist
    tmp_dir = os.path.join(project_path, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)

    # Define the path to the marker file inside the 'tmp' direc
    marker_file = os.path.join(tmp_dir, "nmap_scan_ongoing.marker")

    if scan_type not in ["tcp", "udp", "both"]:
        print("Invalid scan type: Choose 'tcp', 'udp', or 'both'.")
        sys.exit(1)

    if not nmap_is_installed():
        print("Nmap is not installed or not found in PATH.")
        sys.exit(1)

    # Prepare command strings
    tcp_scan_command = f"sudo nmap -sSV --top-ports 4000 -Pn -oG tcp.txt {' '.join(ip_list)}"
    udp_scan_command = f"sudo nmap -sU --top-ports 400 -Pn -oG udp.txt {' '.join(ip_list)}"

    if not schedule:
        if scan_type == "tcp" or scan_type == "both":
            subprocess.Popen(tcp_scan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if scan_type == "udp" or scan_type == "both":
            subprocess.Popen(udp_scan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        # Create a marker file to indicate the scan has started
        with open(marker_file, "w") as f:
            f.write("Scan started")

        # For scheduled execution, run the command directly
        if scan_type == "tcp" or scan_type == "both":
            subprocess.run(tcp_scan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if scan_type == "udp" or scan_type == "both":
            subprocess.run(udp_scan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

       # Delete the marker file
        if os.path.exists(marker_file):
            os.remove(marker_file)


def main():
    if len(sys.argv) < 3:
        print("Usage: nmap_scan.py [single_ip/ip_file_path] [tcp/udp/both] [True/False for scheduled]")
        sys.exit(1)

    scheduled = len(sys.argv) == 4 and sys.argv[3] == 'True'
    input_arg = sys.argv[1]
    scan_type = sys.argv[2].lower()

    try:
        if os.path.isfile(input_arg):
            with open(input_arg, 'r') as file:
                ip_list = file.read().splitlines()
                # Validate IPs in file
                for ip in ip_list:
                    if not is_valid_ip(ip):
                        print(f"Invalid IP found in file: {ip}")
                        sys.exit(1)
            # Run scan with file input
            run_nmap_scan(["-iL", input_arg], scan_type, scheduled)
        elif is_valid_ip(input_arg):
            # Run scan with single IP
            run_nmap_scan([input_arg], scan_type, scheduled)
        else:
            print("Invalid input: Please provide a valid single IP or a path to a text file with IPs.")
            sys.exit(1)

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()