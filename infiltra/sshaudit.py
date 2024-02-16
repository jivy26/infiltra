import subprocess
import re
import sys

def is_ssh_audit_installed():
    try:
        subprocess.run(["ssh-audit", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_ssh_audit():
    try:
        subprocess.run(["sudo", "apt", "install", "ssh-audit", "-y"], check=True)
        print("ssh-audit installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install ssh-audit: {e}")
        sys.exit(1)

def run_ssh_audit(ip, port=22):
    try:
        result = subprocess.run(["ssh-audit", f"{ip}:{port}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        if '[fail]' in output:
            fail_lines = [line for line in output.split('\n') if '[fail]' in line]
            print('\n'.join(fail_lines))
        else:
            print("No [fail] findings.")
            print("Rerunning ssh-audit for you to take a screenshot...")
            subprocess.run(["ssh-audit", f"{ip}:{port}"])  # This will output directly to the terminal
    except subprocess.CalledProcessError as e:
        print(f"ssh-audit failed: {e}")

def main():
    if not is_ssh_audit_installed():
        print("ssh-audit is not installed. Installing now...")
        install_ssh_audit()

    ip_input = input("Enter the IP address (optionally with port, format IP:port): ").strip()
    match = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?", ip_input)
    if match:
        ip = match.group(1)
        port = int(match.group(2)) if match.group(2) else 22
        run_ssh_audit(ip, port)
    else:
        print("Invalid IP address format.")

    input("Press Enter to return to the menu...")

if __name__ == "__main__":
    main()
