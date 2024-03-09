import os
import subprocess
import sys

from infiltra.utils import RICH_GREEN, RICH_YELLOW, RICH_RED, clear_screen, console


def check_and_install_sippts():
    try:
        subprocess.run(["which", "sipscan"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        console.print(f"{RICH_GREEN}sippts is installed.")
    except subprocess.CalledProcessError:
        console.print(f"{RICH_YELLOW}sippts is not installed. Installing now...")
        install_command = "pip install sippts"
        try:
            subprocess.run(install_command.split(), check=True)
            console.print(f"{RICH_GREEN}sippts installed successfully.")
        except subprocess.CalledProcessError as e:
            console.print(f"{RICH_RED}Failed to install sippts: {e}")
            sys.exit(1)


def run_sippts_commands_for_host(ip):
    output_dir = 'voip'
    os.makedirs(output_dir, exist_ok=True)

    sippts_commands = [
        f'sipscan -i {ip} -r 5060',
        f'sipenumerate -i {ip} r 5060',
        f'sipexten -i {ip} -r 5060 -e 100-150',
        f'sipinvite -i {ip} -r 5060 -tu 100'
    ]

    for command in sippts_commands:
        output_file = os.path.join(output_dir, f'{command.split()[0]}_{ip.replace(".", "_")}.txt')
        try:
            subprocess.run(f'{command} > {output_file}', shell=True, check=True)
            console.print(f"{RICH_GREEN}Successfully executed: {command} with output saved to {output_file}")
        except subprocess.CalledProcessError as e:
            console.print(f"{RICH_RED}Failed to execute {command}: {e}")


def main():
    clear_screen()
    check_and_install_sippts()
    clear_screen()
    if len(sys.argv) < 2:
        console.print(f"{RICH_YELLOW}Usage: {sys.argv[0]} <IP address or file with IP list>")
        sys.exit(1)

    hosts_arg = sys.argv[1]
    if os.path.isfile(hosts_arg):
        with open(hosts_arg, 'r') as file:
            ips = [line.strip() for line in file.readlines()]
    else:
        ips = [hosts_arg]

    for ip in ips:
        run_sippts_commands_for_host(ip)


if __name__ == "__main__":
    main()