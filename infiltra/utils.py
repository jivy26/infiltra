import os
import re
import ipaddress
import subprocess
import glob
from colorama import init, Fore
from colorama import Style as Style1
from rich.console import Console
from rich.style import Style
from rich.text import Text
from importlib.metadata import version as get_distribution_version


# Initialize Colorama
init(autoreset=True)

# Define colors using Colorama
DEFAULT_COLOR = Fore.WHITE
IT_MAG = Fore.MAGENTA + Style1.BRIGHT
BOLD_BLUE = Fore.BLUE + Style1.BRIGHT
BOLD_CYAN = Fore.CYAN + Style1.BRIGHT
BOLD_GREEN = Fore.GREEN + Style1.BRIGHT
BOLD_RED = Fore.RED + Style1.BRIGHT
BOLD_MAG = Fore.MAGENTA + Style1.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style1.BRIGHT
BOLD_WHITE = Fore.WHITE + Style1.BRIGHT


# Create a console object for Rich
console = Console()

# Style definitions using Rich
RICH_COLOR = Style(color="white")
RICH_BLUE = Style(color="blue", bold=True)
RICH_CYAN: Style = Style(color="cyan", bold=True)
RICH_GREEN = Style(color="green", bold=True)
RICH_RED = Style(color="red", bold=True)
RICH_MAG = Style(color="magenta", bold=True)
RICH_YELLOW = Style(color="yellow", bold=True)
RICH_WHITE = Style(color="white", bold=True)


def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def run_subprocess(command, working_directory=None, shell=False):
    try:
        result = subprocess.run(command, cwd=working_directory, shell=shell,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        console.print(f"Subprocess error: {e.stderr}", RICH_RED)
        return None

def check_run_indicator(pattern):
    files = glob.glob(pattern)
    if files:
        return Text("✓", RICH_GREEN)
    else:
        return Text("", DEFAULT_COLOR)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    return re.match(pattern, domain) is not None

def read_file_lines(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        console.print(f"File not found: {filepath}", RICH_RED)
        return None

def list_txt_files(directory):
    txt_files = [f for f in os.listdir(directory) if f.endswith('.txt')]
    if not txt_files:
        print(f"{BOLD_RED}No .txt files found in the current directory.")
        return None
    return txt_files

def write_to_file(filepath, content, mode='w'):
    try:
        with open(filepath, mode) as file:
            file.write(content)
    except IOError as e:
        console.print(f"IO error occurred: {e}", RICH_RED)

def is_valid_hostname(hostname):
    if not hostname or len(hostname) > 255 or hostname[-1] == ".":
        hostname = hostname[:-1] if hostname[-1] == "." else hostname
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def get_version():
    try:
        return get_distribution_version('infiltra')
    except Exception as e:
        console.print(f"Could not read version: {e}", RICH_RED)
        return "unknown"