import os
import re
import ipaddress
import subprocess
import glob
from rich.console import Console
from rich.style import Style
from rich.text import Text
from importlib.metadata import version as get_distribution_version

# Create a console object for Rich
console = Console()

# Style definitions using Rich
DEFAULT_COLOR = Style(color="white")
IT_MAG = Style(color="magenta", bold=True)
BOLD_BLUE = Style(color="blue", bold=True)
BOLD_CYAN = Style(color="cyan", bold=True)
BOLD_GREEN = Style(color="green", bold=True)
BOLD_RED = Style(color="red", bold=True)
BOLD_MAG = Style(color="magenta", bold=True)
BOLD_YELLOW = Style(color="yellow", bold=True)
BOLD_WHITE = Style(color="white", bold=True)

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
        console.print(f"Subprocess error: {e.stderr}", style=BOLD_RED)
        return None

def check_run_indicator(pattern):
    files = glob.glob(pattern)
    if files:
        return Text("✓", style=BOLD_GREEN)
    else:
        return Text("", style=DEFAULT_COLOR)

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
        console.print(f"File not found: {filepath}", style=BOLD_RED)
        return None

def list_txt_files(directory):
    txt_files = [f for f in os.listdir(directory) if f.endswith('.txt')]
    if not txt_files:
        console.print("No .txt files found in the current directory.", style=BOLD_RED)
        return None
    return txt_files

def write_to_file(filepath, content, mode='w'):
    try:
        with open(filepath, mode) as file:
            file.write(content)
    except IOError as e:
        console.print(f"IO error occurred: {e}", style=BOLD_RED)

def is_valid_hostname(hostname):
    if not hostname or len(hostname) > 255 or hostname[-1] == ".":
        hostname = hostname[:-1] if hostname[-1] == "." else hostname
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def get_version():
    try:
        return get_distribution_version('infiltra')
    except Exception as e:
        console.print(f"Could not read version: {e}", style=BOLD_RED)
        return "unknown"