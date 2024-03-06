import os
import re
import ipaddress
import subprocess
import glob
from rich.console import Console
from rich.style import Style
from rich.text import Text
from ascii_magic import AsciiArt
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
    os.system('cls' if os.name == 'nt' else 'clear')


def run_subprocess(command, working_directory=None, shell=False):
    try:
        result = subprocess.run(command, cwd=working_directory, shell=shell,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"{BOLD_RED}Subprocess error: {e.stderr}")
        return None


# Menu status functionality
def check_run_indicator(pattern):
    files = glob.glob(pattern)
    if files:
        return f"{BOLD_GREEN}✓{DEFAULT_COLOR}"
    else:
        return ""


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain):
    # Basic pattern for validating a standard domain name
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    return re.match(pattern, domain) is not None


def read_file_lines(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        print(f"{BOLD_RED}File not found: {filepath}")
        return None


def list_txt_files(directory):
    txt_files = [f for f in os.listdir(directory) if f.endswith('.txt')]
    if not txt_files:
        print(f"{BOLD_RED}No .txt files found in the current directory.")
        return None
    return txt_files

def read_file_lines(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        print(f"{BOLD_RED}File not found: {filepath}")
        return None


def write_to_file(filepath, content, mode='w'):
    try:
        with open(filepath, mode) as file:
            file.write(content)
    except IOError as e:
        print(f"{BOLD_RED}IO error occurred: {e}")


def is_valid_hostname(hostname):
    if not hostname:
        return False
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


# Function to get the current version from a file
def get_version():
    try:
        # Replace 'my-package-name' with the actual package name
        return get_distribution_version('infiltra')
    except Exception as e:
        print(f"Could not read version: {e}")
        return "unknown"


def get_ascii_art(image_path, columns=80):
    # Ensure the correct path is used for the image file
    script_directory = os.path.dirname(os.path.realpath(__file__))
    full_image_path = os.path.join(script_directory, image_path)

    # Check if the image exists
    if not os.path.isfile(full_image_path):
        return f"Image file not found: {full_image_path}"

    # Generate ASCII art from an image file
    try:
        art = AsciiArt.from_image(full_image_path)
        colored_art = art.to_terminal(columns=columns)
        return colored_art
    except Exception as e:
        return f"Error generating ASCII art: {e}"