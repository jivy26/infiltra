import os
import re
import ipaddress
import subprocess
from ascii_magic import AsciiArt
from colorama import init, Fore, Style
from importlib.metadata import version as get_distribution_version


# Initialize Colorama
init(autoreset=True)

# Define colors using Colorama
DEFAULT_COLOR = Fore.WHITE
IT_MAG = Fore.MAGENTA + Style.BRIGHT
BOLD_BLUE = Fore.BLUE + Style.BRIGHT
BOLD_CYAN = Fore.CYAN + Style.BRIGHT
BOLD_GREEN = Fore.GREEN + Style.BRIGHT
BOLD_RED = Fore.RED + Style.BRIGHT
BOLD_MAG = Fore.MAGENTA + Style.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style.BRIGHT
BOLD_WHITE = Fore.WHITE + Style.BRIGHT


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