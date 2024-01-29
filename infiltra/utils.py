import re
import subprocess
import ipaddress
from importlib.metadata import version as get_distribution_version

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname):
    if not hostname:
        return False
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


# Function to get the current version from a file
def get_version():
    try:
        # Replace 'my-package-name' with the actual package name
        return get_distribution_version('infiltra')
    except Exception as e:
        print(f"Could not read version: {e}")
        return "unknown"


def get_ascii_art(text):
    # Run the toilet command with subprocess and capture the output
    try:
        result = subprocess.run(['toilet', '-f', 'mono9', '-F', 'gay', text], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        # Decode the result from bytes to a string and return it
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        return f"Error generating ASCII art: {e}"
