import re
import subprocess
import ipaddress
import ascii_magic
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
    # Generate ASCII art from an image file
    output = ascii_magic.from_image_file(image_path, mode=ascii_magic.Modes.HTML, columns=columns)
    # Get the ASCII art with color
    colored_art = ascii_magic.to_ansi(output)
    return colored_art
