import os
import re
import ipaddress
from ascii_magic import AsciiArt
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

