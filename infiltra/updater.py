from importlib.metadata import version, PackageNotFoundError
import os
import requests
from packaging import version as pkg_version

# Define color constants
BOLD_BLUE = "\033[34;1m"
COLOR_RESET = "\033[0m"
BOLD_GREEN = "\033[32;1m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[33;1m"

PACKAGE_NAME = 'infiltra'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_installed_version():
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return None

def check_and_update():
    installed_version = get_installed_version()
    if installed_version is None:
        return False

    pypi_url = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
    try:
        response = requests.get(pypi_url).json()
        available_version = response['info']['version']

        return pkg_version.parse(available_version) > pkg_version.parse(installed_version)
    except Exception:
        return False

if __name__ == '__main__':
    check_and_update()
