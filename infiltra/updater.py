import pkg_resources
import os
import requests

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
        return pkg_resources.get_distribution(PACKAGE_NAME).version
    except pkg_resources.DistributionNotFound:
        return None

def check_and_update():
    clear_screen()
    installed_version = get_installed_version()

    if installed_version is None:
        print(f"{BOLD_RED}The package {PACKAGE_NAME} is not installed.{COLOR_RESET}")
        return

    pypi_url = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
    try:
        response = requests.get(pypi_url).json()
        available_version = response['info']['version']

        if pkg_resources.parse_version(available_version) > pkg_resources.parse_version(installed_version):
            print(f"{BOLD_GREEN}New update available: {available_version}{COLOR_RESET}")
            print(f"{BOLD_RED}Your version: {installed_version}{COLOR_RESET}")
            print(f"{BOLD_YELLOW}Run 'pip install --upgrade {PACKAGE_NAME}' to update.{COLOR_RESET}")
        else:
            print(f"{BOLD_GREEN}You are up-to-date with version {installed_version}.{COLOR_RESET}")

    except requests.HTTPError as http_err:
        print(f"{BOLD_RED}HTTP error occurred: {http_err}{COLOR_RESET}")
    except Exception as err:
        print(f"{BOLD_RED}An error occurred: {err}{COLOR_RESET}")

if __name__ == '__main__':
    check_and_update()
