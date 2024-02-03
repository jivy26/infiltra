import pkg_resources
import os
import requests

# Define color constants
BOLD_BLUE = "\033[34;1m"
COLOR_RESET = "\033[0m"
BOLD_GREEN = "\033[32;1m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[33;1m"


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def get_installed_version(package_name):
    try:
        return pkg_resources.get_distribution(package_name).version
    except pkg_resources.DistributionNotFound:
        return None


def check_and_update(package_name):
    clear_screen()
    installed_version = get_installed_version(package_name)

    if installed_version is None:
        print(f"{BOLD_RED}The package {package_name} is not installed.")
        return False

    pypi_url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(pypi_url).json()
        available_version = response['info']['version']

        if pkg_resources.parse_version(available_version) > pkg_resources.parse_version(installed_version):
            print(f"{BOLD_GREEN}New update available: {available_version}")
            print(f"{BOLD_RED}Your version: {installed_version}")
            print(f"{BOLD_YELLOW}Run 'pip install --upgrade {package_name}' to update.")
            return True
        else:
            print(f"{BOLD_GREEN}You are up-to-date with version {installed_version}.")
            return False

    except requests.HTTPError as http_err:
        print(f"{BOLD_RED}HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"{BOLD_RED}An error occurred: {err}")


# Replace 'your-package-name' with the actual name of your package on PyPI.
if __name__ == '__main__':
    check_and_update('your-package-name')
