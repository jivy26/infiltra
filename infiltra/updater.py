import os
import subprocess
from packaging import version
import requests
import stat
import threading
import time
import pkg_resources
import sys

# Exit Code
UPDATE_EXIT_CODE = 85

# Define color constants
BOLD_BLUE = "\033[34;1m"
COLOR_RESET = "\033[0m"
BOLD_GREEN = "\033[32;1m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[33;1m"


def print_progress(stop_event):
    print(f"{BOLD_BLUE}Starting update...", end="")
    while not stop_event.is_set():
        print(".", end="", flush=True)
        time.sleep(0.5)
    print(f"")


def is_git_repository(path):
    try:
        subprocess.run(['git', '-C', path, 'status'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False


def set_executable_permissions(file_path):
    # Check if the file has executable permissions
    if not os.access(file_path, os.X_OK):
        print(f"Setting executable permissions for: {file_path}")
        st = os.stat(file_path)
        os.chmod(file_path, st.st_mode | stat.S_IEXEC)


def set_permissions_for_all_executables(directory):
    # Iterate over files in the current working directory only
    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path) and (file_path.endswith('.sh') or file_path.endswith('.py')):
            # Check if the file has executable permissions
            if not os.access(file_path, os.X_OK):
                st = os.stat(file_path)
                os.chmod(file_path, st.st_mode | stat.S_IEXEC)


def get_version(version_file_path):
    try:
        with open(version_file_path, "r") as file:
            return file.read().strip()
    except Exception as e:
        print(f"Could not read version file: {e}")
        return "unknown"


def get_latest_version_from_github(github_repo):
    releases_url = f'https://api.github.com/repos/{github_repo}/releases/latest'
    response = requests.get(releases_url)
    response.raise_for_status()  # Raises stored HTTPError, if one occurred
    latest_release = response.json()
    return latest_release['tag_name']


def update_needed(local_version, remote_version):
    return version.parse(local_version) < version.parse(remote_version)


def perform_update(repo_dir):
    stop_event = threading.Event()
    progress_thread = threading.Thread(target=print_progress, args=(stop_event,))
    progress_thread.start()

    try:
        # Fetch the latest changes from the remote repository
        subprocess.run(["git", "fetch", "origin"], cwd=repo_dir, check=True)
        # Reset the current HEAD to the latest fetched version
        subprocess.run(["git", "reset", "--hard", "origin/master"], cwd=repo_dir, check=True)
        # Clean untracked files
        subprocess.run(["git", "clean", "-fd"], cwd=repo_dir, check=True)

        stop_event.set()
        progress_thread.join()  # Wait for the progress thread to finish

        print(f"\n{BOLD_GREEN}Update completed successfully.")

        # Set executable permissions for script files
        print(f"{BOLD_YELLOW}Checking file permissions and setting executable if necessary...", end="", flush=True)
        set_permissions_for_all_executables(repo_dir)
        print(f"{BOLD_GREEN} Done.")

    except subprocess.CalledProcessError as e:
        stop_event.set()
        progress_thread.join()  # Ensure the progress thread is stopped
        print(f"\n{BOLD_RED}An error occurred while updating: {e}")


def check_and_update():
    os.system('clear')  # Clear the screen at the beginning of the function
    dir_of_script = os.path.dirname(os.path.realpath(__file__))
    version_file_path = os.path.join(dir_of_script, "version.txt")
    local_version = get_version(version_file_path)

    try:
        github_repo = 'jivy26/epttool'  # Replace with your GitHub username/repo
        latest_version_tag = get_latest_version_from_github(github_repo)

        if update_needed(local_version, latest_version_tag):
            print(f"{BOLD_GREEN}New update available: {latest_version_tag}")
            print(f"{BOLD_RED}Your version: {local_version}")
            # Proceed with the update after user confirmation
            input(f"{BOLD_YELLOW}Press any key to start the update or Ctrl+C to cancel...")
            perform_update(dir_of_script)
            print("Update was successful. Please restart the tool to apply the updates.")
            return True  # Indicate that an update was performed
        else:
            print(f"{BOLD_GREEN}You are up-to-date with version {local_version}.")

        # Wait for user input before returning to the main menu #
        input(f"{BOLD_YELLOW}Press any key to return to the main menu...")

        return False #No Update Neccessary

    except requests.HTTPError as http_err:
        print(f"{BOLD_RED}HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"{BOLD_RED}An error occurred: {err}")
