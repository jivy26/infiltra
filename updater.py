import os
import subprocess
from packaging import version
import requests
import stat


# Define color constants
BOLD_BLUE = "\033[34;1m"
COLOR_RESET = "\033[0m"
BOLD_GREEN = "\033[32;1m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[33;1m"


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
    # Iterate over all files in the directory
    for subdir, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(subdir, file)
            if file_path.endswith('.sh') or file_path.endswith('.py'):  # Check for .sh and .py files
                set_executable_permissions(file_path)


def get_version(version_file_path):
    with open(version_file_path, "r") as file:
        return file.read().strip()


def get_latest_version_from_github(github_repo):
    releases_url = f'https://api.github.com/repos/{github_repo}/releases/latest'
    response = requests.get(releases_url)
    response.raise_for_status()  # Raises stored HTTPError, if one occurred
    latest_release = response.json()
    return latest_release['tag_name']


def update_needed(local_version, remote_version):
    return version.parse(local_version) < version.parse(remote_version)


def perform_update(repo_dir):
    print(f"{BOLD_BLUE}Starting update...{COLOR_RESET}")

    try:
        # Fetch the latest changes from the remote repository
        subprocess.run(["git", "fetch", "origin"], cwd=repo_dir, check=True)
        # Reset the current HEAD to the latest fetched version
        subprocess.run(["git", "reset", "--hard", "origin/master"], cwd=repo_dir, check=True)
        # Clean untracked files
        subprocess.run(["git", "clean", "-fd"], cwd=repo_dir, check=True)

        print(f"{BOLD_GREEN}Update completed successfully.{COLOR_RESET}")

        # Set executable permissions
        set_permissions_for_all_executables(repo_dir)


    except subprocess.CalledProcessError as e:
        print(f"{BOLD_RED}An error occurred while updating: {e}{COLOR_RESET}")


def check_and_update():
    os.system('clear')  # Clear the screen at the beginning of the function
    dir_of_script = os.path.dirname(os.path.realpath(__file__))
    version_file_path = os.path.join(dir_of_script, "version.txt")
    local_version = get_version(version_file_path)

    try:
        github_repo = 'jivy26/epttool'  # Replace with your GitHub username/repo
        latest_version_tag = get_latest_version_from_github(github_repo)

        if update_needed(local_version, latest_version_tag):
            print(f"{BOLD_GREEN}New update available: {latest_version_tag}{COLOR_RESET}")
            print(f"{BOLD_RED}Your version: {local_version}{COLOR_RESET}")
            # Proceed with the update after user confirmation
            input(f"{BOLD_YELLOW}Press any key to start the update or Ctrl+C to cancel...{COLOR_RESET}")
            perform_update(dir_of_script)
        else:
            print(f"{BOLD_GREEN}You are up-to-date with version {local_version}.{COLOR_RESET}")

        # Wait for user input before returning to the main menu
        input(f"{BOLD_YELLOW}Press any key to return to the main menu...{COLOR_RESET}")

    except requests.HTTPError as http_err:
        print(f"{BOLD_RED}HTTP error occurred: {http_err}{COLOR_RESET}")
    except Exception as err:
        print(f"{BOLD_RED}An error occurred: {err}{COLOR_RESET}")
