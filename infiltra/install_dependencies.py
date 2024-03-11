import subprocess
import sys

from infiltra.utils import BOLD_GREEN, BOLD_YELLOW, BOLD_RED


def check_and_install_gnome_terminal():
    try:
        # Check if gnome-terminal is installed
        subprocess.run(["which", "gnome-terminal"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{BOLD_GREEN}gnome-terminal is installed.")
    except subprocess.CalledProcessError:
        # gnome-terminal is not installed; proceed with installation
        print(f"{BOLD_YELLOW}gnome-terminal is not installed. Installing now...")
        install_command = "sudo apt install gnome-terminal -y"
        try:
            subprocess.run(install_command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print(f"{BOLD_GREEN}gnome-terminal installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"{BOLD_RED}Failed to install gnome-terminal: {e}")
            sys.exit(1)


def check_and_install_eyewitness():
    try:
        # Check if gnome-terminal is installed
        subprocess.run(["which", "eyewitness"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{BOLD_GREEN}eyewitness is installed.")
    except subprocess.CalledProcessError:
        # gnome-terminal is not installed; proceed with installation
        print(f"{BOLD_YELLOW}eyewitness is not installed. Installing now...")
        install_command = "sudo apt install eyewitness -y"
        try:
            subprocess.run(install_command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print(f"{BOLD_GREEN}eyewitness installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"{BOLD_RED}Failed to install eyewitness: {e}")
            sys.exit(1)


def check_and_install_sippts():
    try:
        # Check if 'sipscan' command is available in the system path
        subprocess.run(["which", "sipscan"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{BOLD_GREEN}sippts is installed.")
    except subprocess.CalledProcessError:
        print(f"{BOLD_YELLOW}sippts is not installed. Installing now...")
        try:
            # Use /tmp as the directory for installation to avoid permission issues
            tmp_dir = '/tmp/sippts'
            # Ensure the directory is clean before cloning
            subprocess.run(["rm", "-rf", tmp_dir], check=True)
            # Clone the repository
            subprocess.run(["git", "clone", "https://github.com/Pepelux/sippts.git", tmp_dir], check=True)
            # Install using pip in editable mode
            subprocess.run(["pip", "install", "-e", tmp_dir], check=True)
            print(f"{BOLD_GREEN}sippts installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"{BOLD_RED}Failed to install sippts: {e}")
            sys.exit(1)