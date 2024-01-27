import subprocess
import sys
import os
import getpass

# The exit code that indicates an update has occurred
UPDATE_EXIT_CODE = 85


def main():
    # Get the username of the currently logged-in user
    username = getpass.getuser()

    # Define the absolute path to ept.py using the username
    ept_script_path = f'/home/{username}/tools/ept/ept.py'

    while True:
        # Check if the ept.py script exists at the specified path
        if not os.path.isfile(ept_script_path):
            print(f"Error: {ept_script_path} does not exist.")
            sys.exit(1)

        # Run the ept.py script using its absolute path and wait for it to complete
        process = subprocess.run(['python', ept_script_path], cwd=os.path.dirname(ept_script_path))

        # If the exit code is the special update code, restart the script
        if process.returncode == UPDATE_EXIT_CODE:
            print("Update detected, restarting the tool...")
            continue
        else:
            # If it's any other exit code, break the loop (exit the wrapper)
            break


if __name__ == "__main__":
    main()
