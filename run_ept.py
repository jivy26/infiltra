import subprocess
import sys

# The exit code that indicates an update has occurred
UPDATE_EXIT_CODE = 85


def main():
    while True:
        # Run the ept.py script and wait for it to complete
        process = subprocess.run(['python', 'ept.py'])

        # If the exit code is the special update code, restart the script
        if process.returncode == UPDATE_EXIT_CODE:
            print("Update detected, restarting the tool...")
            continue
        else:
            # If it's any other exit code, break the loop (exit the wrapper)
            break


if __name__ == "__main__":
    main()