# project_handler.py

import os
import shutil
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Define colors using Colorama
BOLD_RED = Fore.RED + Style.BRIGHT
BOLD_GREEN = Fore.GREEN + Style.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style.BRIGHT

# Base projects directory path
projects_base_path = os.path.expanduser('~/projects')


def create_project_directory(org_name):
    project_path = os.path.join(projects_base_path, org_name)
    if not os.path.exists(project_path):
        os.makedirs(project_path)
        print(f"{BOLD_GREEN}Created project directory for '{org_name}' at {project_path}")
    else:
        print(f"{BOLD_YELLOW}Project directory for '{org_name}' already exists at {project_path}")
    return project_path


def load_project(org_name):
    project_path = os.path.join(projects_base_path, org_name)
    if os.path.exists(project_path):
        print(f"{BOLD_GREEN}Loaded project for '{org_name}'.")
        # Implement any specific logic for loading a project here
        # For example, you could change the current working directory:
        # os.chdir(project_path)
    else:
        print(f"{BOLD_RED}Project directory for '{org_name}' does not exist.")


def delete_project(org_name):
    project_path = os.path.join(projects_base_path, org_name)
    if os.path.exists(project_path):
        shutil.rmtree(project_path)
        print(f"{BOLD_GREEN}Deleted project directory for '{org_name}'.")
    else:
        print(f"{BOLD_RED}Project directory for '{org_name}' does not exist or has already been deleted.")


def project_submenu():
    while True:
        print("\nProject Management Menu:")
        print("1. Create Project")
        print("2. Load Project")
        print("3. Delete Project")
        print("4. Return to Main Menu")

        choice = input("\nEnter your choice: ").strip()

        if choice == '1':
            org_name = input("Enter the organization name for the new project: ").strip()
            create_project_directory(org_name)
        elif choice == '2':
            org_name = input("Enter the organization name to load the project: ").strip()
            load_project(org_name)
        elif choice == '3':
            org_name = input("Enter the organization name to delete the project: ").strip()
            delete_project(org_name)
        elif choice == '4':
            print(f"{BOLD_YELLOW}Returning to the main menu...")
            break
        else:
            print(f"{BOLD_RED}Invalid choice, please try again.")