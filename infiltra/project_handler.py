# project_handler.py

import os
import shutil
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Define colors using Colorama
DEFAULT_COLOR = Fore.WHITE
IT_MAG = Fore.MAGENTA + Style.BRIGHT
BOLD_BLUE = Fore.BLUE + Style.BRIGHT
BOLD_CYAN = Fore.CYAN + Style.BRIGHT
BOLD_GREEN = Fore.GREEN + Style.BRIGHT
BOLD_RED = Fore.RED + Style.BRIGHT
BOLD_YELLOW = Fore.YELLOW + Style.BRIGHT

# Base projects directory path
projects_base_path = os.path.expanduser('~/projects')


def create_project_directory(org_name):
    os.system('clear')
    project_path = os.path.join(projects_base_path, org_name)
    if not os.path.exists(project_path):
        os.makedirs(project_path)
        print(f"{BOLD_GREEN}Created project directory for '{org_name}' at {project_path}")
    else:
        print(f"{BOLD_YELLOW}Project directory for '{org_name}' already exists at {project_path}")
    return project_path


def load_project():
    os.system('clear')
    projects = list_projects()
    if not projects:
        print(f"{BOLD_RED}There are no projects to load.")
        return None

    print(f"{BOLD_CYAN}Available Projects:")
    for idx, project in enumerate(projects, start=1):
        print(f"{BOLD_GREEN}{idx}. {project}")

    choice = input(f"{BOLD_YELLOW}Enter the number of the project to load: ").strip()
    if choice.isdigit():
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(projects):
            org_name = projects[choice_idx]
            project_path = os.path.join(projects_base_path, org_name)
            print(f"{BOLD_GREEN}Loaded project for '{org_name}'.")
            return project_path
        else:
            print(f"{BOLD_RED}Invalid project number.")
    else:
        print(f"{BOLD_RED}Please enter a valid number.")
    return None


def delete_project():
    os.system('clear')
    projects = list_projects()
    if not projects:
        print(f"{BOLD_RED}There are no projects to delete.")
        return None

    print(f"{BOLD_CYAN}Available Projects:")
    for idx, project in enumerate(projects, start=1):
        print(f"{BOLD_GREEN}{idx}. {project}")

    choice = input(f"{BOLD_YELLOW}Enter the number of the project to delete: ").strip()
    if choice.isdigit():
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(projects):
            org_name = projects[choice_idx]
            confirm = input(f"{BOLD_RED}Are you sure you want to delete the project '{org_name}'? (y/N): ").strip().lower()
            if confirm == 'y':
                project_path = os.path.join(projects_base_path, org_name)
                shutil.rmtree(project_path)
                print(f"{BOLD_GREEN}Deleted project '{org_name}'.")
                return projects_base_path
            else:
                print(f"{BOLD_YELLOW}Project deletion cancelled.")
        else:
            print(f"{BOLD_RED}Invalid project number.")
    else:
        print(f"{BOLD_RED}Please enter a valid number.")
    return None


def list_projects():
    os.system('clear')
    projects = [d for d in os.listdir(projects_base_path) if os.path.isdir(os.path.join(projects_base_path, d))]
    return projects


def project_submenu():
    os.system('clear')
    project_path = None
    while True:
        print(f"\n{BOLD_GREEN}Project Management Menu:\n")
        print(f"{BOLD_GREEN}1. Create Project")
        print(f"{BOLD_GREEN}2. Load Project")
        print(f"{BOLD_GREEN}3. Delete Project")

        print(f"\n{BOLD_CYAN}Utilities:")
        print(f"{BOLD_RED}X. Return to Main Menu")

        choice = input("\nEnter your choice: ").strip().lower()

        if choice == '1':
            os.system('clear')
            org_name = input(f"{BOLD_GREEN}Enter the organization name for the new project: ").strip()
            project_path = create_project_directory(org_name)
            if project_path:
                os.chdir(project_path)
        elif choice == '2':
            os.system('clear')
            project_path = load_project()
            if project_path:
                os.chdir(project_path)
        elif choice == '3':
            os.system('clear')
            project_path = delete_project()
            if project_path:
                os.chdir(project_path)
        elif choice == 'x':
            print(f"{BOLD_YELLOW}Returning to the main menu...")
            break
        else:
            print(f"{BOLD_RED}Invalid choice, please try again.")

    return project_path or projects_base_path

