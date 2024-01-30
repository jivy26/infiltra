import re
import os

# Define colors
IT_MAG = "\033[35;3m"
BOLD_BLUE = "\033[34;1m"
COLOR_RESET = "\033[0m"
BOLD_CYAN = "\033[36;1m"
BOLD_GREEN = "\033[32;1m"
BOLD_RED = "\033[31;1m"
BOLD_YELLOW = "\033[33;1m"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def parse_bbot_output(file_path):
    sections = {
        'FINDINGS': [],
        'Vulnerabilities': [],
        'DNS Results': [],
        'ASN': [],
        'TCP Ports': [],
        'UDP Ports': [],
        'Technology': []
    }

    with open(file_path, 'r') as file:
        for line in file:
            line = re.sub(r"\s*\([^)]*\)", "", line)  # Remove anything in parentheses
            parts = line.split()
            if not parts:
                continue  # Skip empty lines

            tag = parts[0].strip('[]')
            content = ' '.join(parts[1:]).strip()

            if tag == 'FINDING':
                sections['FINDINGS'].append(content)
            elif tag == 'VULNERABILITY':
                sections['Vulnerabilities'].append(content)
            elif tag == 'DNS_NAME':
                sections['DNS Results'].append(content)
            elif tag == 'ASN':
                sections['ASN'].append(content)
            elif tag == 'OPEN_TCP_PORT':
                sections['TCP Ports'].append(content)
            elif tag == 'OPEN_UDP_PORT':
                sections['UDP Ports'].append(content)
            elif tag == 'TECHNOLOGY':
                sections['Technology'].append(content)

    return sections

def bbot_main():
    clear_screen()  # This will clear the screen
    use_default = input(f"{BOLD_CYAN}Use default bbot/output.txt? (Y/n): ").strip().lower()

    if use_default == '' or use_default.startswith('y'):
        file_name = os.path.join(os.getcwd(), "bbot", "output.txt")
    else:
        file_name = input("Please enter the path to your custom .txt file: ").strip()

    try:
        parsed_results = parse_bbot_output(file_name)
        for section, items in parsed_results.items():
            print(f"\n{BOLD_GREEN}{section} Section:")
            for item in items:
                print(f"- {item}")
            print()
        input(f"\n{BOLD_CYAN}Press any key to return to the menu...")
        clear_screen()  # This will clear the screen
    except FileNotFoundError:
        print("File does not exist. Please check the file name and path.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()