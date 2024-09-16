import requests
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
import sys
import os
from colorama import init, Fore, Style  
from rich.panel import Panel
from rich import print as rich_print
import time

init(autoreset=True)
class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    BOLD = '\033[1m'
    UNBOLD = '\033[22m'


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    title = r"""
  _________                                  .__  
 /   _____/____    _____  __ ______________  |__| 
 \_____  \\__  \  /     \|  |  \_  __ \__  \ |  | 
 /        \/ __ \|  Y Y  \  |  /|  | \// __ \|  | 
/_______  (____  /__|_|  /____/ |__|  (____  /__| 
        \/     \/      \/                  \/     
"""
    print(Color.YELLOW + Style.BRIGHT + title.center(63)) 
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    border_color = Color.PURPLE + Style.BRIGHT
    option_color = Fore.WHITE + Style.BRIGHT
    print(border_color + "┌" + "─" * 61 + "┐")
    options = [
        "1) XSS Scanner",
        "2) LFI Scanner",
        "3) Exit"
    ]
    for option in options:
        print(border_color + "│" + option_color + option.ljust(61) + border_color + "│")

    print(border_color + "└" + "─" * 61 + "┘")
    authors = "Created by LexSem"
    instructions = "Select an option:"
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    print(Fore.WHITE + Style.BRIGHT + authors.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)

def selection_choice(selection):
    if selection == '1':
        clear_screen()
        run_xss_scanner()
    elif selection == '2':
        clear_screen()
        run_lfi_scanner()
    elif selection == '3':
        clear_screen()
        exit_menu()

def exit_menu():
    clear_screen()
    panel = Panel(r"""
 ______               ______              
|   __ \.--.--.-----.|   __ \.--.--.-----.
|   __ <|  |  |  -__||   __ <|  |  |  -__|
|______/|___  |_____||______/|___  |_____|
        |_____|              |_____|      
   
        """,
        style="bold green",
        border_style="yellow",
        expand=False
    )

    rich_print(panel)
    print(Color.RED + "\n\nSamurai stopped working...\n")
    exit()


def run_xss_scanner():

    title = r"""
 ___    ___ ________   ________  ________  ________  ________   ________   _______   ________     
|\  \  /  /|\   ____\ |\   ____\|\   ____\|\   __  \|\   ___  \|\   ___  \|\  ___ \ |\   __  \    
\ \  \/  / | \  \___|_\ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ \  \\ \  \ \   __/|\ \  \|\  \   
 \ \    / / \ \_____  \\ \_____  \ \  \    \ \   __  \ \  \\ \  \ \  \\ \  \ \  \_|/_\ \   _  _\  
  /     \/   \|____|\  \\|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ \  \\ \  \ \  \_|\ \ \  \\  \| 
 /  /\   \     ____\_\  \ ____\_\  \ \_______\ \__\ \__\ \__\\ \__\ \__\\ \__\ \_______\ \__\\ _\ 
/__/ /\ __\   |\_________\\_________\|_______|\|__|\|__|\|__| \|__|\|__| \|__|\|_______|\|__|\|__|
|__|/ \|__|   \|_________\|_________|                                                             
                                                                                                  
                                                                                                  
"""
    print(Color.CYAN + Style.BRIGHT + title.center(63))

    url = input(Fore.GREEN + "[?] Enter URL for scanning: " + Style.RESET_ALL).strip()
    payload_file = input(Fore.CYAN + "[?] Enter payload file name: " + Style.RESET_ALL).strip()

   
    if not os.path.isfile(payload_file):
        print(Fore.RED + "[!] File not found. Try again." + Style.RESET_ALL)
        return

    
    payloads = load_payloads(payload_file)
    scan_xss(url, payloads)


def load_payloads(payload_file):
    try:
        with open(payload_file, "r") as file:
            payloads = [line.strip() for line in file if line.strip()]
        if not payloads:
            print(Fore.RED + f"[!] The file {payload_file} is empty." + Style.RESET_ALL)
            sys.exit(1)
        return payloads
    except Exception as e:
        print(Fore.RED + f"[!] Error reading file {payload_file}: {e}" + Style.RESET_ALL)
        sys.exit(1)


def generate_payload_urls(url, payload):
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string, keep_blank_values=True)
    urls_with_payloads = []

    for key in query_params.keys():
        modified_params = query_params.copy()
        modified_params[key] = [payload]  # Insert payload into the parameter
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        urls_with_payloads.append(modified_url)

    return urls_with_payloads


def check_for_xss(url, payload):
    try:
        response = requests.get(url)
    
        if payload in response.text:
            print(Fore.RED + f"[!] Possible XSS vulnerability at {url}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"[-] No XSS found at {url}" + Style.RESET_ALL)
    except requests.RequestException as e:
        print(Fore.RED + f"[!] Error making request to {url}: {e}" + Style.RESET_ALL)

def scan_xss(url, payloads):
    print(Fore.YELLOW + f"[*] Scanning URL: {url}" + Style.RESET_ALL)
    for payload in payloads:
        print(Fore.YELLOW + f"[*] Testing with payload: {payload}" + Style.RESET_ALL)
        payload_urls = generate_payload_urls(url, payload)
        for payload_url in payload_urls:
            check_for_xss(payload_url, payload)


def load_files_from_user(file_path):
    try:
        with open(file_path, 'r') as file:
            files = [line.strip() for line in file.readlines()]
        return files
    except FileNotFoundError:
        print(f"[!] File {file_path} not found.")
        return []


def scan_lfi(url, files):
    for file in files:
        
        target_url = url + file
        try:
           
            response = requests.get(target_url)
            if response.status_code == 200 and file in response.text:
                print(f"[+] LFI vulnerability found: {file}")
            else:
                print(f"[-] No LFI vulnerability found for {file}")
        except Exception as e:
            print(f"[!] Error connecting to {url}: {e}")


def run_lfi_scanner():
    title = r"""
.____   ___________.___  __________________     _____    _______    _______  _____________________ 
|    |  \_   _____/|   |/   _____/\_   ___ \   /  _  \   \      \   \      \ \_   _____/\______   \
|    |   |    __)  |   |\_____  \ /    \  \/  /  /_\  \  /   |   \  /   |   \ |    __)_  |       _/
|    |___|     \   |   |/        \\     \____/    |    \/    |    \/    |    \|        \ |    |   \
|_______ \___  /   |___/_______  / \______  /\____|__  /\____|__  /\____|__  /_______  / |____|_  /
        \/   \/                \/         \/         \/         \/         \/        \/         \/ 
                                                                                                  
"""
    print(Color.ORANGE + Style.BRIGHT + title.center(63))    
    url = input("Enter the URL to scan : ")

    file_path = input("Enter the path to the file with files to scan: ")
    
    files = load_files_from_user(file_path)
    if files:
        scan_lfi(url, files)

def main():
    clear_screen()
    time.sleep(1)
    clear_screen()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit_menu()


while True:
    display_menu()
    choice = input(f"\n{Fore.CYAN}[?] Select an option (0-3): {Style.RESET_ALL}").strip()
    selection_choice(choice)


