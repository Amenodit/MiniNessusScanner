from colorama import Fore, Style, init

init(autoreset=True)

def log_info(message):
    print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")

def log_success(message):
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def log_error(message):
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

def log_warning(message):
    print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")