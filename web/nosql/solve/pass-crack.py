# hashcat -m 10000 hash.txt words.txt 
from django.contrib.auth.hashers import check_password

target_hash = "pbkdf2_sha256$600000$w66tk98hCiqCBHakQRQvoL$pPjuJfwHdHqgoNS2vijx599idFGYFwj1tz4xz7BKuNQ="

wordlist = [
    "password", "admin", "secret", "flag", "ctf",
    "test", "root", "password123", "admin123",
    "hacker", "security", "hack", "capture",
    "downwithhackerz", "hacktheplanet", "vulnerable",
    "crackme", "challenge", "solve", "winner", "palestine4ever", "hello"
]

print("Starting password check...")
for word in wordlist:
    attempts = [word]

    for attempt in attempts:
        result = check_password(attempt, target_hash)
        print(f"Trying: {attempt}")
        if result:
            print(f"\n🎉 SUCCESS! Password found: {attempt}")
            break

    if result:
        break
else:
    print("\n❌ No password found")