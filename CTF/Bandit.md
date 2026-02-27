# Bandit CTF

https://tryhackme.com/room/bandit

ネットワーク構成

```
WIN=10.200.30.10
UBUNTU=10.200.30.101
REGSRV=10.200.30.250
```

250 でユーザー登録が必要。

```
Username: register
Password: register
```

```sh
ssh register@$REGSRV

...

Thank you for registering, please take note of the following details. Your entry host for this challenge is 10.200.30.106.
Please add the challenge IP to your /etc/hosts resolving with the hostname bandit.escape 
Good luck

Thank you for using challenge registration, goodbye!
Connection to 10.200.30.250 closed.
```

```
ENTRY=10.200.30.106
sudo bash -c "echo $ENTRY   bandit.escape  >> /etc/hosts"
```

## ポートスキャン

エントリーポイントは反応が無い。

```sh
$ nmap -v -p- -Pn --min-rate 10000 $ENTRY
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-26 11:24 JST
Initiating SYN Stealth Scan at 11:24
Scanning bandit.escape (10.200.30.106) [65535 ports]
Completed SYN Stealth Scan at 11:24, 14.39s elapsed (65535 total ports)
Nmap scan report for bandit.escape (10.200.30.106)
Host is up (0.47s latency).
All 65535 scanned ports on bandit.escape (10.200.30.106) are in ignored states.
Not shown: 65520 filtered tcp ports (no-response), 15 filtered tcp ports (host-unreach)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.46 seconds
           Raw packets sent: 131059 (5.767MB) | Rcvd: 15 (1.080KB)
```

```sh
$ ping $ENTRY 
PING 10.200.30.106 (10.200.30.106) 56(84) bytes of data.
From 10.150.30.1 icmp_seq=1 Destination Host Unreachable
From 10.150.30.1 icmp_seq=2 Destination Host Unreachable
From 10.150.30.1 icmp_seq=3 Destination Host Unreachable
```

WIN

```sh
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49666/tcp open  unknown
```

UBUNTUはポートスキャンに反応しない。ただしpingは返る。

```sh
$ nmap -v -sS -p- $UBUNTU      
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-26 11:27 JST
Initiating Ping Scan at 11:27
Scanning 10.200.30.101 [4 ports]
Completed Ping Scan at 11:27, 3.04s elapsed (1 total hosts)
Nmap scan report for 10.200.30.101 [host down]
Read data files from: /usr/share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.13 seconds
           Raw packets sent: 8 (304B) | Rcvd: 0 (0B)
```

```sh
$ ping $UBUNTU
PING 10.200.30.101 (10.200.30.101) 56(84) bytes of data.
64 bytes from 10.200.30.101: icmp_seq=1 ttl=63 time=270 ms
64 bytes from 10.200.30.101: icmp_seq=2 ttl=63 time=270 ms
64 bytes from 10.200.30.101: icmp_seq=3 ttl=63 time=270 ms
```

エントリポイントのVMが起動されていない模様。

bug-report 投稿済。

# ルームのバグのため中断


## Enumeration

```shell
TARGET=<ip>
sudo bash -c "echo $TARGET   dockmagic.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET
```

```sh
sudo nmap -sV -p22,80 $TARGET
```

```sh
# windows
sudo nmap -vv -Pn -p- $TARGET
sudo nmap -sT -sC -p- $TARGET
```

```sh
sudo nmap -sS -oA ./nmap.txt --script safe -p80 $TARGET
sudo nmap -sV -p- --script vuln $TARGET
sudo nmap -sC $TARGET
```

```sh
# pingは通るが、下記のような感じで進まない場合
Scanning 10.65.134.175 [65535 ports]
SYN Stealth Scan Timing: About 2.26% done; ETC: 05:46 (0:22:21 remaining)
SYN Stealth Scan Timing: About 5.01% done; ETC: 05:45 (0:21:11 remaining)

nmap -v -p- -Pn --min-rate 10000 $ENTRY
```

```sh
# mysqlポートが開いている場合、ユーザー列挙できる場合がある
sudo nmap -sS -n -p3306 --script "mysql-enum" $TARGET
```

```sh
# リバースコールバック
# C2が稼働しているという設定で、ポートスキャンしたらTCP接続が来るパターンがある。
# VPN では機能せず、AttackBoxでは機能した。
sudo tcpdump -i tun0 port 81 -vv
```

```sh
# SNMPスキャン
onesixtyone $TARGET -c /usr/share/wordlists/SecLists/Discovery/SNMP/snmp-onesixtyone.txt 
```

```sh
# 指定可能なオプションは、nikto -h
nikto -p 80 -T 1 2 3 -h $TARGET
```

### SMB, NFS, LDAP

```sh
enum4linux -S $TARGET
enum4linux -R 1000-1003 $TARGET
enum4linux-ng -A $TARGET -oA results.txt
```

```sh
smbclient -L //$TARGET -U ""
smbclient -L //$TARGET -N
```

```sh
showmount -e $TARGET
```

ユーザー列挙

```sh
lookupsid.py foo.corp/guest@$TARGET
```

AD列挙.md 参照

```sh
ldapsearch -x -H ldap://$TARGET -s base
```

### サブドメイン、VHOST

2万、11万のリストもある。発見した後は、hosts の追加を忘れずに・・・。また、単純なスペルミスを防ぐためにコピペすること。

```shell
ffuf -u http://example.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.example.thm' -fs 0
```

```sh
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 64 -k
```

DNSがある場合

```sh
sudo dig axfr example.thm @$TARGET
```

### ディレクトリ列挙

```sh
dirb http://$TARGET
```

```sh
dirsearch -u http://$TARGET -e py,txt
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k
```

何も出ない場合、

- hosts に名前を追加
- HTTPS の場合、証明書にホスト名が表示されていないか確認
- dirb http://<ip>

フレームワークの場合はデフォルトパスワードを調べる。

## kerberos

```sh
~/tools/kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt

GetNPUsers.py -dc-ip $TARGET controller.local/ -usersfile users.txt

GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.194.124 -request
```

## 権限昇格

```sh
# env_keep+=LD_PRELOAD は見落としがちなので注意
sudo -l
```

```sh
find / -perm -u=s -type f -ls 2>/dev/null
```

```sh
find / -user <name> -type f -not -path "/proc/*" 2>/dev/null
find / -group <group> -type f -not -path "/proc/*" 2>/dev/null
```

```sh
getcap -r / 2>/dev/null
ls -al /var/backups
cat /etc/crontab
cat /etc/exports
```

どうしても何も見つからない場合の最後の手段として、linpeasのCVEリストに有効なものがないか確認する。

## 振り返り

-
-

## Tags

#tags: #tags: #tags:

```sh
# 大分類（Linuxはタグ付けしない）
Window Kerberos pwn pwn(Windows) Crypto puzzle ウサギの穴 LLM

# 脆弱性の種類
CVE-xxxx-yyyyy カーネルエクスプロイト
ツール脆弱性 sudo脆弱性 PHP脆弱性 exiftool脆弱性 アプリケーション保存の認証情報

# 攻撃の種類
サービス LFI SSRF XSS SQLインジェクション 競合 認証バイパス フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD セッションID AVバイパス UACバイパス AMSIバイパス PaddingOracles

# ツールなど
docker fail2ban modbus ルートキット gdbserver jar joomla MQTT CAPTCHA git tmux john redis rsync pip potato ligolo-ng insmod pickle
```

## メモ

### シェル安定化

```shell
# python が無くても、python3 でいける場合もある
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236
```

### SSH

ユーザー名、パスワード（スペース区切り）ファイルを使ってSSHスキャンする

```sh
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 10.10.165.96; set USERPASS_FILE creds.txt; run; exit"
```

エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```
