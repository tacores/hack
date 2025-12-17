# <name> CTF

<URL>

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

nmap -v -p- -Pn --min-rate 10000 $TARGET
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
# 指定可能なオプションは、nikto -h
nikto -p 80 -T 1 2 3 -h $TARGET
```

### サブドメイン、VHOST

2万、11万のリストもある。
```shell
ffuf -u http://example.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.example.thm' -fs 0
```

```sh
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 64 -k
```

### ディレクトリ列挙

```sh
dirb http://$TARGET
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
サービス LFI SSRF XSS SQLインジェクション 競合 フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD セッションID AVバイパス UACバイパス AMSIバイパス

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
