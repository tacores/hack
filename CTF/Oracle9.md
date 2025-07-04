# Oracle 9 CTF

https://tryhackme.com/room/oracle9

## Enumeration

```shell
TARGET=10.10.50.65
sudo bash -c "echo $TARGET   oracle9.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

Open 10.10.50.65:22
Open 10.10.50.65:80
Open 10.10.50.65:5000
Open 10.10.50.65:11434
```

```shell
sudo nmap -sS -sV -p22,80,5000,11434 $TARGET

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Werkzeug/3.0.2 Python/3.10.12
5000/tcp  open  upnp?
11434/tcp open  unknown
```

チャットを入れるとmessageリクエストが送られた。

```http
POST /message HTTP/1.1
Host: 10.10.50.65
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.50.65/
Content-Type: multipart/form-data; boundary=---------------------------252318077134675133153494368866
Content-Length: 178
Origin: http://10.10.50.65
Connection: keep-alive
Priority: u=0

-----------------------------252318077134675133153494368866
Content-Disposition: form-data; name="msg"

hello'
-----------------------------252318077134675133153494368866--
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.0.2 Python/3.10.12
Date: Fri, 04 Jul 2025 00:38:13 GMT
Content-Type: text/plain; charset=utf-8
Connection: close
Content-Length: 64

A sealed transmission exists. Authorization required to proceed.
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/message              (Status: 405) [Size: 153]
Progress: 454380 / 454382 (100.00%)
===============================================================
```

既知のエンドポイントしか出なかった。

続きは後日。


## 権限昇格

## 振り返り

-
-

## シェル安定化メモ

```shell
# python が無くても、python3 でいける場合もある
python3 -c 'import pty; pty.spawn("/bin/bash")'
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
