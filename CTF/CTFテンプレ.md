# <name> CTF

<URL>

## Enumeration

### ポートスキャン

```shell
TARGET=<ip>
sudo nmap -sS -p- $TARGET
sudo nmap -sV -p80 $TARGET

sudo nmap -sV -p- --script vuln $TARGET
```

### gobuster

```shell
# attack box
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

# kali
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
```

```shell
gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k
```

何も出ない場合、

- hosts に名前を追加
- dirb http://<ip>

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
stty rows 54
stty cols 235
```
