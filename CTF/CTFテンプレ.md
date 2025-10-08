# <name> CTF

<URL>

## Enumeration

```shell
TARGET=<ip>
sudo bash -c "echo $TARGET   dockmagic.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET
```

```sh
rustscan -a -p22,80 $TARGET -- -sV
```

```shell
sudo nmap -sS -p- $TARGET
sudo nmap -sS -sV -p22,80 $TARGET
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
