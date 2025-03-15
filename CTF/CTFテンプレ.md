# <name> CTF

<URL>

## Enumeration

### ポートスキャン

```shell
TARGET=<ip>
sudo nmap -sS -p- $TARGET
sudo nmap -sV -p80 $TARGET
```

### gobuster

```shell
# attack box
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

# kali
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
```

```shell
gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30
```

何も出ない場合は、hosts に名前を追加することを検討。

## 権限昇格


## 振り返り

- 
- 
