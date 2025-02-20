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
gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30

gobuster dir -u http://$TARGET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -t 30

gobuster dir -x php,txt,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30

/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt


```

### whatweb

```shell
whatweb -v $TARGET

```

### nikto

```shell
nikto -h http://$TARGET
```
