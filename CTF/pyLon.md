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

exiftool を実行すると、Base85が示唆されている。

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
lone@pylon:~/pylon$ git checkout cfc14d599b9b3cf24f909f66b5123ee0bbccc8da^C

lone@pylon:~/pylon$ ls
README.txt  banner.b64  pyLon.db  pyLon_crypt.py  pyLon_db.py  pyLon_pwMan.py
```

pylon.thm_gpg_key / lone_gpg_key が入っていた。これを使ってgpgで復号化しようとしたが、失敗。

```
40703ac897fd8cfdffc97947981e88a1
```

```
222 id_rsa
2_[-I2_[0E2DmEK

22 password
Username = lone
Password = +2BRkRuE!w7>ozQ4



```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA45nVhEtT37sKnNBWH2VYsXbjA8vAK8e04HfrgF06NiGGQsRBLtJw
YJu73+zGO0AoETo8LYhxB5eI5D9KzboGuTDAuGZQuUq+8N/hBmfavieHLHgkRNBr0ErJ60
l2FAcDW6pDowfiwC1vsdixQ6L8kvVhdkz0GUfPAlfIRhHHtQaQnQ7wnRtdGjIPK9/S1MPs
IJOLD2S79NxS7vguw87Mp0cnRjDalaCcRE0ELUvLDKQdZlWba0kF/PciqknkDYq2mbkCRd
3jWX2Umx0WtP2wCh9BQ/syxTJDXn6mCEsoNI/roLKyB1uGms/pFiBxS0qdiZAAO6CyTkyG
hZwb1BKmUwAAA8hSynq9Usp6vQAAAAdzc2gtcnNhAAABAQDjmdWES1Pfuwqc0FYfZVixdu
MDy8Arx7Tgd+uAXTo2IYZCxEEu0nBgm7vf7MY7QCgROjwtiHEHl4jkP0rNuga5MMC4ZlC5
Sr7w3+EGZ9q+J4cseCRE0GvQSsnrSXYUBwNbqkOjB+LALW+x2LFDovyS9WF2TPQZR88CV8
hGEce1BpCdDvCdG10aMg8r39LUw+wgk4sPZLv03FLu+C7DzsynRydGMNqVoJxETQQtS8sM
pB1mVZtrSQX89yKqSeQNiraZuQJF3eNZfZSbHRa0/bAKH0FD+zLFMkNefqYISyg0j+ugsr
IHW4aaz+kWIHFLSp2JkAA7oLJOTIaFnBvUEqZTAAAAAwEAAQAAAQB+u03U2EzfqzqBjtAl
szzrtBM8LdvXhOAGjT+ovkCHm6syyiyxcaP5Zz35tdG7dEHbNd4ETJEDdTFYRpXUb90GiU
sGYpJYWnJvlXmrI3D9qOzvqgYn+xXNaZd9V+5TwIPyKqB2yxFLiQFEujAaRUr2WYPnZ3oU
CZQO7eoqegQFm5FXLy0zl0elAkEiDrrpS5CNBunv297nHMLFBPIEB231MNbYMDe0SU40NQ
WAGELdiAQ9i7N/SMjAJYAV2MAjbbzp5uKDUNxb3An85rUWKHXslATDh25abIY0aGZHLP5x
4B1usmPPLxGTqX19Cm65tkw8ijM6AM9+y4TNj2i3GlQBAAAAgQDN+26ilDtKImrPBv+Akg
tjsKLL005RLPtKQAlnqYfRJP1xLKKz7ocYdulaYm0syosY+caIzAVcN6lnFoBrzTZ23uwy
VB0ZsRL/9crywFn9xAE9Svbn6CxGBYQVO6xVCp+GiIXQZHpY7CMVBdANh/EJmGfCJ/gGby
mut7uOWmfiJAAAAIEA9ak9av7YunWLnDp6ZyUfaRAocSPxt2Ez8+j6m+gwYst+v8cLJ2SJ
duq0tgz7za8wNrUN3gXAgDzg4VsBUKLS3i41h1DmgqUE5SWgHrhIJw9AL1fo4YumPUkB/0
S0QMUn16v4S/fnHgZY5KDKSl4hRre5byrsaVK0oluiKsouR4EAAACBAO0uA2IvlaUcSerC
0OMkML9kGZA7uA52HKR9ZE/B4HR9QQKN4sZ+gOPfiQcuKYaDrfmRCeLddrtIulqY4amVcR
nx3u2SBx9KM6uqA2w80UlqJb8BVyM4SscUoHdmbqc9Wx5f+nG5Ab8EPPq0FNPrzrBJP5m0
43kcLdLe8Jv/ETfTAAAAC3B5bG9uQHB5bG9uAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
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

## 振り返り

-
-

## Tags

#tags:ステガノグラフィー #tags:puzzle #tags:

```sh
# 大分類（Linuxはタグ付けしない）
Window Kerberos pwn pwn(Windows) Crypto puzzle ウサギの穴 LLM

# 脆弱性の種類
CVE-xxxx-yyyyy カーネルエクスプロイト
ツール脆弱性 sudo脆弱性 PHP脆弱性 exiftool脆弱性 アプリケーション保存の認証情報

# 攻撃の種類
サービス LFI SSRF XSS SQLインジェクション 競合 フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD

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
