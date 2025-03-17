# Gotta Catch'em All! CTF

https://tryhackme.com/room/pokemon

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.177.32
root@ip-10-10-150-190:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-17 07:22 GMT
Nmap scan report for 10.10.177.32
Host is up (0.034s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:5E:F2:29:8C:71 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 13.23 seconds
root@ip-10-10-150-190:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-17 07:23 GMT
Nmap scan report for 10.10.177.32
Host is up (0.00012s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:5E:F2:29:8C:71 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.46 seconds
```

SSH, HTTP

Web ページは Apache インストールページだが、下記コメントがある。

```html
<pokemon
  >:<hack_the_pokemon>
    <!--(Check console for extra surprise!)--></hack_the_pokemon
  ></pokemon
>
```

```js
<script type="text/javascript">
    const randomPokemon = [
        'Bulbasaur', 'Charmander', 'Squirtle',
        'Snorlax',
        'Zapdos',
        'Mew',
        'Charizard',
        'Grimer',
        'Metapod',
        'Magikarp'
    ];
    const original = randomPokemon.sort((pokemonName) => {
        const [aLast] = pokemonName.split(', ');
    });

    console.log(original);
</script>
```

ポケモンの英名のリスト。

### gobuster

```shell
# attack box
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

# kali
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
```

```shell
root@ip-10-10-150-190:~# gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.177.32
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

何も出ない。

## 質問

### Q1

```text
Find the Grass-Type Pokemon
*******{*********}
```

リストの中では Bulbasaur（フシギダネ）が草タイプ。  
文字数的に、下記の形と推測。

```
*******{Bulbasaur}
```

当てずっぽうで下記を入力したら正解だった。どういうこと？

```
pokemon{Bulbasaur}
```

### Q2

```text
Find the Water-Type Pokemon
**************{********}
```

リストのタイプで水タイプは、Squirtle（ゼニガメ）。  
しかし前半の文字数が Q1 と違うので、これ以上は当てずっぽうでは無理。

ポケモンのリストファイルを作り、gobuster

```shell
$ gobuster dir -x=txt,php -u http://pokemon.thm/ -w ./pokemon-list -t 30
```

何もでない。SSH

```shell
$ hydra -L ./pokemon-list -P ./pokemon-list 10.10.177.32 ssh -t 30
```

ヒットしない。

違った。HTML コメントの一つ上の行がユーザ名とパスワードを表していた。

## SSH

```shell
pokemon@root:~/Desktop$ pwd
/home/pokemon/Desktop
pokemon@root:~/Desktop$ unzip ./P0kEmOn.zip
Archive:  ./P0kEmOn.zip
   creating: P0kEmOn/
  inflating: P0kEmOn/grass-type.txt
pokemon@root:~/Desktop$ cat P0kEmOn/grass-type.txt
50 6f 4b 65 ..............................
```

これを hex2ascii 変換すると、Q1 の答えになる。  
https://www.rapidtables.com/convert/number/hex-to-ascii.html

```shell
pokemon@root:~$ ls -al Videos/Gotta/Catch/Them/ALL\!/
total 12
drwxrwxr-x 2 pokemon pokemon 4096 Jun 22  2020 .
drwxrwxr-x 3 pokemon pokemon 4096 Jun 22  2020 ..
-rw-r--r-- 1 pokemon root      78 Jun 22  2020 Could_this_be_what_Im_looking_for?.cplusplus
pokemon@root:~$ cat Videos/Gotta/Catch/Them/ALL\!/Could_this_be_what_Im_looking_for\?.cplusplus
# include <iostream>

int main() {
        std::cout << "ash : （ひみつ）"
        return 0;
}
```

下記のように、ash ユーザーが存在しているのでそのパスワードと思われる。

```shell
pokemon@root:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
pokemon:x:1000:1000:root,,,:/home/pokemon:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
ash:x:1001:1001::/home/ash:
```

ユーザー変更成功。

```shell
pokemon@root:~$ su ash
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bash: /home/ash/.bashrc: Permission denied
ash@root:/home/pokemon$
```

/home/ash にアクセスできないが、テキストファイルが 1 つある。

```shell
ash@root:/home$ ls -al
total 20
drwxr-xr-x  4 root    root    4096 Jun 22  2020 .
drwxr-xr-x 24 root    root    4096 Aug 11  2020 ..
drwx------  6 root    root    4096 Jun 24  2020 ash
drwxr-xr-x 19 pokemon pokemon 4096 Mar 17 03:21 pokemon
-rwx------  1 ash     root       8 Jun 22  2020 roots-pokemon.txt
```

```shell
ash@root:/home$ cat roots-pokemon.txt
........
```

これが Q4 の答えらしい。

```shell
ash@root:/home$ sudo -l
[sudo] password for ash:
Matching Defaults entries for ash on root:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ash may run the following commands on root:
    (ALL : ALL) ALL
```

無制限 sudo。

```shell
ash@root:/home$ sudo bash -p
root@root:/home#
```

root 昇格。

Web ディレクトリに水タイプがあるのを発見。

```shell
root@root:/root# ls /var/www/html
index.html  water-type.txt

root@root:/root# cat /var/www/html/water-type.txt
......................
```

この ROT14 が Q2 の答え。

fire-type でファイル検索。

```shell
root@root:/root# find / -type f -name "fire-type*" 2>/dev/null
/etc/why_am_i_here?/fire-type.txt
root@root:/root# cat /etc/why_am_i_here\?/fire-type.txt
.....................
```

これを Base64 デコードしたものが Q3 。

## 振り返り

- あまり勉強にはならないが、最初、Web のソースから認証情報を拾えなかったのでセンスを磨く必要があると感じた。
