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
