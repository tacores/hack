# Linux フォレンジック

https://tryhackme.com/room/linuxfilesystemanalysis

## 安全なバイナリを使うことを検討

侵害されたマシンでは、バイナリが安全ではない可能性がある。  
クリーンなインストールから、/bin、/sbin、/lib、/lib64 をコピーし、侵害されたシステムの/mnt/usb にマウントしたとする。

```sh
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```

## OS 情報

ディストリビューションの種類にもよる

```shell
cat /etc/os-release

cat /etc/passwd | column -t -s :

cat /etc/group

sudo cat /etc/sudoers

# ログイン、ログアウト履歴
sudo last -f /var/log/wtmp

# 認証関連のログ（SSHログイン試行、sudo使用履歴、認証エラーなど）
cat /var/log/auth.log | tail
```

## システム構成

```shell
cat /etc/hostname

cat /etc/timezone

cat /etc/network/interfaces

ip address show

netstat -natp

ps aux

cat /etc/hosts

cat /etc/resolv.conf

# パッケージの変更をチェック
sudo debsums -e -s
```

## ユーザー、グループ

```shell
# UID 0 のユーザー
cat /etc/passwd | cut -d: -f1,3 | grep ':0$'

# 特定ユーザーのグループ
groups investigator

# 特定グループに属するユーザー
getent group adm

# sudo グループ内の全てのユーザー
getent group 27

# sudoers
sudo cat /etc/sudoers
```

## ログインアクティビティ

```shell
# ログインアクティビティ
last

# 失敗したログインアクティビティ
lastb

# 各ユーザーの最新ログインアクティビティ
lastlog

# 現在ログインしているユーザー
who
```

## タイムスタンプ

```shell
# 内容が変更された
ls -l /var/www/html/assets/reverse.elf

# メタデータが変更された（権限、所有権、ファイル名など）
ls -lc /var/www/html/assets/reverse.elf

# 最後にアクセスされた
ls -lu /var/www/html/assets/reverse.elf

# すべて出力される
stat /var/www/html/assets/reverse.elf
```

## 永続メカニズム

```shell
cat /etc/crontab
crontab -l

ls /etc/init.d/
systemctl status <pid>

cat ~/.bashrc
cat /etc/bash.bashrc
cat /etc/profile

cat /etc/sudoers
ls -al /root/.ssh

# nobody ユーザーが root グループに入っていたりしないか？
id nobody

cat -al /home/xxx/.ssh/authorized_keys

# 実行可能ファイル
find / -type f -executable 2> /dev/null

# 固定のパスワードで認証されるよう細工されている可能性
stat `locate pam_unix.so

# apache に nc で接続し、get root でシェルをとるモジュール
stat /usr/lib/apache2/modules/mod_rootme.so
```

## 実行の証拠

```shell
# sudo実行履歴
cat /var/log/auth.log* |grep -i COMMAND|tail

cat ~/.bash_history

cat ~/.viminfo
```

### audit

実行

```sh
ausearch -i -x whoami

ausearch -i --pid 3905

# 指定プロセスの子プロセスを全て表示
ausearch -i --ppid 577
```

永続化

```sh
ausearch -i -f /etc/crontab
ausearch -i -x crontab

ausearch -i -f /etc/systemd
ausearch -i -f /lib/systemd

find /etc/systemd/system /lib/systemd/system -type f -name '*.service' -printf '%TY-%Tm-%Td %TT %p\n' | sort -r

find /etc/systemd/system -type f -name '*.conf' -exec ls -lh --time-style=long-iso {} +
```

紛らわしい名前の場合は見ても分からないので、`ls /etc/systemd` の結果をChatGPTに見せて不審なものがないか確認するとよい。

## ログファイル

```shell
cat /var/log/syslog* | head

cat /var/log/auth.log* |head

# 時刻フィルタ
sudo awk '/2024-06-04 15:30:00/,/2024-06-05 15:29:59/' /var/log/auth.log

# 相対時間フィルタ
sudo grep "$(date --date='2 hours ago' '+%b %e %H:')" /var/log/auth.log

# 失敗したログイン
last /var/log/btmp

# systemd（サービス）関連
sudo journalctl -S "2024-02-06 15:30:00" -U "2024-02-17 15:29:59"
sudo journalctl -S "2 hours ago"
sudo journalctl -u nginx.service
sudo journalctl -p crit 

ls /var/log
```

## ルートキット

### ChkRootkit

https://www.chkrootkit.org/

ファイルシステム内のルートキットを検査するために使用される、人気の Unix ベースのユーティリティ

```shell
sudo chkrootkit
```

### RKHunter

https://rkhunter.sourceforge.net/

chkrootkit と比較して、より包括的で機能豊富なルートキット検出チェックを提供する。

```shell
# DBの更新
rkhunter --update

sudo rkhunter -c -sk
```
