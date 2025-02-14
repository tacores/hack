# Linux システム強化

https://tryhackme.com/room/linuxsystemhardening

## 物理的セキュリティ

GRUB にパスワードを設定する

```shell
# パスワードハッシュ生成
grub2-mkpasswd-pbkdf2

# /etc/grub.d/40_custom 編集
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.<ハッシュ>

# 設定を反映
grub2-mkconfig -o /boot/grub2/grub.cfg
```

## ファイルシステムのパーティション分割と暗号化

### LUKS ( Linux Unified Key Setup)

```shell
# インストール
apt install cryptsetup

# パーティション名確認
sudo fdisk -l
sudo lsblk
sudo blkid

# 暗号化パーティション設定
sudo cryptsetup -y -v luksFormat /dev/sdb1

# パーティションにアクセスするためのマッピング作成
sudo cryptsetup luksOpen /dev/sdb1 EDCdrive

# マッピングの詳細確認
sudo ls -l /dev/mapper/EDCdrive
sudo cryptsetup -v status EDCdrive

# 既存のデータを0で上書き
sudo dd if=/dev/zero of=/dev/mapper/EDCdrive

# パーティションをフォーマット
sudo mkfs.ext4 /dev/mapper/EDCdrive -L "Strategos USB"

# マウント
sudo mount /dev/mapper/EDCdrive /media/secure-USB

# LUKS設定を確認
sudo cryptsetup luksDump /dev/sdb1
```

ファイルを myvault ディレクトリにマウントする例

```shell
sudo cryptsetup open --type luks secretvault.img myvault && sudo mount /dev/mapper/myvault myvault/
```

## ファイアウォール

### netfilter

#### iptables

```shell
# 以前のルールをフラッシュ（削除）
iptables -F

# SSH通信を許可する
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

# 以前のルールで許可されていない全てのトラフィックをブロック
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```

#### nftables

```shell
# fwfilterという名前のテーブルを作成
sudo nft add table fwfilter

# 入力チェーンと出力チェーンを追加
sudo nft add chain fwfilter fwinput { type filter hook input priority 0 \; }
sudo nft add chain fwfilter fwoutput { type filter hook output priority 0 \; }

# SSHトラフィックを許可
sudo nft add fwfilter fwinput tcp dport 22 accept
sudo nft add fwfilter fwoutput tcp sport 22 accept

# テーブルを確認
sudo nft list table fwfilter
```

#### UFW (Uncomplicated Firewall)

```shell
# SSHトラフィックを許可
sudo ufw allow 22/tcp

# 確認
sudo ufw status
```

## リモート接続

- root のリモート接続を無効にする
- パスワード認証を無効にし、公開鍵認証を強制する

```text
/etc/ssh/sshd_config
（ロックアウトされないように、物理端末にアクセスできることを確認してから変更を行う）

PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
```

```shell
# 鍵ペアを生成
ssh-keygen -t rsa

# 公開鍵をSSHサーバーにコピー
ssh-copy-id username@server
```

## ユーザーアカウント保護

- 管理用に sudo ユーザーを作る
- root ユーザーを /sbin/nologin 設定にする
- 使用されていないアカウントを /sbin/nologin 設定にする
- 強力なパスワードポリシー

```shell
# libpwquality
apt-get install libpam-pwquality

man pwquality.conf

/etc/security/pwquality.conf
or
/etc/pam.d/common-password
```

## ソフトウェアとサービス

- 不要なサービスを無効にする
- 不要なネットワークポートをブロック
- レガシープロトコルを避ける
- 識別文字列を削除（バージョンなど）

## 更新、アップグレードポリシー

### Ubuntu LTS の例

- 無料で 5 年間
- 有料でプラス 5 年間

### カーネルアップデート

Dirty COW のような root 昇格の脆弱性もある

### 自動更新

- セキュリティニュースの入手
- 最新テクノロジーより安定性を優先するディストリビューションの場合は、更新の自動化を検討

## 監査とログの構成

| ログファイル        | 説明                                                                              |
| ------------------- | --------------------------------------------------------------------------------- |
| `/var/log/messages` | Linux システムの一般的なログ                                                      |
| `/var/log/auth.log` | すべての認証試行をリストするログファイル (Debian ベースのシステム)                |
| `/var/log/secure`   | すべての認証試行をリストするログファイル (Red Hat および Fedora ベースのシステム) |
| `/var/log/utmp`     | 現在システムにログインしているユーザーに関する情報を含むアクセスログ              |
| `/var/log/wtmp`     | システムにログインおよびログアウトしたすべてのユーザーの情報を含むアクセスログ    |
| `/var/log/kern.log` | カーネルからのメッセージを含むログファイル                                        |
| `/var/log/boot.log` | 起動メッセージとブート情報を含むログファイル                                      |
