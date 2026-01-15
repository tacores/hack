# keepass

## ハッシュ抽出

### keepass2john

```sh
keepass2john foo.kdbx > hash.txt
```

### john-jumbo

KDBX 4.x 形式 (Keepass >=2.36) は keepass2john で現状（2026年1月時点）サポートされていない。

```sh
File version '40000' is currently not supported!
```

john-jumbo をインストールすることで扱えるようになる。

https://github.com/TurboLabIt/cybersec/blob/main/script/john-the-ripper/install.sh

## 表示

### [KeePassXC](https://github.com/keepassxreboot/)

画像などのバイナリが含まれている場合もあるので、可能な限りファイル自体をコピーしてGUIで開く方が良い。

```sh
# flatpak のインストール
sudo apt install -y flatpak
sudo flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

# KeePassXC のインストール
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo

flatpak install --user flathub org.keepassxc.KeePassXC
```

```sh
# GUIアプリ起動
/home/kali/.local/share/flatpak/app/org.keepassxc.KeePassXC/x86_64/stable/active/export/share/applications/org.keepassxc.KeePassXC.desktop
```

### command

例

```sh
keepassxc-cli open ./dataset.kdbx
Enter password to unlock ./dataset.kdbx:

dataset.kdbx> ls
user:password

dataset.kdbx> show user:password
Title: user:password
UserName: sysadmin
Password: PROTECTED
URL:
Notes:
Uuid: {c116cbb5-f7c3-9a74-04c2-75019b28cc51}
Tags:

dataset.kdbx> show --show-protected user:password
```
