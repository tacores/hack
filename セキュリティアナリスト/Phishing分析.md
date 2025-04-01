# Phishing 分析

## オンラインツール

### メール分析

いずれも、電子メールのヘッダー全体を貼り付ける

https://toolbox.googleapps.com/apps/messageheader/analyzeheader

https://mha.azurewebsites.net/

https://mailheader.org/

URL も抽出してくれる  
https://www.convertcsv.com/url-extractor.htm

CyberChef にも URL 抽出機能がある  
https://gchq.github.io/CyberChef/

### IP アドレス情報

https://ipinfo.io/

### URLScan

URL を入れると、スキャンしてくれる。  
https://urlscan.io/

### 添付ファイルのハッシュ調査

https://talosintelligence.com/talos_file_reputation

https://www.virustotal.com/gui/home/upload

### マルウェアサンドボックス

https://app.any.run/

https://www.hybrid-analysis.com/

https://www.joesecurity.org/

## オフラインツール

### PhishTool

無料でダウンロードできるコミュティエディションもある。  
https://www.phishtool.com/

## 防止技術

https://tryhackme.com/room/phishingemails4gkxh

### SPF (送信者ポリシーフレームワーク)

送信者ポリシーフレームワーク ( SPF ) は、電子メールの送信者を認証するために使用される。SPF レコードを設定すると、インターネット サービス プロバイダーは、メール サーバーが特定のドメインに電子メールを送信する権限を持っていることを確認できる。SPF レコードは、ドメインに代わって電子メールを送信することが許可されている IP アドレスのリストを含む DNS TXT レコード。

SPF 構文の例

```
v=spf1 ip4:127.0.0.1 include:_spf.google.com -all
```

### DKIM (ドメインキー識別メール)

送信される電子メールの認証に使用される。SPF と同様に、DKIM は DMARC 調整に使用される電子メール認証のオープン スタンダード。DKIM レコードは DNS に存在するが、 SPF よりも少し複雑。 DKIM の利点は転送後も存続できること。そのため、 DKIM は SPF よりも優れており、電子メールを保護するための基盤となる。

例

```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTQIC7vZAHHZ7WVv/5x/qH1RAgMQI+y6Xtsn73rWOgeBQjHKbmIEIlgrebyWWFCXjmzIP0NYJrGehenmPWK5bF/TRDstbM8uVQCUWpoRAHzuhIxPSYW6k/w2+HdCECF2gnGmmw1cT6nHjfCyKGsM0On0HDvxP8I5YQIIlzNigP32n1hVnQP+UuInj0wLIdOBIWkHdnFewzGK2+qjF2wmEjx+vqHDnxdUTay5DfTGaqgA9AKjgXNjLEbKlEWvy0tj7UzQRHd24a5+2x/R4Pc7PF/y6OxAwYBZnEPO0sJwio4uqL9CYZcvaHGCLOIMwQmNTPMKGC9nt3PSjujfHUBX3wIDAQAB
```

### DMARC (ドメインベースのメッセージ認証、レポート、適合)

アライメントと呼ばれる概念を使用して、他の 2 つのオープン ソース標準である SPF (ドメインに代わってメールを送信する権限を持つサーバーの公開リスト) と DKIM (メールに関連付けられた改ざん防止ドメイン シール) の結果をメールの内容に結び付ける。まだ展開されていない場合は、ドメインに DMARC レコードを配置すると、必要に応じて SPF および DKIM 構成のトラブルシューティングを行うことができるフィードバックが得られる。

例

```
v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com
```

DMARC ステータスを確認できる（必然的に SPF と DKIM も）  
https://dmarcian.com/domain-checker/

### S/MIME (Secure/Multipurpose Internet Mail Extensions)

デジタル署名および暗号化されたメッセージを送信するための、広く受け入れられているプロトコル
