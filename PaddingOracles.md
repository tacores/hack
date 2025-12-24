# Padding Oracles

https://tryhackme.com/room/paddingoracles

サーバーが暗号文内のパディングが有効かどうかのフィードバックを提供することで「オラクル」として機能することから、こう名付けられた。

## パディングスキーム

パディングとは、暗号化において、平文データがAESなどのブロック暗号で要求される固定ブロックサイズに収まるようにするための処理。平文がブロックサイズの倍数（例えばAESの場合は16バイト）でない場合、最後のブロックの残りのスペースを埋めるために余分なバイトが追加される。

暗号化には、PKCS#7、ANSI X.923、ISO/IEC 7816-4など、複数のパディング方式が存在する。ブロック暗号で最も一般的に使用されているのは、PKCS#7パディング方式。

### PKCS#7 パディングスキーム

平文がブロックサイズの倍数でない場合、PKCS#7はパディングバイトを追加する。各バイトの値は、追加されるパディングバイトの数に等しくなる。平文が既にブロックサイズと一致している場合は、ブロックサイズと同じ値を持つバイトを含むパディングブロックが追加される。

（８バイトブロックの場合）  
テキストが０バイトの場合、８バイト追加され、各バイトの値は0x08になる。  
テキストが７バイトの場合、１バイト追加され、各バイトの値は0x01になる。  

```python
# python
Crypto.Util.Padding.pad(data_to_pad, block_size, style='pkcs7')
```

## ブロック暗号モード

### 動作モード

- 電子コードブック（ECB）：最も基本的なモードであり、各平文ブロックを独立して暗号化する。ただし、この独立性により、同一の平文ブロックは同一の暗号文ブロックとなるため、データのパターンが明らかになってしまう。このため、ほとんどのアプリケーションにおいてECBは安全ではない。
- 暗号ブロック連鎖（CBC）：CBCモードでは、各平文ブロックを暗号化する前に、前の暗号文ブロックと排他的論理和（XOR）を取る。最初のブロックには、ランダム性を導入するために初期化ベクトル（IV）とのXORを使用する。この連鎖処理により、たとえ同一の平文ブロックであっても、シーケンス内の位置やIVが異なれば、異なる暗号文となる。
- カウンター（CTR）モード：CTRモードでは、ブロックを連鎖させず、代わりにカウンター値とブロックインデックスを組み合わせて使用する。各ブロックを独立して暗号化するが、異なるナンスとカウンターのペアを使用することで、セキュリティと効率性を両立する。

### Cipher Block Chaining（CBC）暗号化

1. 平文をブロックに分割し、パディングを追加する
1. 最初のブロックとランダムなIVをXORする
1. XOR結果を暗号化する（AESまたはDESアルゴリズムと、秘密鍵を使用する）
1. 1番目の暗号化ブロックと、2番目の平文ブロックをXORする
1. XOR結果を暗号化する（同じ秘密鍵を使用する）
1. 暗号化ブロックを結合したものが最終的な暗号文になる（復号にはIVも必要なため、通常は暗号文の先頭にIVを付けて送る）

```python
from Crypto.Cipher import AES

plaintext_bytes = pad(plaintext.encode(), block_size)
cipher = AES.new(key.encode(), AES.MODE_CBC, DEFAULT_IV)
encrypted_bytes = cipher.encrypt(plaintext_bytes)
encrypted_message = binascii.hexlify(encrypted_bytes).decode()
```

### CBC 復号化

1. 暗号文とIVを入力し、暗号文をブロックに分割する
1. 最初のブロックを、秘密鍵を使って復号する
1. 復号文とIVをXORする（これが最初の平文ブロックになる）
1. 2番目のブロックを、秘密鍵を使って復号する。
1. 復号文と最初の暗号化ブロックをXORする（これが2番目の平文ブロックになる）
1. 3番目以降は2番目のブロックと同じ
1. 暗号化ブロックを結合したものからパディングを削除し、最終的な平文になる

```python
ciphertext_bytes = binascii.unhexlify(ciphertext)
cipher = AES.new(key.encode(), AES.MODE_CBC, DEFAULT_IV)
decrypted_bytes = cipher.decrypt(ciphertext_bytes)
decrypted_message = unpad(decrypted_bytes, DEFAULT_BLOCK_SIZE).decode()
```

## 攻撃

復号の数式
$$ P_i = (D_k(C_i)) XOR (C_{i-1}) $$

パディングオラクル攻撃は、パディングが有効かどうかを明らかにするオラクルと対話することで、中間復号状態
$$ D_k(C_i) $$
をバイトごとに徐々に明らかにしていく。

- Dk(n): IVとXORされていない状態を中間復号状態（intermediary decryption state）
- test(n): テストするためのIVを修正IV（modified IV）  
と表現する。

### ステップ

暗号文の最後のバイトから逆順に処理する。全体が16バイトの暗号文を考える。

1. test(16)をブルートフォースし、有効なパディングを見つける。有効かどうかをサーバーからの応答で判断する。
1. 有効なパディングであるとき、Dk(16) XOR test(16) = 0x01 となるはずである。  
Dk(16) = test(16) XOR 0x01 と変形でき、Dk(16)が判明した。
1. P(16) = Dk(16) XOR IV(16) と計算できる。
1. test(15)をブルートフォースし、有効なパディングを見つける。
1. 有効なパディングは 0x02 0x02 となるはずである。Dk(15) XOR test(15) = 0x02
1. P(15) = Dk(15) XOR IV(15) と計算できる。
1. 以降同様に繰り返し、全てのP(i)を計算できる。

## 自動ツール

```
PadBusterは1ブロック分だけしか復号表示されないので、padre 推奨。
また padre の方がかなり速い。
```

### PadBuster

https://github.com/AonCyberLabs/PadBuster

kaliの場合、padbuster と打てば、インストールするか聞かれる。

- http://10.10.170.95:5002/decrypt?ciphertext=暗号文 エンドポイントがあるとする。
- パディング不正の場合、"Invalid padding"　という文字列が含まれた応答を返すとする。

```shell
# -encoding 1 は小文字Hexという意味
# URLの中とパラメータと、暗号化文字列が2回含まれていることに注意
padbuster http://10.10.170.95:5002/decrypt?ciphertext=313233343536373839303132333435362cb8770371460c5a2dc6b6a7e65289b8 313233343536373839303132333435362cb8770371460c5a2dc6b6a7e65289b8 16 -encoding 1
```

### padre

https://github.com/glebarez/padre

※バイナリをコピーするだけで使えるのでそっちの方が楽。HEXは小文字にしてから `-e lhex` を指定する必要がある。

```shell
# インストール
go install github.com/glebarez/padre@latest
```

```shell
# 復号化
padre -cookie 'PHPSESSID=xxxxxxxxxxxxxxxxxx' -u 'http://decryptify.thm:1337/dashboard.php?date=$' '暗号文'

# 暗号化
padre -cookie 'PHPSESSID=xxxxxxxxxxxxxxxxxx' -u 'http://decryptify.thm:1337/dashboard.php?date=$' -enc '暗号化したい平文'
```


## 緩和策

- 認証された暗号化を使用する:暗号化と認証を組み合わせて暗号文の操作を防止するAES -GCM やAES -CCMなどの認証暗号化を使用する。
- エラー表示を避ける: 無効なパディングなどのエラーを本番環境で表示しない。
- 入力を安全に検証する：暗号文などの無効な入力をサーバー側で処理しない。例えば、無効な暗号文は復号せずにフィルタリング。 
- ライブラリを最新の状態に保つ: 古い実装による脆弱性を回避するために、最新の暗号化ライブラリを使用する。

