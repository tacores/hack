# Mindgames CTF

https://tryhackme.com/room/mindgames

## Enumeration

```shell
TARGET=10.201.99.237
sudo bash -c "echo $TARGET   mindgames.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 60
80/tcp open  http    syn-ack ttl 60
```

bf以外のAPIエンドポイントを探すが、bf以外見つからない。

```sh
root@ip-10-201-47-89:~# ffuf -u http://mindgames.thm/api/FUZZ -X POST -d "data" -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : http://mindgames.thm/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt
 :: Data             : data
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 404
________________________________________________

bf                      [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [475254/475254] :: Job [1/1] :: 10696 req/sec :: Duration: [0:00:58] :: Errors: 0 ::
```

全く分からない・・・

https://tryhackme.com/room/wonderland を先に完了することを強くお勧めするという記述を見かけたので、それに従って後回し。

## 権限昇格

## 振り返り

-
-

## シェル安定化メモ

```shell
# python が無くても、python3 でいける場合もある
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236

```
