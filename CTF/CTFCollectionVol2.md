# CTF collection Vol.2 CTF

https://tryhackme.com/room/ctfcollectionvol2

## Enumeration

```shell
TARGET=10.10.195.81
sudo bash -c "echo $TARGET   col2.thm >> /etc/hosts"
```

## 1 robots.txt

```
User-agent: * (I don't think this is entirely true, DesKel just wanna to play himself)
Disallow: /VlNCcElFSWdTQ0JKSUVZZ1dTQm5JR1VnYVNCQ0lGUWdTU0JFSUVrZ1p5QldJR2tnUWlCNklFa2dSaUJuSUdjZ1RTQjVJRUlnVHlCSklFY2dkeUJuSUZjZ1V5QkJJSG9nU1NCRklHOGdaeUJpSUVNZ1FpQnJJRWtnUlNCWklHY2dUeUJUSUVJZ2NDQkpJRVlnYXlCbklGY2dReUJDSUU4Z1NTQkhJSGNnUFElM0QlM0Q=


45 61 73 74 65 72 20 31 3a 20 54 48 4d 7b 34 75 37 30 62 30 37 5f 72 30 6c 6c 5f 30 75 37 7d
```

後半をFrom Hexする。前半のBase64は・・・？

## 2 Base64

1のBase64文字列を、CyberChefで Base64デコードと空白削除を繰り返すと`DesKel_secret_base`となる。

http://col2.thm/DesKel_secret_base/ にアクセス。HTMLソースコメントにフラグがある。

## 3 dirbuster

```sh
root@ip-10-10-234-26:~# dirb http://col2.thm                                            

---- Scanning URL: http://col2.thm/ ----
+ http://col2.thm/button (CODE:200|SIZE:39148)                                   
+ http://col2.thm/cat (CODE:200|SIZE:62048)                                      
+ http://col2.thm/cgi-bin/ (CODE:403|SIZE:284)                                   
+ http://col2.thm/index (CODE:200|SIZE:94328)                                    
+ http://col2.thm/index.php (CODE:200|SIZE:94328)                                
+ http://col2.thm/iphone (CODE:200|SIZE:19867)                                   
==> DIRECTORY: http://col2.thm/login/                                            
+ http://col2.thm/robots (CODE:200|SIZE:430)                                     
+ http://col2.thm/robots.txt (CODE:200|SIZE:430)                                 
+ http://col2.thm/server-status (CODE:403|SIZE:289)                              
+ http://col2.thm/small (CODE:200|SIZE:689)                                      
+ http://col2.thm/static (CODE:200|SIZE:253890)                                  
+ http://col2.thm/who (CODE:200|SIZE:3847428)                                    

---- Entering directory: http://col2.thm/login/ ----
+ http://col2.thm/login/index (CODE:200|SIZE:782)                                
+ http://col2.thm/login/index.php (CODE:200|SIZE:782) 
```

http://col2.thm/login/index.php のソースコードコメントにフラグ3。

## 4 sqli

```sh
# DB名を確認
$ sqlmap -r ./login.txt --dbs --batch

# DB全体をダンプ。フラグとログイン情報が出る。
$ sqlmap -r ./login.txt -D THM_f0und_m3 --dump-all --batch
```

## 5 login

4で取得した情報を使い、DesKelでログイン。

## 6 HTTP header

/index のHTTPレスポンスヘッダーにフラグが出ていた。

## 7 Cookie

Cookieの invited を 1 にしてページ更新。

## 8 User-Agent

BurpでインターセプトしてUser-Agentを差し替え。

`Mozilla/5.0 (iPhone; CPU iPhone OS 13_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.1 Mobile/15E148 Safari/604.1`

## 9

Click Here ボタンを押したとき、きのこ雲が表示される前に別の画面が一瞬表示されてからリダイレクトされる。そのとき表示される画面のHTMLソースにフラグがある。

## 10 Referer

GET /free_sub/ で、Refererを書き換える。

```
Referer: tryhackme.com
```

## 11 dinner

salad で送信すると「eggが好きだ」と表示されるので、Burpでインターセプトして egg に書き換えたらフラグが返る。

## 12 js

jquery-9.1.2.js の関数をコンソールで実行。

## 13 Button

/index の Click Here ボタン画像を押す。

## 14 PNG

/index のHTMLソースコメント。Base64デコードしてPNG保存したらフラグになる。

```
<!--Easter 14<img src="data:image/png;base64,iVBORw0KGgoAA[以下略]"/> --> 
```

## 15 game1

アルファベットに対して独自のエンコードがされている。

`abcdefghijklmnopqrstuvwxyz` -> `89 90 91 92 93 94 95 41 42 43 75 76 77 78 79 80 81 10 11 12 13 14 15 16 17 18`

`ABCDEFGHIJKLMNOPQRSTUVWXYZ` -> `99 100 101 102 103 104 51 52 53 54 55 56 57 58 126 127 128 129 130 131 136 137 138 139 140 141`

`51 89 77 93 126 14 93 10` -> `[REDACTED]`

## 16 game2

POSTリクエストを操作して同時に送る。  
`button1=button1&button2=button2&button3=button3&submit=submit`

## 17 Binary

Mulfunction buttonボタンを押すと0と1の文字列が表示される。

```
100010101100001011100110111010001100101011100100010000000110001001101110011101000100000010101000100100001001101011110110110101000110101010111110110101000110101010111110110101100110011011100000101111101100100001100110110001100110000011001000011001101111101
```

255文字なので、桁数を256にするために先頭に0を追加し、CyberChefで From Binaryしたらフラグになる。

## 18 Request Header

HTTP GETリクエストヘッダーに`Egg: Yes`を追加するとフラグが返る。

## 19 small

http://col2.thm/small でフラグ画像が表示される。

## 20 POST

POSTで下記を送ったらフラグが返る。

```
username=DesKel&password=heIsDumb&submit=submit
```

## 振り返り

- 適切なヒントが提供されていて理不尽に感じるところはなく楽しかった。
