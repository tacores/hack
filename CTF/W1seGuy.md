# W1seGuy CTF

https://tryhackme.com/r/room/w1seguy

```text
The server is listening on port 1337 via TCP. You can connect to it using Netcat or any other tool you prefer.
```

添付されていたソースコード

```python
import random
import socketserver
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}'
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")

    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

## 静的解析

- flag1 は 5 桁以上の文字列
- キーは英数字 5 桁（大文字小文字）
- flag1 とキーの対応する文字の XOR を取った結果の文字列が出力される（flag1 の桁数と等しい）
- 正しいキーを入力したら flag2 が表示される。（flag.txt の中身）

flag = 'THM{thisisafakeflag}' はダミーだが、最初の 4 文字が'THM{'であるとすれば、キーの 5 文字中 4 文字は自動的に決まる。

```shell
$ nc 10.10.96.162 1337
This XOR encoded text has flag 1: 18241e36497d0d3f234d0914270c4d385830265a0d02217e5820202a256c3e182a7d4c3e141c3f44
What is the encryption key?
```

## キーの最初の 4 桁

最初の 4 桁を、'THM{'（0x54 0x48 0x4d 0x7b）と仮定する。

### 1 文字目

```text
flag[0] ^ key[0] -> 0x18
0x54 ^ key[0] -> 0x18

両辺に 0x54 の XOR をとると、
0 ^ key[0] = key[0] -> 0x54 ^ 0x18 = 0x4c(L)
```

### 2 文字目

```text
flag[1] ^ key[1] -> 0x24
0x48 ^ key[1] -> 0x24
key[1] -> 0x48 ^ 0x24 = 0x6c(l)
```

### 3 文字目

```text
flag[2] ^ key[2] -> 0x1e
0x4d ^ key[2] -> 0x1e
key[2] -> 0x4d ^ 0x1e = 0x53(S)
```

### 4 文字目

```text
flag[3] ^ key[3] -> 0x36
0x7b ^ key[3] -> 0x36
key[3] -> 0x7b ^ 0x36 = 0x4d(M)
```

キーの最初の 4 文字は、LlSM。

## ブルートフォース

キーの 5 文字目をブルートフォースし、「18241e36497d0d3f234d0914270c4d385830265a0d02217e5820202a256c3e182a7d4c3e141c3f44」を元に flag を復元・表示してみる。

```python
import string

xored = "18241e36497d0d3f234d0914270c4d385830265a0d02217e5820202a256c3e182a7d4c3e141c3f44"
int_list = [int(xored[i:i+2], 16) for i in range(0, len(xored), 2)]
key = "LlSM"

for c in (string.ascii_letters + string.digits):
    tmp_key = key + c
    flag = ""
    for i in range(0,len(int_list)):
        flag += chr(int_list[i] ^ ord(tmp_key[i % len(tmp_key)]))
    print(tmp_key)
    print(flag)
```

```shell
$ python ./py.py
LlSMa
rty0-rxOr%ExtA,t4ck;Anr39lLyh
LlSMb
THM{+1aln/ExtA/t4ck8Anr3:lLyhrty0.rxOr&
LlSMc
THM{*1aln.ExtA.t4ck9Anr3;lLyhrty0/rxOr'
LlSMd
THM{-1aln)ExtA)t4ck>Anr3<lLyrty0(rxOr
LlSMe
THM{,1aln(ExtA(t4ck?Anr3=lLyh   rty0)rxOr!
LlSMf
THM{/1aln+ExtA+t4ck<Anr3>lLyh
rty0*rxOr"
LlSMg
THM{.1aln*ExtA*t4ck=Anr3?lLyh
                             rty0+rxOr#
LlSMh
THM{!1aln%ExtA%t4ck2Anr30lLyhrty0$rxOr,
LlSMi
THM{ 1aln$ExtA$t4ck3Anr31lLyhrty0%rxOr-
LlSMj
THM{#1aln'ExtA't4ck0Anr32lLyhrty0&rxOr.
LlSMk
THM{"1aln&ExtA&t4ck1Anr33lLyhrty0'rxOr/
LlSMl
THM{%1aln!ExtA!t4ck6Anr34lLyhrty0 rxOr(
LlSMm
THM{$1aln ExtA t4ck7Anr35lLyhrty0!rxOr)
LlSMn
THM{'1aln#ExtA#t4ck4Anr36lLyhrty0"rxOr*
LlSMo
THM{&1aln"ExtA"t4ck5Anr37lLyhrty0#rxOr+
LlSMp
THM{91aln=ExtA=t4ck*Anr3(lLyhrty0<rxOr4
LlSMq
THM{81aln<ExtA<t4ck+Anr3)lLyhrty0=rxOr5
LlSMr
THM{;1aln?ExtA?t4ck(Anr3*lLyhrty0>rxOr6
LlSMs
THM{:1aln>ExtA>t4ck)Anr3+lLyhrty0?rxOr7
LlSMt
THM{=1aln9ExtA9t4ck.Anr3,lLyh▒rty08rxOr0
LlSMu
THM{<1aln8ExtA8t4ck/Anr3-lLyhrty09rxOr1
LlSMv
THM{?1aln;ExtA;t4ck,Anr3.lLyh▒rty0:rxOr2
LlSMw
THM{>1aln:ExtA:t4ck-Anr3/lLyhty0;rxOr3
LlSMx
THM{11aln5ExtA5t4ck"Anr3 lLyhrty04rxOr<
LlSMy
THM{01aln4ExtA4t4ck#Anr3!lLyhrty05rxOr=
LlSMz
THM{31aln7ExtA7t4ck Anr3"lLyhrty06rxOr>
LlSMA
THM1aln
       ExtA
rxOr       t4cknr3lLyh-rty0
LlSMB
THM{
    1alnExtAt4ck▒Anr3▒lLyh.rty0rxOr
LlSMC
THM{
1alnExtAt4ckAnr3Lyh/rty0rxOr
LlSMD
1aln    ExtA    t4ckAnr3lLyh(rtyrxOr
LlSME
THM{
    1alExtt4ckAnr3lLyh)rty0     rxOr
LlSMF
THM{1aln
        ExtA
            t4ckAnr3lLyh*rty0
rxOr
LlSMG
THM{1aln
ExtA
t4ckAnr3lLyh+rty0
                 rxOr
LlSMH
THM{1alnExtAt4ckAnr3lLyh$rty0rxOr

LlSMI
THM{1alnExtAt4ckAnr3lLyh%rty0rxOr
LlSMJ
THM{1alnExtAt4ckAnr3lLyh&rty0rxOr
LlSMK
THM{1alnExtAt4ckAnr3lLyh'rty0rxOr
LlSML
THM{1alnExtAt4ckAnr3lLyh rty0rxOr
LlSMM
THM{1alnExtAt4ckAnr3lLyh!rty0rxOr
LlSMN
THM{1alnExtAt4ckAnr3lLyh"rty0rxOr

LlSMO
THM{1alnExtAt4ckAnr3lLyh#rty0rxOr

LlSMP
THM{1alnExtAt4ck
AnrlLyh<rty0rxOr
LlSMQ
THM{▒1alnExtAt4ck
                 Anr3   lLyh=rty0rxOr
LlSMR
THM{alnExtAt4cAnr3
lLyh>rty0rxOr
LlSMS
THM{▒1alnExtAt4ck       Anr3
                            lLyh?rty0rxOr
LlSMT
THM{1alnExtAt4ckAnr3
                    lLyh8rty0▒rxOr
LlSMU
lLyh9rty0rxOr▒t4ckAnr3
LlSMV
THM{1aln
xtA4ck
      Anr3lLyh:rty0▒rxOr
LlSMW
Anr3lLyh;rty0xOrck
LlSMX
THM{1alnExtAt4ckAnr3lLyh4rty0rxOr
LlSMY
THM{1alnExtAt4ckAnr3lLyh5rty0rxOr
LlSMZ
THM{1alnExtAt4ckAnr3lLyh6rty0rxOr
LlSM0
THM{y1aln}ExtA}t4ckjAnr3hlLyh\rty0|rxOrt
LlSM1
THM{x1aln|ExtA|t4ckkAnr3ilLyh]rty0}rxOru
LlSM2
THM{{1alnExtAt4ckhAnr3jlLyh^rty0~rxOrv
LlSM3
THM{z1aln~ExtA~t4ckiAnr3klLyh_rty0rxOrw
LlSM4
THM{}1alnyExtAyt4cknAnr3llLyhXrty0xrxOrp
LlSM5
THM{|1alnxExtAxt4ckoAnr3mlLyhYrty0yrxOrq
LlSM6
THM{1aln{ExtA{t4cklAnr3nlLyhZrty0zrxOrr
LlSM7
THM{~1alnzExtAzt4ckmAnr3olLyh[rty0{rxOrs
LlSM8
THM{q1alnuExtAut4ckbAnr3`lLyhTrty0trxOr|
LlSM9
THM{p1alntEx....}
```

```text
LlSM9
THM{p1alntEx....}
```

これが正解だと思われる。

```shell
What is the encryption key? LlSM9
Congrats! That is the correct key! Here is flag 2: THM{BrUt3_For......}
```

フラグゲット！

## 振り返り

- 楽しい頭の体操
