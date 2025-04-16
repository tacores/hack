# Crypto Failures CTF

https://tryhackme.com/room/cryptofailures

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.75.207
root@ip-10-10-254-163:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-16 07:21 BST
Nmap scan report for 10.10.75.207
Host is up (0.0040s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:EA:AD:10:92:EB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.39 seconds
root@ip-10-10-254-163:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-16 07:22 BST
Nmap scan report for 10.10.75.207
Host is up (0.00014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
MAC Address: 02:EA:AD:10:92:EB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.30 seconds
```

SSH, HTTP のみ。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

/config.php           (Status: 200) [Size: 0]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/index.php            (Status: 302) [Size: 0]
/server-status        (Status: 403) [Size: 277]
```

config.php, index.php は存在する。

## Web ページ

```html
<p>
  You are logged in as
  guest:**********************************************************************
</p>
<p>
  SSO cookie is protected with traditional military grade en<b>crypt</b>ion
  <!-- TODO remember to remove .bak files-->
</p>
```

crypt が強調されているため、crypt 暗号を示唆していると思われる。

https://www.ibm.com/docs/ja/aix/7.2?topic=algorithm-traditional-password-crypt-function

### Cookie

```
user: guest

secure_cookie:
uztLH0kOX8OWwuzmBa1SoWosqcuzdM4Zmckvd.YuzEM1qVfcJFFIuzsjJ9AMoKOtAuzlNvzyNC04C.uzdSoUvEnsC8AuznBII31KW6A.uzR5th.Xx5bkcuznsJ4hidR1dguzViEuMU.cZpIuz%2F.jd97WTzuYuzvk7oQPCg7J6uz3FNy2WmxKWAuz2gVLaYqOmdQuzC6900U%2FmuQEuzR4ROIYsPohwuzLsalM4zPi5Iuzhb4JOsQmySkuzMZ%2FQt.OSCx2uz%2FN6UVii5%2FEcuzVENcx12QxosuzZJQ7SAPhGGwuzsOl.tvRrR6ouzbAcYz%2F7B7bwuzARQA6AUCsv.uzD0WsEID6P9kuzvGL5woSxgdYuzBh4s7fYPMS6
```

.bak ファイルを探す。

```shell
$ ffuf -u http://10.10.75.207/FUZZ.bak -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt -mc 200
```

上記のコマンドでは見つからなかったので手動で探した。  
把握しているファイルは`index.php`,`config.php`の 2 つ。index.php.bak が見つかった。

```php
<?php
include('config.php');

function generate_cookie($user,$ENC_SECRET_KEY) {
    $SALT=generatesalt(2);

    $secure_cookie_string = $user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $secure_cookie = make_secure_cookie($secure_cookie_string,$SALT);

    setcookie("secure_cookie",$secure_cookie,time()+3600,'/','',false);
    setcookie("user","$user",time()+3600,'/','',false);
}

function cryptstring($what,$SALT){

return crypt($what,$SALT);

}


function make_secure_cookie($text,$SALT) {

$secure_cookie='';

foreach ( str_split($text,8) as $el ) {
    $secure_cookie .= cryptstring($el,$SALT);
}

return($secure_cookie);
}


function generatesalt($n) {
$randomString='';
$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
for ($i = 0; $i < $n; $i++) {
    $index = rand(0, strlen($characters) - 1);
    $randomString .= $characters[$index];
}
return $randomString;
}



function verify_cookie($ENC_SECRET_KEY){


    $crypted_cookie=$_COOKIE['secure_cookie'];
    $user=$_COOKIE['user'];
    $string=$user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $salt=substr($_COOKIE['secure_cookie'],0,2);

    if(make_secure_cookie($string,$salt)===$crypted_cookie) {
        return true;
    } else {
        return false;
    }
}


if ( isset($_COOKIE['secure_cookie']) && isset($_COOKIE['user']))  {

    $user=$_COOKIE['user'];

    if (verify_cookie($ENC_SECRET_KEY)) {

    if ($user === "admin") {

        echo 'congrats: ******flag here******. Now I want the key.';

            } else {

        $length=strlen($_SERVER['HTTP_USER_AGENT']);
        print "<p>You are logged in as " . $user . ":" . str_repeat("*", $length) . "\n";
	    print "<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion\n";
    }

} else {

    print "<p>You are not logged in\n";


}

}
  else {

    generate_cookie('guest',$ENC_SECRET_KEY);

    header('Location: /');


}
?>
```

- secure_cookie の先頭 2 に文字が Salt
- [user]:[User-Agent]:[secret-key] を 8 文字ずつ区切って、それぞれ crypt 関数でハッシュ化している。
- 使用しているブラウザの User-Agent は`Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101`

今回の動作でいうと、Salt は uz であるため、先頭部分は下記のように暗号化される。

```php
<?php
$str1 = crypt("admin:Mo", "uz");
$str2 = crypt("guest:Mo", "uz");

print($str1 . "\n");
print($str2);
?>
```

```shell
$ php ./test1.php
uzjR4K6fQPM36
uztLH0kOX8OWw
```

Cookie を下記のように変更してページをリロード。  
（ユーザー名を admin に変更し、secure_cookie の先頭部分だけ変更）

```
user: admin

secure_cookie:
uzjR4K6fQPM36uzmBa1SoWosqcuzdM4Zmckvd.YuzEM1qVfcJFFIuzsjJ9AMoKOtAuzlNvzyNC04C.uzdSoUvEnsC8AuznBII31KW6A.uzR5th.Xx5bkcuznsJ4hidR1dguzViEuMU.cZpIuz%2F.jd97WTzuYuzvk7oQPCg7J6uz3FNy2WmxKWAuz2gVLaYqOmdQuzC6900U%2FmuQEuzR4ROIYsPohwuzLsalM4zPi5Iuzhb4JOsQmySkuzMZ%2FQt.OSCx2uz%2FN6UVii5%2FEcuzVENcx12QxosuzZJQ7SAPhGGwuzsOl.tvRrR6ouzbAcYz%2F7B7bwuzARQA6AUCsv.uzD0WsEID6P9kuzvGL5woSxgdYuzBh4s7fYPMS6
```

フラグ１をゲット。

```
congrats: THM{...............................}. Now I want the key.
```

## 秘密鍵

User-Agent が長くて扱いづらいので、`Firefox00`として secure_cookie を再生成してみる。

```
doFIEakByFNQUdoMB3f8tmsGO6do7zjWbdZYCHIdoICoArkFmlDMdoiig76.teAqgdo9JY9mh8RoyYdoh7RgQog%2F2Ucdoz7hgS6u6Khgdopzxn9xWl%2FRIdo2MxrWUgb9PMdoBBXOBiiz9McdoCKhu66JlhQYdoGwBFQUWqCuwdoondxzPNYWLodoaa8oIU2tBbQdoFz8i%2Ffy7GIwdo3Wx0FAybWRUdoULp4gZZy66.dowu%2Fh3YGysBkdo09MvYmXQXaAdoHqkIYWXQzO.doIHig7DmK%2Fe.
```

`doFIEakByFNQU`,`doMB3f8tmsGO6` を除いた下記の部分が、秘密鍵を 8 バイトで区切った部分をそれぞれハッシュ化した結果となる。

```
do7zjWbdZYCHI
doICoArkFmlDM
doiig76.teAqg
do9JY9mh8RoyY
doh7RgQog%2F2Uc
doz7hgS6u6Khg
dopzxn9xWl%2FRI
do2MxrWUgb9PM
doBBXOBiiz9Mc
doCKhu66JlhQY
doGwBFQUWqCuw
doondxzPNYWLo
doaa8oIU2tBbQ
doFz8i%2Ffy7GIw
do3Wx0FAybWRU
doULp4gZZy66.
dowu%2Fh3YGysBk
do09MvYmXQXaA
doHqkIYWXQzO.
doIHig7DmK%2Fe.
```

ハッシュ値から元の文字列を復元する方法があれば、復元してつなげるだけで良いのだが。

- crypt()はハッシュ関数なので、ソルト値とハッシュ値から元の文字列に戻すことは不可能
- PHP の crypt()関数の脆弱性情報も見つからない
- 8 桁ずつとしても、ざっと 50 の 8 乗と考えて、桁が大きすぎてブルートフォースは無理

User-Agent を`Firefox0`としたら、2 チャンク目の最後の 1 文字だけが変数となる。  
1 文字だけならブルートフォースで特定することは可能。

```
guest:Fi
refox0:[?]
```

以降、同様に User-Agent の文字列長を調整して 1 文字ずつ特定していくというのは理論的には可能と考えられる。

`Firefox0`

```
Sc77.O%2FtGjn3AScof9J%2FdbZLhwScj0Yu54wq0V2ScBIUmTZmlMO.Scj8GMDmdvlaQScHqFv0K.GLvYSc6MJ4HY6QiXgScO4Mx3QRU1%2FUScjKiIvurLqUEScVeSNESE512AScAgwwno3QQxQScRQQsClPErm2ScoKDwvRXlwuwScrgFIKe25UhEScw5sHkEloVRcScYkgt.lTX2gAScxub4ssz.4%2F.ScD1dwpoUx3tMScj%2F.WAauMQtISc6jc0XSRkpA.ScKKMxJxgzNoEScOqKkYatT98c
```

1 文字だけ特定するテストコード

```php
?php

$fixedString = "reFox0:";               // 固定文字列
$fixedHash = "Scof9J/dbZLhw";            // crypt("mySecretX", "my") などの結果
$salt = substr($fixedHash, 0, 2);      // DES形式のソルト（2文字）

// チェック対象の1文字：英大小・数字・記号（主要な記号）
$chars = array_merge(
    range('a', 'z'),
    range('A', 'Z'),
    range('0', '9'),
    str_split('!@#$%^&*()-_=+[]{};:,.<>?')
);

foreach ($chars as $char) {
    $testStr = $fixedString . $char;
    $hashed = crypt($testStr, $salt);

    if ($hashed === $fixedHash) {
        echo "match: $char\n";
        break;
    }
}
?>
```

```shell
$ php ./poc1.php
match: T
```

このように 1 文字ずつか、多くて 3 文字ずつ程度ならブルートフォースで特定可能。  
しかし、桁数が非常に多いので自動化が必須になる。

自動化のための部品として、User-Agent の長さを変えて 8 種類のハッシュを生成してみる。

`xx1234567`（秘密鍵ハッシュは第 3 チャンク 1 文字目から）

```
F3.hA3Qpjl4SAF3HLIWd3cRuLMF3SezBiXlyvt2F3v3O4tYuvfRwF3BwVwb6ZWZT.F30YQlGilaXGoF3OFPrOlCS06kF338KIzdATKRoF3qHl6y4zvX8YF3XQoF26i0RZ6F3fUFwbN5h2cMF3U5wpPoKkwUwF3Wz9b7ewQKRQF3VXkNeJAaKloF3hDbu6dU/pdUF371MS6bkCZe.F3IL/1qMJATXEF3INHw.8PT8twF3jda4PjKf0EMF3TxLFURPRH4.F3zzFTnphQnykF3qXv6vUGgV0A
```

`xx123456`（秘密鍵ハッシュは第 2 チャンク 8 文字目から）

```
Gms6d/bWHLChIGmUefYveqZO42GmZC5nzKSYDgoGmxR0zL7HxN2IGmRFUJSLveF.6Gm87l5k6CZK86GmzUn2/mRx.MAGmz.RK1DzNtK2GmlhRZsojeHEoGmbh7o.crs3/IGmRH3Rq/y/Z.sGmeToWW96ZAQUGmNIa6Vy/CjEMGmFVRpjgaDZQoGmZQojdaFgGlgGmk0jI0nGdWXEGmEi/dfEeQ5wgGmKgolFGrDF4wGmb/5bMwJWxEsGmbs2E7umfjiAGmXkt3Bg7GNi2Gmu6gRYzHz/1Y
```

`xx12345`

```
ZkTmTFbECk19kZkD380UlG7qa2ZkO7C0bW4TBBAZkP6dl9FCYIUMZku9YfgLvtxCgZk0GGXKQCTE/QZk2cErNfLgbqcZkdpL46/DMctQZkFQNlDU0TsEUZk5ChDaHMx8sMZkTGD4cJFPT0UZkUUHNwO6MvPcZk07hhl2/Sv2.Zk4lhu4ZT2uNUZklT6hi72x97gZkbS.mQrKeQWkZkcAXNmrOuKJMZkNTBhU5kP/kUZkbvIarYIklMIZkzRKGeZ1wsLsZk8k/Qj0ztzuY
```

`xx1234`

```
MqDPYPLFROz0IMqh2MJN/L/py.Mq66ECMoLSeOIMqFOX8/sTfPhcMq/Oc2xZAaqnsMqIFxos6FpurMMqVb6WynArEFUMqt0pHwAOpEKwMquZvBF8gXwyIMqmlog/QcxSqAMqfluW2eMo/igMqFoRDkU.8GzEMqyxkJdLA7GwoMqq6CDkEQQv/6MqW0J.yuRCBW2Mq16IpfngTV0sMqIopakyr8IWoMq6QzNu8RYZEwMqflZWjohUcmMMqXNJNH.gyMIYMqZqPmynug8kU
```

`xx123`

```
VUR0PJKlQNy3oVU2Uctkl0yoU2VU0avj3S6lJXcVUv.C8kqE0AEIVU0ID8zbeQUUYVU5lcIHTqI22QVUrRBnx07WTuMVUi161ZpQqOrgVUr5y/jFjNbPYVU1/LpU7sDUhYVUYJPyy/rP5.wVUDlhiK5c7qLoVUIOvJMdpwc0oVU0RPJLmWhMeMVUrO3VI5GVBPwVUBQSuB4JUiMcVUEgnqKAOfB1IVUIvTuSM7tagcVUvN4UIINuzZYVUaO/Fipgf32wVUj/M645mvuv.
```

`xx12`

```
j4ItMBqL.rsv2j4vojBmZZXjOkj4OuHcshvEYLQj4GDXb2hkD./Yj4Ejtcn/C4Xd2j47XA9YwdmAX.j4bogZ/eqemIYj4kFJVzZgWb4Qj4jeZzv2XNenQj4bym2DRfBVtYj4ROWLPsyoeqMj4NwYqFXsCowUj4Q8KIrjxfM3Aj41Pm1.HTEwc2j4luNsO1OBaMQj4Xq4S4pzW3Qwj49BQfO/J2OxMj4XJ3L7OVu8/Qj4/PRUydo2x0.j4iiDQfRm4zUQj4V3O87ZQEmZ.
```

`xx1`

```
mEQxaKE34yqromEDH/dOa8H5R2mEtFLqyuufXs6mEQxHHXuvsUSEmE7COnrFr.9rYmE.I/rqqFzshcmE5wZ7bDOiUcQmEfZPLx7E7ISwmEwsuLhx.k9mAmEk0lxF7h7nAEmEMbU39zMdDromEY74GDfaadqsmEvazkyswMCqAmESw6eg5NmQDMmEeO3MQcLhL5UmEK7HKOnzTJl6mESksT2iZZoIMmEMbnxrKxnJIomE52bV8MaciHImErN2Qij0R7YomEHqnWqLSNCTc
```

`xx`（秘密鍵ハッシュは第 2 チャンク 2 文字目から）

```
DURMZXUohXLZQDUs/cLZhdRTNYDUMqYuxElT.gsDU52.VpIdqAGgDU6zT9fZHqC.EDUgWHALHemFRgDUqPtuKv/ozuoDUpmGmvNBmvq2DUitgqtDs8/bcDUshAvz4wUhncDUSI2qWew7a8ADUoosBEDBWXIEDUMPJubOUnZs6DUoxphyR.fYKIDUKJhs3Uqyq/2DUSThW85QHrL6DU7wBni8O7S16DUsXRIDyGBYY6DUN2ok10.baCMDU6caaDEKBeosDUn71bLBIiK8g
```

### スクリプト

```php
<?php

$secure_cookies = array(
    "Gms6d/bWHLChIGmUefYveqZO42GmZC5nzKSYDgoGmxR0zL7HxN2IGmRFUJSLveF.6Gm87l5k6CZK86GmzUn2/mRx.MAGmz.RK1DzNtK2GmlhRZsojeHEoGmbh7o.crs3/IGmRH3Rq/y/Z.sGmeToWW96ZAQUGmNIa6Vy/CjEMGmFVRpjgaDZQoGmZQojdaFgGlgGmk0jI0nGdWXEGmEi/dfEeQ5wgGmKgolFGrDF4wGmb/5bMwJWxEsGmbs2E7umfjiAGmXkt3Bg7GNi2Gmu6gRYzHz/1Y",
    "ZkTmTFbECk19kZkD380UlG7qa2ZkO7C0bW4TBBAZkP6dl9FCYIUMZku9YfgLvtxCgZk0GGXKQCTE/QZk2cErNfLgbqcZkdpL46/DMctQZkFQNlDU0TsEUZk5ChDaHMx8sMZkTGD4cJFPT0UZkUUHNwO6MvPcZk07hhl2/Sv2.Zk4lhu4ZT2uNUZklT6hi72x97gZkbS.mQrKeQWkZkcAXNmrOuKJMZkNTBhU5kP/kUZkbvIarYIklMIZkzRKGeZ1wsLsZk8k/Qj0ztzuY",
    "MqDPYPLFROz0IMqh2MJN/L/py.Mq66ECMoLSeOIMqFOX8/sTfPhcMq/Oc2xZAaqnsMqIFxos6FpurMMqVb6WynArEFUMqt0pHwAOpEKwMquZvBF8gXwyIMqmlog/QcxSqAMqfluW2eMo/igMqFoRDkU.8GzEMqyxkJdLA7GwoMqq6CDkEQQv/6MqW0J.yuRCBW2Mq16IpfngTV0sMqIopakyr8IWoMq6QzNu8RYZEwMqflZWjohUcmMMqXNJNH.gyMIYMqZqPmynug8kU",
    "VUR0PJKlQNy3oVU2Uctkl0yoU2VU0avj3S6lJXcVUv.C8kqE0AEIVU0ID8zbeQUUYVU5lcIHTqI22QVUrRBnx07WTuMVUi161ZpQqOrgVUr5y/jFjNbPYVU1/LpU7sDUhYVUYJPyy/rP5.wVUDlhiK5c7qLoVUIOvJMdpwc0oVU0RPJLmWhMeMVUrO3VI5GVBPwVUBQSuB4JUiMcVUEgnqKAOfB1IVUIvTuSM7tagcVUvN4UIINuzZYVUaO/Fipgf32wVUj/M645mvuv.",
    "j4ItMBqL.rsv2j4vojBmZZXjOkj4OuHcshvEYLQj4GDXb2hkD./Yj4Ejtcn/C4Xd2j47XA9YwdmAX.j4bogZ/eqemIYj4kFJVzZgWb4Qj4jeZzv2XNenQj4bym2DRfBVtYj4ROWLPsyoeqMj4NwYqFXsCowUj4Q8KIrjxfM3Aj41Pm1.HTEwc2j4luNsO1OBaMQj4Xq4S4pzW3Qwj49BQfO/J2OxMj4XJ3L7OVu8/Qj4/PRUydo2x0.j4iiDQfRm4zUQj4V3O87ZQEmZ.",
    "mEQxaKE34yqromEDH/dOa8H5R2mEtFLqyuufXs6mEQxHHXuvsUSEmE7COnrFr.9rYmE.I/rqqFzshcmE5wZ7bDOiUcQmEfZPLx7E7ISwmEwsuLhx.k9mAmEk0lxF7h7nAEmEMbU39zMdDromEY74GDfaadqsmEvazkyswMCqAmESw6eg5NmQDMmEeO3MQcLhL5UmEK7HKOnzTJl6mESksT2iZZoIMmEMbnxrKxnJIomE52bV8MaciHImErN2Qij0R7YomEHqnWqLSNCTc",
    "DURMZXUohXLZQDUs/cLZhdRTNYDUMqYuxElT.gsDU52.VpIdqAGgDU6zT9fZHqC.EDUgWHALHemFRgDUqPtuKv/ozuoDUpmGmvNBmvq2DUitgqtDs8/bcDUshAvz4wUhncDUSI2qWew7a8ADUoosBEDBWXIEDUMPJubOUnZs6DUoxphyR.fYKIDUKJhs3Uqyq/2DUSThW85QHrL6DU7wBni8O7S16DUsXRIDyGBYY6DUN2ok10.baCMDU6caaDEKBeosDUn71bLBIiK8g",
    "F3.hA3Qpjl4SAF3HLIWd3cRuLMF3SezBiXlyvt2F3v3O4tYuvfRwF3BwVwb6ZWZT.F30YQlGilaXGoF3OFPrOlCS06kF338KIzdATKRoF3qHl6y4zvX8YF3XQoF26i0RZ6F3fUFwbN5h2cMF3U5wpPoKkwUwF3Wz9b7ewQKRQF3VXkNeJAaKloF3hDbu6dU/pdUF371MS6bkCZe.F3IL/1qMJATXEF3INHw.8PT8twF3jda4PjKf0EMF3TxLFURPRH4.F3zzFTnphQnykF3qXv6vUGgV0A",
);

$user_agents = array (
    "123456",
    "12345",
    "1234",
    "123",
    "12",
    "1",
    "",
    "1234567",
);

function splitBySalt(string $input): array {
    if (strlen($input) < 2) return []; // 2文字未満なら処理しない

    $marker = substr($input, 0, 2);   // 最初の2文字をマーカーに
    $rest = substr($input, 2);        // 残りの部分
    $parts = explode($marker, $rest); // マーカーで分割

    $result = [];
    foreach ($parts as $part) {
        if ($part !== '') {
            $result[] = $marker . $part; // マーカーを戻して格納
        }
    }
    return $result;
}

# secure_cookieのリストを、8文字単位ごとのチャンクに分割して保持する
$allHashChunks = [];
foreach ($secure_cookies as $secure_cookie) {
    $allHashChunks[] = splitBySalt($secure_cookie);
}

$prefix = "guest:xx";
$secret_key = "";

$chars = array_merge(
    range('a', 'z'),
    range('A', 'Z'),
    range('0', '9'),
    str_split('!@#$%^&*()-_=+[]{};:,.<>?')
);

# 秘密鍵が } で終わる（かつそれ以外に出現しない）ことを前提としている
while (!str_ends_with($secret_key, "}")) {
    # 8で割った余りを基準にどのチャンクセットを使うか決める
    $index = strlen($secret_key) % 8;
    $whole_str = $prefix . $user_agents[$index] . ":" . $secret_key;
    #print("whole_str $whole_str\n");

    $chunks = str_split($whole_str, 8); // 8文字ずつ分割
    $lastChunk = end($chunks); // 最後の要素だけ使う
    #print("lastChunk $lastChunk\n");

    # 必ず最後の1文字だけ不明という形を作る
    assert(strlen($lastChunk) % 8 == 7);

    #print_r($allHashChunks);
    $fixedHash = $allHashChunks[$index][strlen($whole_str) / 8];
    #print("fixedhash $fixedHash\n");

    $salt = substr($secure_cookies[$index], 0, 2);
    foreach ($chars as $char) {
        $testStr = $lastChunk . $char;
        #print("$testStr, $salt\n");
        $hashed = crypt($testStr, $salt);

        if ($hashed === $fixedHash) {
            $secret_key = $secret_key . $char;
            break;
        }
    }
    echo "$secret_key\n";
}

?>
```

実行

```shell
$ php ./decrypt.php
T
TH
THM
THM{
THM{T
THM{Tr
THM{Tra
THM{Trad
THM{Tradi
THM{Tradit
THM{Traditi
THM{Traditio
THM{Tradition
THM{Traditiona
THM{Traditional
THM{Traditional_
THM{Traditional_O
THM{Traditional_Ow
THM{Traditional_Own
THM{Traditional_Own_
THM{Traditional_Own_C
THM{Traditional_Own_Cr
THM{Traditional_Own_Cry
THM{Traditional_Own_Cryp
THM{Traditional_Own_Crypt
THM{Traditional_Own_Crypto
（以下略）
```

完璧！

## 振り返り

- こんな全力で頭を使ってコーディングしたのは何年ぶりか。
- 楽しかった。
