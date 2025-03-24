# Splunk

## Tips

### 件数のカウント、ソートの例

```
index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests
```

### 表示する列を選択

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
```

### 正規表現ライクなフィルター

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd* | table _time uri src_ip dest_ip form_data
```

### 正規表現を使用した抽出

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table src_ip creds
```

form_data が `username=admin&passwd=batman&option=com_login&task=login` という内容であるとき、creds は `batman` になる。& が英数字アンダースコアに含まれないため。

### sysmon の EventID=1 （プロセス実行）

```
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
```
