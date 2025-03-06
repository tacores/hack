# Tips

## オンラインサービス

### URL 短縮サービス

- 短縮 URL の最後に+を付けることでどの URL に対応しているかプレビュー表示可能（Bitly、TinyURL 等）

## オフラインツール

### tshark

```shell
tshark --Y http.request -T fields -e http.host -e http.user_agent -r analysis_file.pcap
```

### ファジーハッシュ

ssdeep：ファイルの類似性を評価するツール  
https://ssdeep-project.github.io/ssdeep/index.html
