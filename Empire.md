# Empire

https://tryhackme.com/room/rppsempire

オープンソースのC2ツール。

## install

https://bc-security.gitbook.io/empire-wiki/quickstart

### Empire

```sh
sudo apt install powershell-empire
```

### Starkiller (GUI)

現在はEmpire に取り込まれているため、別途インストールする必要はない。

### 起動

インストール後、再起動が必要だった。

```sh
sudo powershell-empire server
```

http://localhost:1337 でログイン画面が表示される。
認証情報は /etc/powershell-empire/server の下のconfファイルにある。

## フロー

1. ポート、プロトコルなどを設定してリスナーを作成
2. 形式、リスナーなどを指定してステージャーを作成
3. ステージャーをターゲットにダウンロードして実行
4. エージェントとして表示され、コマンド実行などが可能になる
