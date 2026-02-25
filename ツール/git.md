# git

各コミットで変更があったファイル名のみをリスト表示

```sh
git log --name-only --oneline
```

## GitTools

https://github.com/internetwache/GitTools

### Dumper

Webサイトで .git ディレクトリが公開状態にあるとき、ローカルにダンプする。

```sh
/home/kali/tools/GitTools/Dumper/gitdumper.sh http://pwd.harder.local/.git/ ./git
```

### Extractor

各コミットごとの断面をディレクトリに再構成する。

```sh
# カレントに .git ディレクトリがあるとする
/home/kali/tools/GitTools/Extractor/extractor.sh . Website
```

### Finder

インターネット上で.gitディレクトリが公開されているサイトを検索する。
