# Yara

https://tryhackme.com/room/yara

https://tryhackme.com/room/threathuntingwithyara

## 基本

ルール（文法）  
https://yara.readthedocs.io/en/stable/writingrules.html

```shell
yara <rule-file>.yar <target>
```

### Valhalla

何千もの手作りの高品質 YARA ルール  
https://www.nextron-systems.com/valhalla/

## Yara を使用するツール

### Loki

オープンソースの IOC スキャナ

https://github.com/Neo23x0/Loki/blob/master/README.md

### THOR

企業顧客向け IOC スキャナ

https://www.nextron-systems.com/thor-lite/

### Fenrir

Bash スクリプトの IOC スキャナ

https://github.com/Neo23x0/Fenrir

### Yaya

Linux のみ

https://www.eff.org/deeplinks/2020/09/introducing-yaya-new-threat-hunting-tool-eff-threat-lab

## Loki

```shell
# help
python loki.py -h

# ルールをupdate
python loki.py --update

# path 指定してスキャン
python loki.py -p .
```

## yarGen

https://github.com/Neo23x0/yarGen

```shell
# good-opcodes および good-strings DB 更新
python3 yarGen.py --update

# Yaraルールを生成
# 一般的には、Yara ルールを調べて、誤検知が発生する可能性があると思われる文字列を削除
python3 yarGen.py -m /home/cmnatic/suspicious-files/file2 --excludegood -o /home/cmnatic/suspicious-files/file2.yar
```

### yarAnalyzer

https://github.com/Neo23x0/yarAnalyzer/
