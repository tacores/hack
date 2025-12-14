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

### 実行

-r は再帰, -s は一致した文字列を表示

```sh
yara -s -r <yara-file> <target>
```

## 構文

metaは必須ではないが強く推奨

```
rule TBFC_KingMalhare_Trace
{
    meta:
        author = "Defender of SOC-mas"
        description = "Detects traces of King Malhare’s malware"
        date = "2025-10-10"
    strings:
        $s1 = "rundll32.exe" fullword ascii
        $s2 = "msvcrt.dll" fullword wide
        $url1 = /http:\/\/.*malhare.*/ nocase
    condition:
        any of them
}
```

### 一致

文字列

```
rule TBFC_KingMalhare_Trace
{
    strings:
        $TBFC_string = "Christmas"

    condition:
        $TBFC_string 
}
```

大文字小文字を区別しない

```
strings:
    $xmas = "Christmas" nocase
```

ワイド文字列も対象

```
strings:
    $xmas = "Christmas" wide ascii
```

XORエンコードを対象

```
strings:
    $hidden = "Malhare" xor
```

Base64エンコードを対象

```
strings:
    $b64 = "SOC-mas" base64
```

バイト列

```
rule TBFC_Malhare_HexDetect
{
    strings:
        $mz = { 4D 5A 90 00 }   // MZ header of a Windows executable
        $hex_string = { E3 41 ?? C8 G? VB }

    condition:
        $mz and $hex_string
}
```

正規表現。範囲が広すぎるとスキャンが低速になるので注意。

```
rule TBFC_Malhare_RegexDetect
{
    strings:
        $url = /http:\/\/.*malhare.*/ nocase
        $cmd = /powershell.*-enc\s+[A-Za-z0-9+/=]+/ nocase

    condition:
        $url and $cmd
}
```

### 条件

単一の文字列

```
condition:
    $xmas
```

任意の文字列

```
condition:
    any of them
```

すべての文字列

```
condition:
    all of them
```

and、or、not

```
condition:
    ($s1 or $s2) and not $benign
```

ファイルサイズ、エントリポイント、ハッシュなど

```
condition:
    any of them and (filesize < 700KB)
```

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
