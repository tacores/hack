# Sigma

https://github.com/SigmaHQ/sigma

https://tryhackme.com/room/sigma

https://github.com/SigmaHQ/sigma-specification

https://github.com/SigmaHQ/sigma/tree/master/rules

様々な SIEM バックエンドに適用可能な検知ルールを記述するためのオープンソースの汎用シグネチャ言語。  
Sigmaはエンジンではなく他のエンジン用に変換できるようにする仕様。

## Sigma 構文

### YAML

Sigma ルールは YAML で記述される。

- YAML では大文字と小文字が区別される
- ファイルには .yml 拡張子が必要
- インデントにはタブではなくスペースが使用される
- コメントは#文字を使用して付与される
- キーと値のペアはコロン: 文字を使用して表される
- 配列要素はダッシュ- 文字を使用して示される

クイック YAML ガイド  
https://www.tutorialspoint.com/yaml/yaml_quick_guide.htm

### 構文

```yaml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  category: #Classification of the log data for detection
  product: #Source of the log data
detection:
  selection:
    FieldName1: Value #Search identifiers for the detection
    FieldName2: Value
  condition: selection #Action to be taken.
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
```

### 構文チェックコマンド

```sh
sigma check test-detection.yml
```

## 変換

### コマンド

```sh
sigma convert -t splunk -p splunk_cim first-detection.yml
sigma convert -t kusto -p microsoft_xdr first-detection.yml
sigma convert -t eql -p ecs_windows first-detection.yml
```

### オンラインサービス

Uncoder  
Sigma ルールを任意の SIEM ですぐに使用できるクエリに変換できる便利なツール  
https://uncoder.io/

UUID 生成  
https://www.uuidgenerator.net/

## 設定内容

https://tryhackme.com/room/sigmalanguage

### logsource

```yaml
logsource:
  category: process_creation
  product: windows
```

- category: ログイベントの種類。例: process_creation、network_connection、file_event、registry_event。
- product: ベンダーまたはプラットフォーム。例: windows、linux、aws、okta。
- service: 製品内の特定のサービス。例: sysmon、security、powershell。

### detection

```yaml
detection:
  selection_img:
    Image|endswith: '\whoami.exe'
    CommandLine|contains: '/all'
  condition: selection_img
```

`selection_img` の文字列は、自由に設定可能。`filter_admin`, `keywords` 等でも。  
例えば、接頭辞を統一することで、フィルターの一つに抵触したらアラート発報しないような設定が可能になる。

```yaml
condition: selection and not 1 of filter_*
```

#### [修飾子](https://sigmahq.io/docs/basics/modifiers.html)

デフォルトでは、シグマフィールドのマッチは完全一致。正規表現マッチなど、それ以外の処理を行うには、パイプ記号で修飾子を追加する必要がある。

```yaml
Image|endswith: '\whoami.exe'
CommandLine|contains: 'mimikatz'
TargetFilename|startswith: 'C:\Users\Public\'
ProcessName|re: '^[a-z]{8}\.exe$'
```

一般的な修飾子

- contains: フィールド内の任意の場所で部分文字列に一致する。
- startswith: フィールドの先頭と一致させる。
- endswith: フィールドの端に合わせる。
- re: 正規表現による一致。
- allリスト内のすべての値が一致する必要がある。

#### リスト表記

ORとして機能する。

```yaml
selection:
  Image|endswith:
    - '\whoami.exe'
    - '\net.exe'
```

all を付けると、AND として機能する。

```yaml
selection:
  CommandLine|contains|all:
    - 'powershell'
    - 'DownloadString'
    - 'http'
```

#### ワイルドカード

```yaml
selection:
  CommandLine: '*-EncodedCommand*'
```

#### condition

| 条件                               | 意味                                                 |
| -------------------------------- | -------------------------------------------------- |
| `selection`                      | `selection` が一致した場合にマッチする                          |
| `selection and not filter_admin` | `selection` に一致し、かつ `filter_admin` には一致しない場合にマッチする |
| `1 of selection_*`               | `selection_` で始まる条件のうち、少なくとも1つが一致した場合にマッチする        |
| `all of selection_*`             | `selection_` で始まるすべての条件が一致した場合にマッチする               |
| `all of them`                    | ルール内のすべての条件（selection）が一致した場合にマッチする                |

### トリアージとレスポンス

アラート自体には影響しないが、SIEMによっては画面上に情報表示される。

```yaml
falsepositives:
  - Legitimate administrator activity
  - IT scripts performing user enumeration
level: low
```

### 相関ルール

同じプロセスから2分以内にそのフォルダに50回以上のファイル書き込みイベントが発生

```yaml
correlation:
  type: event_count
  rules:
    - file_write_to_windows_temp   # the atomic rule's name
  group-by:
    - Image
  timespan: 2m
  condition:
    gte: 50
```

## 具体例

https://tryhackme.com/room/sighunt

### 1 イメージ、親イメージ、コマンドライン

```yaml
title: Suspicious MSHTA Execution from Chrome
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Detects mshta.exe launched by chrome.exe with specific command line
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    ParentImage|endswith: '\chrome.exe'
    Image|endswith: '\mshta.exe'
    CommandLine|contains: "hta"
  condition: selection
fields:
  - ParentImage
  - Image
  - CommandLine
falsepositives:
  - Unlikely, but user action might trigger it
level: high
```

### 2 Certutil ダウンロード

コマンドラインオプションを順不同にしているところがポイント

```yaml
title: Task2
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task2
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\certutil.exe'
    CommandLine|contains|all:
      - "certutil"
      - "-urlcache"
      - "-split"
      - "-f"
  condition: selection
fields:
  - EventID
  - Image
  - CommandLine
falsepositives:
  - Unlikely, but user action might trigger it
level: high
```

### 3 リバースシェル

-e オプションまたは MD5 ハッシュ

```yaml
title: Task3
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task3
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\nc.exe'
    CommandLine|contains|all:
      - " -e "
  selection2:
    Hashes|contains|all:
      - "MD5=523613A7B9DFA398CBD5EBD2DD0F4F38"
  condition: selection or selection2
fields:
  - EventID
  - Image
  - CommandLine
  - Hashes
falsepositives:
  - Unlikely, but user action might trigger it
level: high
```

### 4 Powershell ダウンロード

```yaml
title: Task3
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task3
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - "iex"
      - "new-object"
      - "net.webclient"
      - "downloadstring"
      - "Invoke-AllChecks"
      - "PowerUp"
  condition: selection
fields:
  - EventID
  - Image
  - CommandLine
falsepositives:
  - download
level: high
```

### 5 サービスバイナリ設定

```yaml
title: Task3
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task3
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\sc.exe'
    CommandLine|contains|all:
      - " config "
      - " -e "
      - "cmd.exe"
      - " binPath= "
  condition: selection
fields:
  - EventID
  - Image
  - CommandLine
falsepositives:
  - download
level: high
```

### 6 RunOnce レジストリ

```yaml
title: Task3
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task3
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\reg.exe'
    CommandLine|contains|all:
      - " add "
      - "RunOnce"
      - " REG_SZ "
  condition: selection
fields:
  - EventID
  - Image
  - CommandLine
falsepositives:
  - download
level: high
```

### 7 7z アーカイブ

```yaml
title: Task3
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task3
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\7z.exe'
    CommandLine|contains|all:
      - " a "
      - " * "
      - " -p"
  condition: selection
fields:
  - EventID
  - Image
  - CommandLine
falsepositives:
  - download
level: high
```

### 8 curl によるアップロード

```yaml
title: Task3
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task3
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith: '\curl.exe'
    CommandLine|contains|all:
      - " -d "
      - "@"
  condition: selection
fields:
  - EventID
  - Image
  - CommandLine
falsepositives:
  - download
level: high
```

### 9 ランサムウェア実行

TargetFilename の拡張子を参照している

```yaml
title: Task3
id: b58e3b3e-3b2b-4f36-9f64-cd6a1a4e1234
description: Task3
status: experimental
author: Your Name
logsource:
  service: sysmon
  product: windows
detection:
  selection:
    EventID: 11
    TargetFilename|endswith: "huntme"
  condition: selection
fields:
  - EventID
  - Image
  - TargetFilename
falsepositives:
  - download
level: high
```

## ルールリポジトリ

https://github.com/SigmaHQ/sigma/tree/master/rules
