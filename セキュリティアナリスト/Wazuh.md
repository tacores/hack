# Wazuh

https://tryhackme.com/room/wazuhct

https://tryhackme.com/room/customalertrulesinwazuh

https://wazuh.com/

Wazuh は、オープンソースで無料で使用できる EDR ソリューション。あらゆる規模の組織で利用でき、マネージャー＆エージェントモジュールで動作する。

## 設定

### エージェント

1. Web 画面で、WAZUH -> Agents を選択
1. Deploy new agent を選択
1. 必要項目を入力するとコマンドが生成されるので、それをログを収集するデバイスで実行する。

### 管理サーバー設定

構成ファイル

```
/var/ossec/etc/ossec.conf
```

- 脆弱性スキャナーモジュールを有効にする

## 監査、監視

### ポリシー監査

Wazuh -> Modules を押して「モジュール」タブに移動し、次のように「ポリシー管理」モジュールを開く。

### アラート

ログオン失敗の監視など。

保存ログ

```
/var/ossec/logs/alerts/alerts.log
```

#### アラートルール

Wazuh -> Management を 押して「管理」タブに移動し 、次のように「ルール」モジュールを開く。

### sysmon イベントの収集

エージェントの設定

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

```xml
<localfile>
<location>Microsoft-Windows-Sysmon/Operational</location>
<log_format>eventchannel</log_format>
</localfile>
```

管理サーバーの設定

```
/var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="sysmon,">
 <rule id="255000" level="12">
 <if_group>sysmon_event1</if_group>
 <field name="sysmon.image">\\powershell.exe||\\.ps1||\\.ps2</field>
 <description>Sysmon - Event 1: Bad exe: $(sysmon.image)</description>
 <group>sysmon_event1,powershell_execution,</group>
 </rule>
</group>
```

### Linux ログの集約

ログを分析する多くのルールが付属している

```
/var/ossec/ruleset/rules
```

ルールを挿入する設定ファイル

```
/var/ossec/etc/ossec.conf
```

```xml
<!-- Apache2 Log Analysis -->
<localfile>
    <location>/var/log/example.log</location>
    <log_format>syslog</log_format>
</localfile>
```

### Linux コマンドの監査

```shell
sudo apt-get install auditd audispd-plugins
sudo systemctl enable auditd.service
sudo systemctl start auditd.service
```

監査ルール

```
/etc/audit/rules.d/audit.rules
```

```
-a exit,always -F arch=64 -F euid=0 -S execve -k audit-wazuh-c
```

適用

```shell
sudo auditctl -R /etc/audit/rules.d/audit.rules
```

管理サーバーに送信するようエージェントを構成

```
/var/ossec/etc/ossec.conf
```

```xml
<localfile>
    <location>/var/log/audit/audit.log</location>
    <log_format>audit</log_format>
</localfile>
```

## API

トークン取得

```
TOKEN=$(curl -u : -k -X GET "https://WAZUH_MANAGEMENT_SERVER_IP:55000/security/user/authenticate?raw=true")
```

トークンの確認

```
curl -k -X GET "https://10.10.17.23:55000/" -H "Authorization: Bearer $TOKEN"
```

Wazuh -> Tools 「API コンソール」でコンソールを開ける。  
Web アプリケーション上で API をテストできる。

## レポート生成

Wazuh -> Modules 「セキュリティイベント」→「Generate Report」

その後しばらく待ってから、  
「 Wazuh 」見出しを押して「管理」を選択し、「ステータスとレポート」サブ見出しの下にある「レポート」テキストをクリック

## サンプルデータ

サンプルデータを使って練習できる。

「Wazuh」「設定」「サンプルデータ」の見出しを選択。
「データの追加」ボタンを押して、データをインポート。
