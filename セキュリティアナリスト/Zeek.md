# Zeek

https://tryhackme.com/room/zeekbro

https://docs.zeek.org/en/master/about.html

フレームワーク  
https://docs.zeek.org/en/master/frameworks/index.html

- オープンソースと商用がある。
- 7 つのカテゴリに 50 以上のログファイルを提供する。
- Zeek を起動すると、トラフィックまたは指定された pcap ファイルの調査が自動的に開始され、ログが自動的に生成される。
- パケット指向ではなくイベント指向

```shell
# デフォルトのログパス
/opt/zeek/logs/
```

```shell
# version
zeek -v
```

## 起動モード

### サービス

```shell
# zeekctl
$ sudo zeekctl
Welcome to ZeekControl 2.X.0
[ZeekControl] > status
[ZeekControl] > start
[ZeekControl] > status
[ZeekControl] > stop

# この書き方もある
zeekctl status
sudo zeekctl start
sudo zeekctl stop
```

### pcap 処理モード

```shell
# pcap処理モード。-Cはチェックサムエラーを無視。
# ログファイルを出力して終了する。
zeek -C -r sample.pcap
```

## Zeek ログ

https://docs.zeek.org/en/current/script-reference/log-files.html

| カテゴリ           | 説明                                                                               | ログファイル                                                                                                                                                                                                                                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ネットワーク       | ネットワーク プロトコル ログ                                                       | conn.log、dce_rpc.log、dhcp.log、dnp3.log、dns.log、ftp.log、http.log、irc.log、kerberos.log、modbus.log、modbus_register_change.log、mysql.log、ntlm.log、ntp.log、radius.log、rdp.log、rfb.log、sip.log、smb_cmd.log、smb_files.log、smb_mapping.log、smtp.log、snmp.log、socks.log、ssh.log、ssl.log、syslog.log、tunnel.log。 |
| ファイル           | ファイル分析結果ログ                                                               | files.log、ocsp.log、pe.log、x509.log。                                                                                                                                                                                                                                                                                           |
| ネットコントロール | ネットワーク制御とフローログ                                                       | netcontrol.log、netcontrol_drop.log、netcontrol_shunt.log、netcontrol_catch_release.log、openflow.log。                                                                                                                                                                                                                           |
| 検出               | 検出および可能な指標のログ                                                         | intel.log、notice.log、notice_alarm.log、signatures.log、traceroute.log。                                                                                                                                                                                                                                                         |
| ネットワークの観察 | ネットワーク フロー ログ。                                                         | known_certs.log、known_hosts.log、known_modbus.log、known_services.log、software.log。                                                                                                                                                                                                                                            |
| その他             | 追加のログには、外部アラート、入力、および障害が含まれる                           | barnyard2.log、dpd.log、unified2.log、unknown_protocols.log、weird.log、weird_stats.log。                                                                                                                                                                                                                                         |
| ジーク診断         | Zeek 診断ログには、システム メッセージ、アクション、およびいくつかの統計が含まれる | broker.log、capture_loss.log、cluster.log、config.log、loaded_scripts.log、packet_filter.log、print.log、prof.log、reporter.log、stats.log、stderr.log、stdout.log。                                                                                                                                                              |

### zeek-cut

```shell
cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p
```

## Zeek シグネチャ

```shell
# シグネチャファイルを使用して、pcap処理
zeek -C -r sample.pcap -s sample.sig
```

シグネチャと一致すると、signatures.log、notice.log が追加で生成される。

### シグネチャの例

#### パスワードのクリアテキスト投信

```text
signature http-password {
     ip-proto == tcp
     dst-port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}

# signature: Signature name.
# ip-proto: Filtering TCP connection.
# dst-port: Filtering destination port 80.
# payload: Filtering the "password" phrase.
# event: Signature match message.
```

#### FTP

複数のシグネチャを定義可能

```shell
signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*/
    event "FTP Username Input Found!"
}

signature ftp-brute {
    ip-proto == tcp
     payload /.*530.*Login.*incorrect.*/
    event "FTP Brute-force Attempt!"
}
```

## Zeek スクリプト

オンライン学習プラットフォーム  
https://try.bro.org/#/?example=hello

```shell
# 基本スクリプト（変更されることを意図していない）
/opt/zeek/share/zeek/base

# ユーザーが生成、変更したスクリプトはここに置く必要がある
/opt/zeek/share/zeek/site

# ポリシースクリプト
/opt/zeek/share/zeek/policy

# ライブスニッフィングで自動的に使用するには、構成ファイルで指定
/opt/zeek/share/zeek/local.zeek
```

```shell
# ライブ監視モードでスクリプトを呼び出す
load @/script/path
# or
load @script-name
```

```shell
# local.zeek で識別される全てのスクリプトを実行
# ヒットした場合、追加のログファイルが生成される
zeek -C -r ftp.pcap local
```

### サンプルと実行例

```shell
event dhcp_message (c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
{
print options$host_name;
}
```

```shell
ubuntu@ubuntu$ zeek -C -r smallFlows.pcap dhcp-hostname.zeek
student01-PC
vinlap01
```

#### Zeek プロセスの開始と終了時のイベント

```shell
event zeek_init()
    {
     print ("Started Zeek!");
    }
event zeek_done()
    {
    print ("Stopped Zeek!");
    }

# zeek_init: Do actions once Zeek starts its process.
# zeek_done: Do activities once Zeek finishes its process.
# print: Prompt a message on the terminal.
```

#### 新しい接続イベント

```shell
event new_connection(c: connection)
{
	print ("###########################################################");
	print ("");
	print ("New Connection Found!");
	print ("");
	print fmt ("Source Host: %s # %s --->", c$id$orig_h, c$id$orig_p);
	print fmt ("Destination Host: resp: %s # %s <---", c$id$resp_h, c$id$resp_p);
	print ("");
}

# %s: Identifies string output for the source.
# c$id: Source reference field for the identifier.

# c 自体を print すると次のような構造

# [id=[orig_h=192.168.121.40, orig_p=123/udp, resp_h=212.227.54.68, resp_p=123/udp], orig=[size=48, state=1, num_pkts=0, num_bytes_ip=0, flow_label=0, l2_addr=00:16:47:df:e7:c1], resp=[size=0, state=0, num_pkts=0, num_bytes_ip=0, flow_label=0, l2_addr=00:00:0c:9f:f0:79], start_time=1488571365.706238, duration=0 secs, service={}, history=D, uid=CajwDY2vSUtLkztAc, tunnel=, vlan=121, inner_vlan=, dpd=, dpd_state=, removal_hooks=, conn=, extract_orig=F, extract_resp=F, thresholds=, dce_rpc=, dce_rpc_state=, dce_rpc_backing=, dhcp=, dnp3=, dns=, dns_state=, ftp=, ftp_data_reuse=F, ssl=, http=, http_state=, irc=, krb=, modbus=, mysql=, ntlm=, ntp=, radius=, rdp=, rfb=, sip=, sip_state=, snmp=, smb_state=, smtp=, smtp_state=, socks=, ssh=, syslog=]
```

#### シグネチャにマッチ

```shell
event signature_match (state: signature_state, msg: string, data: string)
{
if (state$sig_id == "ftp-admin")
    {
    print ("Signature hit! --> #FTP-Admin ");
    }
}
```

#### 事前構築されたフレームワークスクリプトを呼び出す

```shell
# Enable MD5, SHA1 and SHA256 hashing for all files.
@load /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek
```

## フレームワーク

### ファイルフレームワーク

```shell
# ファイルハッシュ　-> files.log
/opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek

# ファイル抽出 -> extract_files フォルダ
/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
```

### 通知フレームワーク | インテリジェンス

インテリジェンスファイル

- タブ区切り
- 行の追加は再デプロイ不要だが、削除は Zeek インスタンスの再デプロイが必要

```shell
# 疑わしいURLを定義
ubuntu@ubuntu$ cat /opt/zeek/intel/zeek_intel.txt
#fields	indicator	indicator_type	meta.source	meta.desc
smart-fax.com	Intel::DOMAIN	zeek-intel-test	Zeek-Intelligence-Framework-Test

ubuntu@ubuntu$ cat intelligence-demo.zeek
# Load intelligence framework!
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
redef Intel::read_files += { "/opt/zeek/intel/zeek_intel.txt" };

# intel.log を生成
ubuntu@ubuntu$ zeek -C -r case1.pcap intelligence-demo.zeek
```

## パッケージ

サードパーティのスクリプトやプラグインをインストールして拡張できる。

```shell
zkg install package_path
zkg install git_url
zkg list
zkg remove
zkg refresh
zkg upgrade
```

### 利用可能なパッケージ

- https://packages.zeek.org/
- https://github.com/zeek/packages
