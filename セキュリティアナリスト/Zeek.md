# Zeek

https://tryhackme.com/room/zeekbro

https://tryhackme.com/room/networkmonitoringwithzeek

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

## Zeek ログの種類

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

## Zeekログ

### zeek-cut

```shell
cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p
```

フィールド名は `head conn.log` を実行したら分かる。

### conn.log

```sh
zeek-cut ts uid id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state < logs/conn.log | head -5
```

#### conn_state の意味

| 状態     | 意味                      | 主な意味・示唆                               |
| ------ | ----------------------- | ------------------------------------- |
| `S0`   | SYNを送信したが応答なし           | ポートスキャン、ファイアウォールによる破棄、またはポートが閉じている可能性 |
| `SF`   | 接続が確立され、正常に終了           | 正常に完了した通信であることを示す                     |
| `REJ`  | SYNに対してRSTが返され拒否された     | ファイアウォールによる遮断やACLによる拒否の可能性            |
| `OTH`  | SYNが観測されず、通信途中のパケットのみ観測 | 非対称ルーティング環境でのキャプチャなどが考えられる            |
| `S1`   | 接続は確立されたが、終了が観測されていない   | 通信が継続中である可能性があるため、通信時間などを確認するとよい      |
| `RSTO` | 接続確立後に送信元がRSTを送信        | クライアント側で通信が中断・強制終了されたことを示す            |

#### 接続ペア（送信元、送信先のペア）、ポートごとの件数

```sh
zeek-cut id.orig_h id.resp_h id.resp_p < logs/conn.log | sort | uniq -c | sort -rn | head -5
```

#### duration を表示してビーコンタイミングを検出

```sh
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < logs/conn.log | awk -F'\t' '$3=="194.165.16.56" && $4=="443"' | sort -k1 | head -5
```

#### 内部スキャンの検出

```sh
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < logs/conn.log | awk -F'\t' '$1=="10.14.22.88" && $3=="445" && $4=="S0"' | wc -l
```

#### 大きい送信サイズの検出

```sh
zeek-cut ts uid id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < logs/conn.log | awk -F'\t' '$3=="10.14.22.88" && $4!~/^10\.14\./ {print $0}' | sort -t$'\t' -k6 -rn | head -3
```

### dns.log

```sh
zeek-cut ts id.orig_h query qtype_name rcode_name answers < logs/dns.log | head -10
```

#### 長いクエリ文字列を検出

```sh
zeek-cut id.orig_h query < logs/dns.log | awk -F'\t' 'length($2) > 60' | sort | uniq -c | sort -rn | head -10
```

### http.log

```sh
zeek-cut ts uid id.orig_h id.resp_h method host uri user_agent request_body_len status_code < logs/http.log
```

### ssl.log

```sh
zeek-cut ts id.orig_h id.resp_h version server_name < logs/ssl.log | head -5
```

#### SNIが空の接続を検出

通常のブラウザトラフィックでは、クライアントはサーバーが適切な証明書を選択できるように、到達しようとしているホスト名を送信する。

```sh
zeek-cut id.orig_h id.resp_h server_name < logs/ssl.log | awk -F'\t' '$2=="194.165.16.56"' | sort -u
```

#### uid と files.log を関連付ける

uid を得る。

```sh
ubuntu@tryhackme:~$ zeek-cut ts uid id.orig_h id.resp_h method host uri user_agent request_body_len status_code < logs/http.log
1763088600.061000	CIEtDD4xl1OB8efmf	10.14.22.88	185.220.101.45	GET	fileshare.corp-helpdesk.net	/downloads/invoice_march.pdf\x2d	0	200
1763090107.081000	CmQW1d3iuUHHDgqYe7	10.14.22.88	185.213.154.201	POST	185.213.154.201	/upload/data	-	5348721	200
```

uid を使って files.log から情報を得る。

```sh
ubuntu@tryhackme:~$ grep -E "(^#)|(CmQW1d3iuUHHDgqYe7)" logs/files.log | zeek-cut source mime_type filename total_bytes
HTTP	application/zip	backup_archive.zip	5348721
HTTP	-	-	7
```

### files.log

mime_type と filename の拡張子の不一致は要注意。  
ハッシュ値をVirusTotalなどに渡して特定できる可能性もある。

```sh
zeek-cut ts uid source mime_type filename total_bytes sha256 < logs/files.log
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

#### [長いDNSクエリを検出する例](https://tryhackme.com/room/networkmonitoringwithzeek)

特定のIPを抑制している点に注目。

```sh
@load base/frameworks/notice

module DNSTunnel;

export {
    redef enum Notice::Type += {
        DNS_Exfil_LongQuery
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( c$id$orig_h == 10.0.0.53 )
        return;

    if ( |query| > 60 )
    {
        NOTICE([$note=DNS_Exfil_LongQuery,
                $conn=c,
                $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
                $identifier=cat(c$id$orig_h),
                $suppress_for=5min]);
    }
}
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

## RITA

Real Intelligence Threat Analytics（RITA）は、Active Countermeasuresが開発したオープンソースフレームワーク。  
その中核機能は、ネットワークトラフィックのキャプチャとログを分析し、コマンドアンドコントロール（C2）通信を検出すること。  
RITA は、ネットワーク トラフィックの入力をZeek のログとしてのみ受け入れる。

```sh
# pcap から zeekログ出力
zeek readpcap pcaps/AsyncRAT.pcap zeek_logs/asyncrat

ls zeek_logs/asyncrat
capture_loss.log  files.log        known_services.log  ocsp.log           software.log  weird.log
conn.log          http.log         loaded_scripts.log  packet_filter.log  ssl.log       x509.log
dns.log           known_hosts.log  notice.log          reporter.log       stats.log
```

```sh
# zeekログをインポート
rita import --logs ~/zeek_logs/asyncrat/ --database asyncrat
```

```sh
# 構造化されたターミナルウィンドウが表示される
rita view asyncrat
```

### 構造化ターミナルの操作

- 検索するにはスラッシュ押下
- 検索中に?を押下すると検索ユーティリティのヘルプを表示、もう一度押して解除
- Esc押下で検索終了

検索の例

```
dst:rabbithole.malhare.net beacon:>=70 sort:duration-desc
```
