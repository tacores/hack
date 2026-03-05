# AWSワークロードの監視

https://tryhackme.com/room/monitoringawsworkloads

## EC2

### AWS Systems Manager (SSM)

EC2インスタンスを管理するためのマネージドサービスで、エージェントに対してコマンドを送信できる。  
悪意のある者がアクセスを得た場合、C2ツールとして使用される可能性がある。

CloudTrail では SendCommand イベントとして記録される。

```
eventName=SendCommand
```

コンソールでの確認

```sh
root@ec2-demo:~$ pstree -l -T -a -s 3810
systemd                                                    # OS itself, first process
└── amazon-ssm-agent                                       # SSM agent service (root)
    └── ssm-agent-worker                                   # Per-command worker process
        └── ssm-document-worker d47130a2-4f90-41af-...     # Same ID as in the SendCommand
            └── sh -c /var/lib/amazon/ssm/.../_script.sh
                └── sh /var/lib/amazon/ssm/.../_script.sh
                    ├── echo "My command!"                 # The first script command
                    └── sleep 100                          # The second script command
```

### AWS Session Manager

 AWSコンソールからEC2インスタンスに直接アクセスできる。SSMエージェントを利用し、コンソール認証を使用するため、 SSHまたはRDPポートを開く必要がない。

CloudTrail ではすべての接続が StartSession イベントとして記録される。

```
eventName=StartSession
```

### Amazon EC2 Auto Scaling に関する問題

一言でいうと、数十分程度の寿命の短いEC2インスタンスで効果的に SIEM / EDRを運用することは困難。

#### Falco

auditdの出力は読みにくく、記録には重要なコンテキストなコンテキストが欠けている。  
[Falco](https://falco.org/docs/) は、クラウドおよびコンテナ化されたワークロード向けの最新の代替ツール。  

Falcoは、コンテナ化されたクラウド環境を監視し、必要なコンテナコンテキストを提供するために設計されている。  
検出ルールをSEIMからローカルエンジンに移すことでアラートを配信する形になり、SEIMに送信されるデータ量を大幅に削減できる。

```sh
root@ec2-demo:~$ grep whoami /var/log/falco.json | jq  // Can log in plaintext and JSON
{
  "hostname": "ec2-demo",
  "output_fields": {
    "container.id": "425f43aad5c9",                    // Includes Docker container context
    "container.image": "wordpress:php8.2-apache",
    "container.name": "mywebsite",
    "proc.cmdline": "whoami",                          // Conveniently logs process fields
...
```

## コンテナ

「コンテナの監視」とは、ホストとホスト上のすべてのコンテナの両方を監視することを意味する。（自分でホストする場合）

Auditdや一部のEDRはホストイベントとコンテナイベントの両方を単一のストリームに記録するため、プロセスがホストで起動されたのか、コンテナで起動されたのかを推測するしかない。

### AWS Fargate

すべてのホストベースのSIEMおよびEDRエージェントは使用できない。  
Falco などの Fargate で動作するツールが必要になる。ツールはサイドカーのデプロイメントをサポートしている必要がある。

### Falco

コンテナIDを識別てきている点に注目。

```sh
root@ec2-demo:~$ tail /var/log/falco.json | jq
{
  "hostname": "ec2-demo",
  "output_fields": {
    // 1. Suspicious "find" command! Who launched it and why?
    "proc.cmdline": "sh -c find / -name *secret*",
    "proc.cwd": "/var/www/html/",
    "proc.exepath": "/usr/bin/sh",
    // 2. The parent process is Apache, does it mean a web shell?
    "proc.pcmdline": "apache2 -DFOREGROUND",
    "proc.pexepath": "/usr/bin/nginx",
    "proc.pid": 7924,
    "proc.ppid": 2285,
    "proc.tty": 0,
    "user.name": "www-data",
    // 3. The activity occurs on a THM production website!
    "container.name": "www-tryhatme-prod",
    // 4. The website uses WordPress, maybe it's vulnerable?
    "container.image": "wordpress:php8.2-apache",
    // 5. Investigate container files and web logs to find out!
    "container.id": "c1ac9c6d51d7",
  },
  "priority": "Notice",
  "rule": "exec",
  "source": "syscall"
}
```

プロセスツリーからコンテナを特定する例

```sh
root@ec2-demo:~$ pstree -T -a
systemd --system
  ├─dockerd -H fd:// --containerd=/run/...               # Docker Engine, manages containers
  ├─containerd                                           # Containerd, a container runtime
  ├─falco -o engine.kind=modern_ebpf                     # Falco, monitors the EC2 instance
  │
  ├─containerd-shim -namespace moby -id 425fd...         # Container for api.tryhatme.thm
  │   └─apache2 -DFOREGROUND                             # Utilizes Apache web server
  │       └─thmapiworker -s                              # Spawns a custom application
  │
  ├─containerd-shim -namespace moby -id c1ac9...         # Container for www.tryhatme.thm
      └─apache2 -DFOREGROUND                             # Runs Apache web server, too
          └─sh -c find / -name *secret*                  # Looks abnormal for Apache!
             └─find / -name *secret*                     # What if it's a cyber attack?

root@ec2-demo:~$ docker container ls --filter "id=c1ac9"
CONTAINER ID   IMAGE                     PORTS    NAMES
c1ac9c6d51d7   wordpress:php8.2-apache   80/tcp   www-tryhatme-prod
```

## Lambda

Lambda の3つのセキュリティ要素

1. 関数コード
2. 信頼ポリシー（誰が関数をトリガーまたは編集できるか）
3. 実行ロール（他のAWSサービスにアクセスする権限）

注目すべきイベント

```
AddPermission*
PublishLayerVersion*
UpdateFunctionCode*
CreateFunction*
UpdateFunctionConfiguration*
```

権限の調査

```sh
user@thm-vm:~$ aws lambda get-function-configuration --function-name thm-deployer
{
  "Role": "arn:aws:iam::123456789012:role/THMDeployerRole", ...
}
user@thm-vm:~$ aws iam list-attached-role-policies --role-name THMDeployerRole
[
  {"PolicyName": "EC2FullAccess" ...},
  {"PolicyName": "SSMFullAccess" ...}
]
```
