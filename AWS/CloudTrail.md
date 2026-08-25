# CloudTrail

https://tryhackme.com/room/thesilenceoftheiams


## CloudTrail を確認

```sh
aws cloudtrail describe-trails \
    --query "trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail,HomeRegion:HomeRegion,GlobalEvents:IncludeGlobalServiceEvents}" \
    --output table
```

```sh
TRAIL_NAME=$(aws cloudtrail describe-trails \
    --query "trailList[0].Name" --output text)

aws cloudtrail get-trail-status --name $TRAIL_NAME
```

## ハイリスクなIAMイベント

| **Event Name**                    | **Risk** | **Why（理由）**                                               |
| --------------------------------- | -------- | --------------------------------------------------------- |
| **AttachUserPolicy**              | Critical | 管理ポリシー（AdministratorAccessなど）をユーザーに付与すると、即座に権限昇格が可能になるため。 |
| **AttachRolePolicy**              | Critical | ロールにポリシーを付与することでも、同様に権限昇格が可能になるため。                        |
| **PutUserPolicy**                 | Critical | ユーザーにインラインポリシーを作成すると、権限昇格の痕跡を発見しにくくなるため。                  |
| **CreateUser**                    | High     | 新しいIAMユーザーの作成は、永続化（Persistence）を目的とした操作である可能性があるため。       |
| **CreateAccessKey**               | High     | コンソールログインを必要とせず、APIアクセスに使用できる新しいプログラム認証情報が作成されるため。        |
| **CreateLoginProfile**            | High     | これまでプログラムアクセスのみだったユーザーに、コンソールへのログイン権限を追加できるため。            |
| **UpdateAssumeRolePolicy**        | High     | クロスアカウントでの永続化（Persistence）を可能にする場合があるため。                  |
| **DeleteTrail** / **StopLogging** | Critical | 監査ログを無効化し、攻撃の痕跡を隠す防御回避（Defense Evasion）につながるため。           |
| **DeactivateMFADevice**           | High     | MFAを無効化することで、アカウントへの不正アクセスが容易になるため。                       |

### 最近のIAM書き込みイベント

```sh
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
    --max-results 10 \
    --query "Events[*].{Time:EventTime,User:Username,Event:EventName,Resources:Resources[0].ResourceName}" \
    --output table
```

```sh
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
    --max-results 50 \
    --query "Events[?contains(EventName,'Attach') || contains(EventName,'Create') || contains(EventName,'Put') || contains(EventName,'Update') || contains(EventName,'Delete')].{Time:EventTime,User:Username,Event:EventName}" \
    --output table
```

### イベント詳細

```sh
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
    --max-results 5 \
    --query "Events[0].CloudTrailEvent" \
    --output text | python3 -m json.tool
```
