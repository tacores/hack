# EntraID モニタリング

https://tryhackme.com/room/entraidmonitoring

## パスワードベース攻撃

失敗したログイン試行をIPアドレス別に表示

```
index=* sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, status.errorCode, status.failureReason
| sort - _time
```

特定IPアドレスのログイン成功一覧

```
index=* sourcetype="azure:aad:signin" "status.errorCode"=0
| where ipAddress="<SUSPICIOUS_IP>"
| stats count by userPrincipalName, status.errorCode
| sort status.errorCode
```

特定ユーザーのログイン成功一覧

```
index=* sourcetype="azure:aad:signin" "status.errorCode"=0
| where userPrincipalName="<TARGET_USER>"
| stats count by userPrincipalName, status.errorCode, ipAddress
| sort status.errorCode
```

## 条件付きアクセスポリシー (Conditional Access Policies、CAP)

全てのログインイベントには、どのポリシーが適用されたかの情報が含まれている。

```yaml
appDisplayName: "One Outlook Web"
appId: "9199bf20-a13f-4107-85dc-02114787ef48"
appliedConditionalAccessPolicies: [
    {
    displayName: "Require MFA" // Applied Policy
    enforcedGrantControls: [
        "Block"
    ]
    enforcedSessionControls: [
    ]
    id: "c63499f4-64b6-4943-bfc3-52fbb641ef10"
    result: "notApplied" // Resulted action
    }
]
```

CAPによりブロックされたサインイン一覧

```
index=* sourcetype="azure:aad:signin" conditionalAccessStatus=failure
| spath output=policies path=appliedConditionalAccessPolicies{}
| mvexpand policies
| spath input=policies output=policy_result path=result
| spath input=policies output=policy_name path=displayName
| where policy_result="failure"
| stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus
| eval FailedPolicies=mvjoin(FailedPolicies, ", ")
| table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies
| sort - _time
```

### Identity Protection

Entra IDに組み込まれた機械学習ベースのリスク検出エンジンで、疑わしい点があった場合に条件付きアクセスに通知する。

サインインリスクとユーザーリスクがある。

- サインインリスク：特定のサインイン試行の疑わしさを評価
- ユーザーリスク：特定のアカウントが侵害される可能性を評価

#### サインインリスク

高リスクサインイン一覧

```
index=* sourcetype="azure:aad:signin"
| where riskLevelDuringSignIn="high"
| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, riskLevelDuringSignIn, riskLevelAggregated
| sort - _time
```

詳細はリスク検出ログ`azure:aad:identity_protection:riskdetection`から得られる。

```
index=* sourcetype="azure:aad:identity_protection:riskdetection"
```

匿名化されたIPに絞る

```
index=* sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="anonymizedIPAddress"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
| sort - _time
```

#### ユーザーリスク

ユーザーリスク一覧

```
index=* sourcetype="azure:aad:identity_protection:risky_user"
| table _time, userPrincipalName, riskLevel, riskState, riskDetail 
| sort - _time
```

## MFAバイパス

### MFA疲労（MFA Fatigue）

ユーザーが承認するまでMFAプッシュ通知を送り続けるソーシャルエンジニアリング手法。

ユーザー別MFA失敗回数

```
index=* sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)
| stats count as mfa_failures values(status.errorCode) as errorCodes values(status.failureReason) as failureReasons by userPrincipalName, ipAddress
| sort - mfa_failures
```

### SIMスワッピング

被害者の電話番号を攻撃者が管理するSIMカードに移行させる手法。  
対策は、SMSをMFAとして利用しないようにすること。

普段と異なるデバイス場所からのログオン成功が兆候。

### Adversary-in-the-Middle (AiTM)フィッシング

被害者と正規のMicrosoftログインページの間にリバースプロキシを設置する手法。  
唯一の兆候は、地理的情報とIPアドレス。

### Impossible Travel

様々な要因により必ずしも正確に出るとは限らないので、即断せず確認が必要。

成功したサインイン一覧（地理情報を表示）

```
index="task-4" sourcetype="azure:aad:signin" status.errorCode=0
| table _time, userPrincipalName, ipAddress, location.countryOrRegion, conditionalAccessStatus
| sort - _time
```

impossibleTravel のアラート表示

```
index="task-4" sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="impossibleTravel"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
| sort - _time
```

## 特権の拡大と継続

全ての監査ログを一覧表示

```
index=* sourcetype="azure:aad:audit"
```

ロールの割り当て

```
index=* sourcetype="azure:aad:audit" activityDisplayName="Add member to role" 
| table _time, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue | sort - _time
```

ユーザー作成

```
index=* sourcetype="azure:aad:audit" activityDisplayName="Add user"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval userCreated='targetResources{}.userPrincipalName'
| table _time, activityDisplayName,initiator, userCreated
```

MFAデバイスの追加

```
index=* sourcetype="azure:aad:audit" activityDisplayName="User started security info registration" loggedByService="Authentication Methods"  operationType="Add"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| table _time, activityDisplayName, initiator, initiatedBy.user.ipAddress, additionalDetails{}.value
```

## OAuthアプリケーションの悪用

高リスクの権限スコープ

| 権限 | 説明 |
|---|---|
| Mail.Read.All / Mail.ReadWrite.All | テナント内のすべてのメールボックスを読み取り、または変更します。 |
| Files.ReadWrite.All | SharePoint と OneDrive 上のすべてのファイルを読み書きします。 |
| RoleManagement.ReadWrite.Directory | Entra ID の役割（グローバル管理者を含む）を割り当てたり削除したりします。 |
| Directory.ReadWrite.All | ユーザーやグループを含む、ディレクトリ内のすべてのデータを読み書きします。 |
| offline_access | ユーザーがアクティブにログインしていない場合でも、リフレッシュトークンを使用して無期限にアクセスを維持します。 |

アプリケーションに対するすべての同意付与一覧

```
index=* sourcetype="azure:aad:audit"
activityDisplayName="Consent to application"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval appName='targetResources{}.displayName'
| eval permissionsGranted='targetResources{}.modifiedProperties{}.newValue'
| table _time, initiator, appName, permissionsGranted
| sort - _time
```
