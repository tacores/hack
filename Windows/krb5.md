# krb5

```sh
sudo apt-get install krb5-user
```

```sh
nano /etc/krb5.conf
```

ドメイン指定は必ず大文字。

```yaml
[libdefaults]
        default_realm = WINDCORP.THM  

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4 
        forwardable = true
        proxiable = true  
        rdns = false


# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true  

[realms]
        WINDCORP.THM = {
                kdc = 10.49.185.223
                admin_server = 10.49.185.223
        }
```

## コマンド

### 1. Kerberos チケット管理・確認

#### チケットを取得

```sh
kinit edwardle@WINDCORP.THM
```

#### チケットの有効期限と内容を確認

```sh
$ klist                      
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: edwardle@WINDCORP.THM

Valid starting       Expires              Service principal
03/16/2026 03:37:41  03/16/2026 13:37:41  krbtgt/WINDCORP.THM@WINDCORP.THM
        renew until 03/17/2026 03:37:32
```

#### チケットを破棄（再認証のとき必須）

```sh
kdestroy
```

#### チケットキャッシュの場所を明示的に指定する

Impacketなどのツールがチケットを見つけられない場合、環境変数でパスを指定。

```sh
export KRB5CCNAME=/tmp/krb5cc_...
```

### 2. チケットの使用

実行時にパスワードを指定するか、チケットを指定するかの違いだけのようだが、パスワードの場合は毎回認証が発生してログに残るので、チケットを使う方がステルス性が高いと考えられる。

#### evil-win

```sh
# KRB5CCNAME 環境変数をチケットファイルのパスに設定
export KRB5CCNAME=/tmp/krb5cc_1000

# -k オプションで「チケットを使う」ことを明示
evil-winrm -i 10.49.185.223 -u edwardle -r WINDCORP.THM
```

#### impacket

```sh
getST.py -dc-ip 10.49.185.223 -spn cifs/fire.windcorp.thm windcorp.thm/edwardle -k -no-pass
```

IP指定では失敗する

```sh
smbclient.py -k -no-pass windcorp.thm/edwardle@fire.windcorp.thm
```
