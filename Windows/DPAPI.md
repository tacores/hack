# DPAPI

## 基礎

DPAPI（Data Protection API）は、Windows 2000以降に組み込まれた、ユーザーやマシンの資格情報（パスワード）を利用してデータを安全に暗号化・復号するWin32 API。  
独自のキー管理が不要で、主にWebブラウザの保存パスワード、資格情報マネージャー、C#のProtectedDataクラスなどで機密情報を保護する仕組みとして利用されている。

### 主な特徴と機能

- 簡単・安全な暗号化: 暗号化キーを自分で生成・管理する必要がない。
- ユーザー専用の鍵: 暗号化したユーザー本人しか復号できない（CurrentUserスコープ）。
- TPMが関与している場合、別のPCで復号することは不可能。

### 主な用途

- ブラウザが保存するパスワード
- 証明書の秘密鍵保護
- 設定ファイル内の機密情報など

### 使用イメージ

```cs
using System;
using System.Security.Cryptography;
using System.Text;

public class DpapiExample
{
    public static void Main()
    {
        // 1. 暗号化したい秘密の文字列
        string secretMessage = "これは秘密のパスワードです(Flag{dpapi_is_magic})";
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(secretMessage);

        // 2. 暗号化の実行
        // DataProtectionScope.CurrentUser を指定することで、
        // 「今ログインしているこのユーザー」の鍵（パスワードやTPM由来の鍵）で保護する。
        byte[] encryptedBytes = ProtectedData.Protect(
            plaintextBytes, 
            null, // 追加のソルト（オプション）
            DataProtectionScope.CurrentUser
        );

        Console.WriteLine("暗号化されました（このデータはファイルに保存しても安全です）:");
        Console.WriteLine(Convert.ToBase64String(encryptedBytes));
        Console.WriteLine();

        // 3. 復号の実行
        // 復号時も、OSが自動的に「今のユーザーの鍵」をTPMやレジストリから取ってきて照合する。
        try
        {
            byte[] decryptedBytes = ProtectedData.Unprotect(
                encryptedBytes, 
                null, 
                DataProtectionScope.CurrentUser
            );

            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine("復号成功:");
            Console.WriteLine(decryptedMessage);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("復号失敗: 別のユーザーや別のPCでは、このデータは開けません。");
            Console.WriteLine(e.Message);
        }
    }
}
```

### DPAPIマスターキーファイルのPath例

```
AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580
```

## Hack

### Windowsパスワードのクラック  

そのユーザーがWindowsパスワードを使っている場合の話。PINコードなどを使っている場合は、ハッシュは出力されるかもしれないが無意味。  
TPMが有効な場合でも、パスワードをクラックできる可能性はあるため無意味とは限らないことに注意。

```sh
DPAPImk2john -mk AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580 -c local -S S-1-5-21-3854677062-280096443-3674533662-1001 > mkhash

john mkhash --wordlist=/usr/share/wordlists/rockyou.txt
```

### マスターキーを復号

TPMが関与していない場合のみ別のPC環境で復号できる。

```sh
mimikatz # dpapi::masterkey /in:"AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580" /sid:S-1-5-21-3854677062-280096443-3674533662-1001 /password:[PASSWORD]
```
