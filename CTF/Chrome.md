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

```sh
cat AppData/Local/Google/Chrome/User\ Data/Local\ State | jq .os_crypt.encrypted_key -r
```

```sh
mimikatz # dpapi::chrome /in:"AppData/Local/Google/Chrome/User Data/Default/Login Data" /masterkey:ca43[REDACTED]9840 /encryptedKey:RFBBUEkBAAAA.........
```




## 振り返り

-
-

## Tags

#tags: #tags: #tags:

```sh
# 大分類（Linuxはタグ付けしない）
Window Kerberos AWS pwn pwn(Windows) Crypto puzzle ウサギの穴 LLM

# 脆弱性の種類
CVE-xxxx-yyyyy カーネルエクスプロイト
ツール脆弱性 sudo脆弱性 PHP脆弱性 exiftool脆弱性 アプリケーション保存の認証情報 証明書テンプレート

# 攻撃の種類
サービス LFI SSRF XSS SQLインジェクション 競合 認証バイパス フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD セッションID AVバイパス UACバイパス AMSIバイパス PaddingOracles フィッシング

# ツールなど
docker fail2ban modbus ルートキット gdbserver jar joomla MQTT CAPTCHA git tmux john redis rsync pip potato ligolo-ng insmod pickle スマートコントラクト
```

## メモ

### シェル安定化

```shell
# python が無くても、python3 でいける場合もある
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# sh: 3: export: -c: bad variable name というエラーが出る場合、まず /bin/bash を実行する。

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236
```

### SSH

ユーザー名、パスワード（スペース区切り）ファイルを使ってSSHスキャンする

```sh
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 10.10.165.96; set USERPASS_FILE creds.txt; run; exit"
```

エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```
