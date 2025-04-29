# TryPwnMe Two

https://tryhackme.com/room/trypwnmetwo

## TryExecMe 2

```c
undefined8 main(void)
{
  char cVar1;
  code *__buf;
  
  setup();
  banner();
  __buf = (code *)mmap((void *)0xcafe0000,100,7,0x22,-1,0);
  puts("\nGive me your spell, and I will execute it: ");
  read(0,__buf,0x80);
  puts("\nExecuting Spell...\n");
  cVar1 = forbidden(__buf);
  if (cVar1 != '\0') {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  (*__buf)();
  return 0;
}

undefined8 forbidden(long param_1)

{
  ulong local_18;
  
  local_18 = 0;
  while( true ) {
    if (0x7e < local_18) {
      return 0;
    }
    if ((*(char *)(local_18 + param_1) == '\x0f') && (*(char *)(param_1 + local_18 + 1) == '\x05'))
    {
      puts("Forbidden spell detected!");
      return 1;
    }
    if ((*(char *)(local_18 + param_1) == '\x0f') && (*(char *)(param_1 + local_18 + 1) == '4')) {
      puts("Forbidden spell detected!");
      return 1;
    }
    if ((*(char *)(local_18 + param_1) == -0x33) && (*(char *)(param_1 + local_18 + 1) == -0x80))
    break;
    local_18 = local_18 + 1;
  }
  puts("Forbidden spell detected!");
  return 1;
}
```

3種類のシェルコードが禁止されている。これにより、単純に /bin/sh を実行するようなシェルコードは成功しないと思われる。

- \x0f\x05	syscall命令	システムコール（例：execveなど）
- \x0f\x34	sysenter命令	古いLinuxカーネル向けシステムコール
- \xcd\x80（= -0x33と-0x80）	int 0x80命令	もっと古いLinuxシステムコール

```shell
$ pwn checksec ./tryexecme2
[*] '/home/kali/CTF/0429/materials-trypwnmetwo/TryExecMe2/tryexecme2'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

