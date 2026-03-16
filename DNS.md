# DNS

https://tryhackme.com/room/dnsmanipulation

https://datatracker.ietf.org/doc/html/rfc1035

```sh
dnsrecon -d foobar.thm -n $TARGET
```

## ゾーン転送

ゾーン設定が次のように誤って設定されている場合

```
allow-transfer { any; };
```

```sh
$ dig axfr hipflasks.thm @10.201.95.128

; <<>> DiG 9.20.4-4-Debian <<>> axfr hipflasks.thm @10.201.95.128
;; global options: +cmd
hipflasks.thm.          86400   IN      SOA     ns1.hipflasks.thm. localhost. 1 604800 86400 2419200 86400
hipflasks.thm.          86400   IN      NS      ns1.hipflasks.thm.
hipflasks.thm.          86400   IN      NS      localhost.
hipper.hipflasks.thm.   86400   IN      A       10.201.95.128
www.hipper.hipflasks.thm. 86400 IN      A       10.201.95.128
ns1.hipflasks.thm.      86400   IN      A       10.201.95.128
hipflasks.thm.          86400   IN      SOA     ns1.hipflasks.thm. localhost. 1 604800 86400 2419200 86400
;; Query time: 331 msec
;; SERVER: 10.201.95.128#53(10.201.95.128) (TCP)
;; WHEN: Mon Sep 01 10:58:34 JST 2025
;; XFR size: 7 records (messages 1, bytes 242)
```

ほぼ同じ

```sh
host -t axfr hipflasks.thm 10.201.95.128
```

## DNS動的更新

更新可能な場合の動作。AD & Kerberos 環境では基本的に動的更新可能だが、危険なのは設定不備で「誰でも更新可能」になっている場合。

```sh
$ nsupdate      
> server 10.48.173.61
> update add test.windcorp.thm 600 A 192.168.129.39
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
test.windcorp.thm.      600     IN      A       192.168.129.39

> send
```

存在する場合は削除してから追加する。

```sh
> update delete test.windcorp.thm
> send
> update add test.windcorp.thm 600 A 192.168.129.39
> send
```

pfxファイルを使用してResponderを起動する方法は、pfxファイル.md 参照。

## iodine

DNSトンネリングに使用するプログラム

https://github.com/yarrick/iodine

## Tips

### FirefoxでDNSサーバーを強制する小技

```
about:config
network.dns.forceResolve
```

### pcapに含まれるDNSクエリを表示

```sh
tshark -r test.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name
```
