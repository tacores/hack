# GoBGP

https://qiita.com/yas-nyan/items/efd6c587b88678878da6

kali なら、gobgp と打てばインストールできる。

router-id はIPアドレスの形式である必要があるが、通信に使われるわけではないので到達不能なIPでも構わない。

```
[global.config]
  as = 65000
  router-id = "192.0.0.1"
  
[[neighbors]]
  [neighbors.config]
    peer-as = 65000
    neighbor-address = "2001:df8::cafe"
    local-as = 65000

    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-unicast"
```

```sh
gobgpd -f example.conf 
```

neighbor の確認

```hs
gobgp neighbor
```

## 経路

追加

```sh
gobgp global rib add -a ipv6 2001:df8:100:200::/64 nexthop  2001:df8::beaf
```

削除

```sh
gobgp global rib del -a ipv6 2001:df8:100:200::/64 nexthop  2001:df8::beaf
```

自分が広告している経路の確認

```sh
gobgp nei 2001:df8:: adj-out
   ID  Network               Next Hop             AS_PATH              Attrs
   1   2001:df8:100:200::/64 2001:df8::cafe                            [{Origin: ?} {LocalPref: 100}]
```

