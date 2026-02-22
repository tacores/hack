# SNMP

バージョン1～3があり、v1, v2 は認証が平文文字列になっている。

## SNMPコミュニティ文字列スキャン

このスキャンが成功しない限り、背後にSNMPがあるかどうかも判別できない。

```sh
# SNMPコミュニティ文字列をブルートフォースで特定
onesixtyone $TARGET -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt 
```

## 情報取得

```sh
# システム情報
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.2.1.1        

iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.2
iso.3.6.1.2.1.1.3.0 = Timeticks: (525727) 1:27:37.27
iso.3.6.1.2.1.1.4.0 = ""
iso.3.6.1.2.1.1.5.0 = STRING: "year-of-the-owl"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
```

```sh
# Windows ローカルアカウント名一覧
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.4.1.77.1.2.25

iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.74.97.114.101.116.104 = STRING: "Jareth"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
iso.3.6.1.4.1.77.1.2.25.1.1.14.68.101.102.97.117.108.116.65.99.99.111.117.110.116 = STRING: "DefaultAccount"
iso.3.6.1.4.1.77.1.2.25.1.1.18.87.68.65.71.85.116.105.108.105.116.121.65.99.99.111.117.110.116 = STRING: "WDAGUtilityAccount"
```

```sh
# SMB共有名
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.4.1.77.1.2.27
```

```sh
# 実行中プロセス名
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2

iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.68 = STRING: "Registry"
...
```

```sh
# インストールソフト
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.2.1.25.6.3.1.2
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "XAMPP"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "Microsoft Visual C++ 2017 x64 Minimum Runtime - 14.11.25325"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "Microsoft Visual C++ 2017 x64 Additional Runtime - 14.11.25325"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "Amazon SSM Agent"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "Amazon SSM Agent"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "Microsoft Visual C++ 2017 Redistributable (x64) - 14.11.25325"
```

```sh
# AD
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.4.1.77.1.4.1  
iso.3.6.1.4.1.77.1.4.1.0 = STRING: "WORKGROUP"
End of MIB
```

```sh
# NWインターフェース一覧
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.2.1.2.2.1.2
```

```sh
# IPアドレス
$ snmpwalk -c openview -v1 $TARGET 1.3.6.1.2.1.4.20.1.1
iso.3.6.1.2.1.4.20.1.1.10.48.128.88 = IpAddress: 10.48.128.88
iso.3.6.1.2.1.4.20.1.1.127.0.0.1 = IpAddress: 127.0.0.1
```
