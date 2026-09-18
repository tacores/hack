# Tryhackme リンク集

侵害されたネットワークへのアクセス  
https://tryhackme.com/room/accessingacompromisednetwork

DFIRキーアーティファクト（収集手順ではないことに注意）  
https://tryhackme.com/room/keyartifactsfordfir

ターゲットとDFIRマシンでファイル共有する方法

```ps
# ただし共有ストレージを使うほうが望ましい
net use M: \\DFIR-IP\C$ /user:DFIRUser
```
