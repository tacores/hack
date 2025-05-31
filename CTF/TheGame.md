# The Game, The Game v2 CTF

https://tryhackme.com/room/hfb1thegame

https://tryhackme.com/room/hfb1thegamev2

## The Game

Ghidraで解析したり、binwalkで展開したりといろいろこねくり回した後、下記で出てくることに気づいた。

説明文の「encrypted data」という文言に騙された。

```sh
$ strings ./Tetrix.exe | grep THM
, FEATURE_ARITHMETIC
ATTENUATION_LOGARITHMIC
PATHFINDING_ALGORITHM_ASTAR
-4PTHMM
THM{..................}
```

## The Game v2

同じやり方で文字列が出てくるが、これは答えではない。

```sh
$ strings -t x ./TetrixFinal.exe | grep THM
41ac91a , FEATURE_ARITHMETIC
4290fec ATTENUATION_LOGARITHMIC
43c56f8 PATHFINDING_ALGORITHM_ASTAR
50e91c3 -4PTHMM
59ccc30 THM{GAME_MASTER_HACKER}
```

foremost でファイルカービングすると、GODOT Game Engine の PNGファイルが出てきた。

1. GDRETools で exe を開き、Extractする。  
https://github.com/GDRETools/gdsdecomp

2. Godot Engine で Extract したフォルダを開く。  
https://godotengine.org/download/windows/

3. 「2D」ビューを選択するとフラグが表示されていた。
