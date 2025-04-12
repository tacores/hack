# tmux

https://tryhackme.com/room/rptmux

[チートシート](https://imgur.com/bL9Dn3U)

## 基本

- コンビネーションの最初のキーは必ず Ctrl + B（このファイルでは CBと表記する）
- Ctrl と B は、ターゲットキーを押す前に離す

```shell
# 無名でセッション開始
tmux

# 名前付きでセッション開始
tmux new -s <name>

# セッションを切断（デタッチ）
CB, D

# セッションをリスト表示
tmux ls

# セッションに接続（アタッチ）。無名の場合は 0 などが名前になる。
tmux a -t <session-name>
```

### コピーモード

```shell
# コピーモードに入る（画面に入りきらない出力を見るときなど）
CB, [

# コピーモードから出る
q
```

### ペイン

```shell
# 垂直分割
CB, %

# 水平分割
CB, "

# 分割したペイン間を移動
CB, 矢印キー

# CBを押しっぱなしにしながら矢印キーで、サイズ変更が可能
CB（Hold）, 矢印キー

# ペインをキル
CB, x
```

### Window

```shell
# 新しい Window をクリエイト
CB, C

# Window切り替え（Previous、Next）
CB, P
CB, N

# Window切り替え（Last Used）
CB, L

# Window切り替え（番号指定）
CB, 1

# Windowsを終了
exit
```
