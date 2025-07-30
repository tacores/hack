# tmux

https://tryhackme.com/room/rptmux

https://tryhackme.com/room/tmuxremux

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
tmux attach -t <session-name>

# セッションを削除
tmux kill-session -t <session-name>

# 指定したセッションを除くすべてのセッションを削除
tmux kill-session -t <session-name> -a
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

# ペイン番号を表示
CB, q

# ペインを入れ替え
:swap-pane -s <num> -t <num>
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

# 名前変更
CB, ,

# ペインを切り離して別のWindowに
CB, Shift !

# Windowsを終了
exit
```

### セッション

```sh
# セッションの名前変更
CB, Shift+$

# 別のセッションを作成
tmux -s new tryhackme -d

# セッションを終了せずにtmuxを終了する
CB, d

# セッションの切り替え
CB, s

# 開始ディレクトリを指定
Ctrl + B Shift + :
attach -c /path/to/new/starting/directory
```
