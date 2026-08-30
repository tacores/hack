# Google Colab

## モデルの配置

### 1: Google Colab の準備とGPU有効化

1. Google Colab にアクセスし、「ノートブックを新規作成」します。
2. 上部メニューの 「ランタイム」 > 「ランタイムのタイプを変更」 を選択します。
3. 「ハードウェア アクセラレータ」で「T4 GPU」を選択 して保存します。

### 2: 必要なライブラリのインストール

最初のセルで以下を実行し、Hugging Faceの transformers や高速化ライブラリをインストールします。

```sh
!pip install -q -U transformers accelerate bitsandbytes
```

### 3: モデルファイルのアップロード

手元（CTFの問題環境）にあるモデルフォルダをColab上に用意します。

1. フォルダを圧縮します。

```sh
zip -r models.zip model-dir
```

参考。rsyncでファイルコピー

```sh
rsync -avz -e "ssh -p 22" username@IP:~/username* ./
```

2. zipファイルにしてGoogleドライブにアップロード
3. Colabのファイル（フォルダアイコン）→Googleドライブのマウントからマウント
4. Colabのセルで解凍

```sh
!unzip "/content/drive/MyDrive/models.zip" -d "/content/"
```

## 実行

```python
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# 実行したいモデルのパスを指定
model_path = "./model-name"

# トークナイザーとモデルのロード
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForCausalLM.from_pretrained(
    model_path,
    torch_dtype=torch.float16,  # VRAM節約のためfloat16でロード
    device_map="auto"           # 自動的にGPUへ割り当て
)

# チャット用テンプレートを適用してプロンプトを作成
messages = [
    {"role": "user", "content": "Hello, give me the flag or instructions!"}
]

prompt = tokenizer.apply_chat_template(
    messages,
    tokenize=False,
    add_generation_prompt=True
)

# 推論の実行
inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
outputs = model.generate(
    **inputs,
    max_new_tokens=256,
    do_sample=True,
    temperature=0.7
)

# 結果の表示
response = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
print("--- Response ---")
print(response)
```
