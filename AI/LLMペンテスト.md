# LLMペンテスト

https://tryhackme.com/room/llmpentesting

## tools

### Garak

NVIDIAのGitHubでメンテナンスされているオープンソースのLLM脆弱性スキャナー

```sh
pip install garak

python3 -m garak --model_type ollama \
  --model_name llama3:8b \
  --probes dan.DAN_Jailbreak

python3 -m garak --model_type ollama \
  --model_name llama3:8b \
  --probes dan
```

### PyRIT

マイクロソフトが開発した生成型AI向けのオープンソースのレッドチームフレームワーク

```sh
pip install pyrit
```

### promptfoo

LLMテストおよびレッドチーム演習用のCLIツール

```sh
npm install -g promptfoo

promptfoo redteam run
```
