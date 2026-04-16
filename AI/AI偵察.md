# AI偵察

https://tryhackme.com/room/aisystemreconnaissance

## ポート

### 各AIサービスのポート

| サービス                         | ポート | API/用途                         |
|----------------------------------|--------|----------------------------------|
| NVIDIA Triton Inference Server   | 8000   | HTTP 推論API                     |
| NVIDIA Triton Inference Server   | 8001   | gRPC 推論API                     |
| NVIDIA Triton Inference Server   | 8002   | Prometheus メトリクス            |
| TensorFlow Serving               | 8500   | gRPC 推論API                     |
| TensorFlow Serving               | 8501   | HTTP 推論API                     |
| TorchServe                       | 8080   | 推論API                          |
| TorchServe                       | 8081   | 管理API                          |
| TorchServe                       | 8082   | メトリクス                       |
| Ollama                           | 11434  | OpenAI互換 API（LLM推論）        |
| vLLM                             | 8000   | OpenAI互換 API（LLM推論）        |

### オーケストレーション

| サービス                  | ポート | API/用途                                      |
|---------------------------|--------|-----------------------------------------------|
| MLflow Tracking Server    | 5000   | 実験追跡API（メトリクス・パラメータ・成果物管理） |
| Kubeflow                  | 80     | HTTP（パイプライン・Notebook・デプロイ管理）   |
| Kubeflow                  | 443    | HTTPS（パイプライン・Notebook・デプロイ管理）  |
| Ray                       | 8265   | ダッシュボード                                |
| Ray                       | 8000   | サーバーAPI（分散処理・推論など）              |

### ベクターデータベース

| サービス   | ポート | API/用途                         |
|------------|--------|----------------------------------|
| Qdrant     | 6333   | HTTP API                         |
| Qdrant     | 6334   | gRPC API                         |
| Weaviate   | 8080   | HTTP / GraphQL API               |
| Milvus     | 19530  | gRPC API                         |
| Chroma     | 8000   | HTTP API                         |

### サポートインフラ

| サービス                     | ポート | API/用途                                               |
|------------------------------|--------|--------------------------------------------------------|
| Jupyter Notebook             | 8888   | Web UI / ノートブック実行（ターミナルアクセス含む）     |
| MinIO                        | 9000   | S3互換 API（オブジェクトストレージ）                   |
| MinIO                        | 9001   | 管理コンソール（Web UI）                               |
| Triton Inference Server      | 8002   | Prometheus メトリクス                                  |
| TorchServe                   | 8082   | メトリクス                                             |
| Prometheus メトリクスエンドポイント | 各種   | モデル情報・GPU使用率・レイテンシなどの可視化           |

### まとめ

| Component | Default Port(s) | Protocol(s) | Recon Endpoints | 説明 |
|-----------|----------------|-------------|------------------|------|
| NVIDIA Triton | 8000, 8001, 8002 | HTTP, gRPC, Prometheus | /v2/health/ready, /v2/models | モデルをメモリにロードし、大規模に推論を提供するサーバー |
| TensorFlow Serving | 8500, 8501 | gRPC, HTTP | /v1/models/<name> | TensorFlowモデル用のGoogle製サービングフレームワーク |
| TorchServe | 8080, 8081, 8082 | HTTP | /ping, /models | PyTorch公式のモデルサービングフレームワーク |
| Ollama | 11434 | HTTP | /api/tags, /api/show | ローカル環境でLLMを実行するためのランタイム |
| vLLM | 8000 | HTTP | /v1/models | OpenAI互換APIを持つ高スループットなLLMサービングエンジン |
| MLflow | 5000 | HTTP | /api/2.0/mlflow/experiments/search | 実験追跡・モデル保存・MLライフサイクル管理ツール |
| Kubeflow | 80, 443 | HTTP | /pipeline/apis/v1beta1/pipelines | Kubernetes上でMLパイプラインを管理・実行するプラットフォーム |
| Ray | 8265, 8000 | HTTP | /api/jobs/, Ray Dashboard | AIワークロードをスケールさせる分散コンピューティング基盤 |
| Qdrant | 6333, 6334 | HTTP, gRPC | /collections | セマンティック検索やRAG向けのベクトルデータベース |
| Weaviate | 8080 | HTTP, GraphQL | /v1/schema, /v1/meta | GraphQLなどを備えたベクトルデータベース |
| Milvus | 19530 | gRPC | Port 19530 connection | 大規模埋め込みデータを扱う分散型ベクトルデータベース |
| Jupyter Notebook | 8888 | HTTP | /api/kernels, /api/contents | データサイエンティスト向けの対話型開発環境 |
| MinIO | 9000, 9001 | HTTP (S3-compatible) | Bucket listing | モデル成果物などを保存するS3互換オブジェクトストレージ |
| Prometheus metrics | 8002, 8082 | HTTP | /metrics | 各種MLサーバーが提供する監視用メトリクスエンドポイント |

## フィンガープリンティング

### HTTPヘッダー

| 判別対象                     | ヘッダー / 特徴                              | 判別ポイント                         |
|------------------------------|-----------------------------------------------|----------------------------------------------|
| TorchServe                   | Server: TorchServe/0.x.x                      | サーバーヘッダーで一意に特定可能             |
| Triton Inference Server      | NV-Status ヘッダー                            | 固有ヘッダーで識別                           |
| Triton Inference Server      | endpoint-load-metrics-format: text（リクエスト） | GPU/CPU使用率がヘッダーに返る（Triton特有）  |
| FastAPI系MLサービス          | server: uvicorn                               | Python製バックエンドの可能性が高い           |
| FastAPI系MLサービス          | /predict, /embeddings                         | ML推論APIの典型パス                          |
| OpenAI互換API（vLLM等）      | x-request-id ヘッダー                          | OpenAI系ラッパーの特徴                        |
| OpenAI互換API（vLLM等）      | /v1/models のJSON "object": "model"           | OpenAI互換フォーマット                        |

### APIレスポンスシグネチャ

| 判別対象                     | レスポンス例 / 特徴                                              | 判別ポイント                          |
|------------------------------|------------------------------------------------------------------|-----------------------------------------------|
| TensorFlow Serving           | {"model_version_status": [...]}                                  | model_version_status フィールドが特徴          |
| Triton Inference Server      | {"name": "...", "versions": [...], "platform": "..."}            | name / versions / platform 構造               |
| MLflow                       | エラーレスポンスに mlflow.server / mlflow.tracking が含まれる    | スタックトレースで特定可能                    |
| OpenAI互換API（vLLM等）      | {"object": "model", "id": "...", "created": ...}                 | "object": "model" でOpenAI互換と判別可能       |

### エラーメッセージ

| 判別対象                         | エラー例 / 特徴                                         | 判別ポイント                          |
|----------------------------------|----------------------------------------------------------|-----------------------------------------------|
| TensorFlow Serving               | tensorinfo_map を含むエラー                              | TF Serving特有の内部構造が露出                |
| MLflow                           | mlflow.server / mlflow.tracking を含むスタックトレース   | 名前空間で特定可能                            |
| MLflow（脆弱性例）               | ファイルパスが露出（CVE-2024-1558）                      | サーバーの実パスが判明                        |
| Databricks Mosaic AI             | io.jsonwebtoken.IncorrectClaimException                  | Java例外クラス名で即判別                      |
| 共通（AI推論API全般）            | 詳細で冗長なエラーメッセージ                            | デバッグ情報過多＝フィンガープリントしやすい  |

### エンドポイント命名規則

| カテゴリ             | パス例                                      | 判別ポイント                          |
|----------------------|---------------------------------------------|-----------------------------------------------|
| 推論API              | /predict, /invocations, /infer, /generate, /embeddings, /score | 動詞ベース＝AI特有のエンドポイント            |
| モデル管理API        | /v1/models, /v2/models                      | モデル一覧・管理系API                         |
| MLflow               | /api/2.0/mlflow/                            | 他に出ない固有プレフィックス                  |
| Kubeflow             | /pipeline/apis/v1beta1/                     | パイプライン管理APIの典型パス                |
| 共通（探索手法）     | ffuf / feroxbuster + 専用ワードリスト       | 通常のSecListsには含まれない                  |

### gRPC

| 判別対象                     | ポート / ツール              | 特徴 / コマンド例                                      | 判別ポイント（簡潔）                          |
|------------------------------|------------------------------|--------------------------------------------------------|-----------------------------------------------|
| Triton Inference Server      | 8001                         | gRPC                                                   | HTTPでは見えないgRPCエンドポイント            |
| TensorFlow Serving           | 8500                         | gRPC                                                   | 同様にgRPCで推論APIを公開                     |
| gRPC共通                     | grpcurl                      | grpcurl -plaintext target:PORT list                    | サービス一覧を取得可能                        |
| gRPC共通                     | grpcurl                      | grpcurl -plaintext target:PORT describe <Service>      | RPC・スキーマ詳細を取得                       |
| gRPC（リフレクション有効時） | -                            | protobufスキーマ取得                                   | 入出力構造まで完全に把握可能                  |
| RESTとの違い                 | -                            | バイナリプロトコル                                     | HTTPスキャナでは検出不可                      |
| 対応関係（参考）             | -                            | /openapi.json（REST）相当                              | API仕様を丸ごと取得できる                     |

grpcurl (https://github.com/fullstorydev/grpcurl)

```sh
grpcurl -plaintext target:8001 list
grpcurl -plaintext target:8001 describe inference.GRPCInferenceService
```

### TLS（JA3/JA4）

| 判別対象                     | 手法 / 指標        | 特徴                                                  | 判別ポイント                          |
|------------------------------|--------------------|-------------------------------------------------------|-----------------------------------------------|
| TLSフィンガープリント        | JA3 / JA4          | TLSハンドシェイクのハッシュ解析                       | 通信クライアントの種類を識別可能              |
| AIサービス通信               | Python系ライブラリ | requests / urllib / gRPC 由来の通信                   | ブラウザ通信と異なるシグネチャ                |
| 攻撃トラフィック検知         | JA4H               | 複数IPでも同一ハッシュが出現                          | 自動化ツール由来の可能性が高い                |
| 事例（GreyNoise）            | JA4H一致率99%      | 62 IP・27カ国でも同一シグネチャ                       | 共通ツールによる攻撃と特定可能                |
| ネットワークレベル識別       | -                  | 人間操作 vs 自動化トラフィックの区別                  | MLパイプライン由来通信を識別可能              |

## AIシステム列挙

### MLflow

```sh
# 全実験名を列挙
POST /api/2.0/mlflow/experiments/search

# 登録済のモデルを一覧表示
GET /api/2.0/mlflow/registered-models/list

# モデルのバージョン詳細を取得
GET /api/2.0/mlflow/model-versions/search

# トレーニングプランを検索
POST /api/2.0/mlflow/runs/search

# ダウンロード可能な成果物を一覧表示
GET /api/2.0/mlflow/artifacts/list
```

### 推論サーバーメタデータ

データベースのスキーマ全体を取得するのと同等

#### Triton

```sh
GET /v2/models/<name>/config
```

#### TensorFlow Serving

```sh
GET /v1/models/<name>/metadata
```

### ベクトルデータベース

ベクトルデータベースは、AIシステムがどのようなデータを扱っているか、そしてどの埋め込みモデルがそれを処理しているかを明らかにする。

#### Weaviate

```sh
# サーバーのバージョンとインストールされているモジュール
GET /v1/meta

# プロパティ名やベクトル化モジュールの設定など、すべてのクラス定義
GET /v1/schema

# 認証されていないインスタンスでも完全なスキーマの内省とデータクエリを実行できる
GET /v1/graphql
```

#### Qdrant

```sh
# すべてのコレクション名一覧
GET /collections

# ベクトルの次元、距離指標、および総点数
GET /collections/<name>
```

#### Chroma

```sh
# 古いバージョンではデフォルトで認証無しで公開される
GET /api/v1/collections
```

### プロメテウス・メトリクスをインテリジェンスとして活用

モデルサーバーは多くの場合、/metrics 専用ポート（Tritonは8002、TorchServeは8082）で公開される。

- 現在読み込まれているモデル名とバージョン番号
- 推論リクエスト数とレイテンシのパーセンタイル
- 処理中のバッチサイズ
- モデルごとのGPUメモリ使用量

### デバッグインターフェースと情報漏洩

| 対象                     | エンドポイント / 手法        | 漏えい内容                          |
|--------------------------|-----------------------------|---------------------------------------------|
| FastAPI系MLサービス      | /docs, /openapi.json        | API仕様・認証要件・リクエスト例             |
| MLflow                   | /graphql                    | 実験情報・ユーザー名・ソースコードパス      |
| MLflow                   | mlflowSearchRuns など       | 実行履歴・プロジェクト構成                  |
| AIゲートウェイ全般       | ?debug=true / ?verbose=1    | スタックトレース・ファイルパス・ライブラリ情報 |
| 共通リスク               | -                           | 認証回避・内部情報の過剰露出                |

### Jupyter Notebook

認証されていない Jupyter インスタンスでは、実行中のカーネルの名前、カーネル ID、および最後のアクティビティ タイムスタンプが返される。

```sh
GET /api/kernels
```

また、セルの中にアクセスキーなどをハードコーディングしている場合がよくある。  
MLflow (MLFLOW_TRACKING_USERNAME, MLFLOW_TRACKING_PASSWORD) 等

```sh
curl http://10.10.45.20:8888/api/contents

{"content":[{"name":"fraud_model_training.ipynb","type":"notebook","last_modified":"2024-01-15T14:32:00Z"},{"name":"rag_pipeline_debug.ipynb","type":"notebook","last_modified":"2024-01-15T16:45:00Z"},{"name":"data_exploration.ipynb","type":"notebook","last_modified":"2024-01-10T09:15:00Z"}]}
```

```sh
curl http://10.10.45.20:8888/rag_pipeline_debug.ipynb

Cell 1: import qdrant_client  
Cell 2: from sentence_transformers import SentenceTransformer  
Cell 3:  
import mlflow, os  
mlflow.set_tracking_uri("http://10.10.45.12:5000")  
os.environ["MLFLOW_TRACKING_USERNAME"]="ml-service-account"  
os.environ["MLFLOW_TRACKING_PASSWORD"]="[REDACTED]"  
os.environ["HF_TOKEN"]="hf_kR7mXpQv[REDACTED]"  
Cell 4:  
import boto3  
s3=boto3.client('s3',aws_access_key_id='AKIA3Cyp[REDACTED]',aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/[REDACTED]')
```

