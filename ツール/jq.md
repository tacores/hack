# jq

JSON query ツール

[cheetsheet](https://gist.github.com/olih/f7437fb6962fb3ee9fe95bda8d2c8fa4)

練習用ファイルを作成

```sh
$ cat << 'EOF' > sample.json
{
  "company": "TechCorp",
  "updated_at": "2026-08-01",
  "members": [
    {
      "id": 1,
      "name": "Tanaka",
      "age": 28,
      "role": "Developer",
      "skills": ["Python", "Go", "Docker"],
      "active": true
    },
    { 
      "id": 2,
      "name": "Suzuki",
      "age": 35,
      "role": "Manager",
      "skills": ["Management", "Agile"],
      "active": true
    },
    { 
      "id": 3,
      "name": "Sato",
      "age": 24,
      "role": "Developer",
      "skills": ["JavaScript", "React", "TypeScript"],
      "active": false
    },
    { 
      "id": 4,
      "name": "Takahashi",
      "age": 42,
      "role": "Designer",
      "skills": ["Figma", "UI/UX"],
      "active": true
    }
  ]  
}
EOF
```

## 基本

会社名（company の値）だけを文字列で抽出

```sh
jq '.company' ./sample.json
```

members 配列の先頭だけを取り出す

```sh
jq '.members[0]' ./sample.json
```

全メンバーの name だけを一覧（改行区切り）で抽出

```sh
jq '.members[].name' ./sample.json
```

## フィルタリング、条件抽出

在籍中（active が true）のメンバーだけを取り出す

```sh
jq '.members[] | select(.active == true)' ./sample.json
# or
jq '.members[] | select(.active)' ./sample.json
```

30歳以上のメンバーの「名前」と「年齢」だけを抽出

```sh
jq '.members[] | select(.age >= 30) | {name: .name, age: .age}' ./sample.json
# or 
jq '.members[] | select(.age >= 30) | {name, age}' ./sample.json
```

スキルに Docker を持っているメンバーの「名前」を抽出

```sh
jq '.members[] | select(.skills | contains(["Docker"])) | .name' ./sample.json
# or
jq '.members[] | select(.skills | index("Docker")) | .name' ./sample.json
# or
jq '.members[] | select(.skills[] == "Docker") | .name' ./sample.json
```

## データ加工・整形

メンバー全員の「名前」と「役割」のペアを持つ新しいオブジェクトの配列を作成。

期待する出力形式: `[{"name": "Tanaka", "role": "Developer"}, ...]`

```sh
jq '[.members[] | {name: .name, role: .role}]' ./sample.json
```

在籍中（active が true）のメンバーの「平均年齢」を計算して出力

```sh
# add は合計、length は配列の要素数
jq '[.members[] | select(.active == true).age] | add / length' ./sample.json
35
```
