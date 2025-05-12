# GraphQL

https://tryhackme.com/room/introtographqlhacking

## 基本

### GraphQL の主要コンポーネント

- スキーマ： API の設計図。すべてのデータ型、フィールド、そしてそれらの関係を定義します。クライアントとサーバー間の契約書と考えてください。
- クエリ：データの取得に使用されます。クライアントは特定のフィールドを要求するため、従来の API 呼び出しよりも効率的です。
- ミューテーション：データを変更するために使用されます。レコードの作成、更新、削除などのアクションを処理します。
- クエリの形式は「GraphQL Query Language」で、レスポンスは JSON。
- クエリを JSON の中に入れて送るのが一般的。

```json
{
  "query": "{ user(id: \"1\") { id name } }",
  "variables": null,
  "operationName": null
}
```

#### クエリの例

```json
{
  user(id: "123") {
    name
    email
  }
}
```

```json
{
  "data": {
    "user": {
      "name": "John Doe",
      "email": "john@example.com"
    }
  }
}
```

#### ミューテーションの例

```json
mutation {
  updateUser(id: "123", name: "Jane Doe") {
    id
    name
  }
}
```

```json
{
  "data": {
    "updateUser": {
      "id": "123",
      "name": "Jane Doe"
    }
  }
}
```

### ネストされたクエリ

id=123 のユーザーを取得、ユーザーに紐づくポストを取得、ポストに紐づくコメントを取得

```json
{
  user(id: "123") {
    name
    posts {
      title
      comments {
        text
        author {
          name
        }
      }
    }
  }
}
```

```json
{
  "data": {
    "user": {
      "name": "John Doe",
      "posts": [
        {
          "title": "GraphQL Basics",
          "comments": [
            {
              "text": "Great article!",
              "author": {
                "name": "Jane Doe"
              }
            }
          ]
        },
        {
          "title": "Advanced GraphQL Techniques",
          "comments": [
            {
              "text": "Very informative!",
              "author": {
                "name": "Bob Smith"
              }
            }
          ]
        }
      ]
    }
  }
}
```

### フラグメント

... はフラグメントを展開する記号

```json
fragment UserDetails on User {
  name
  email
}

{
  user(id: "123") {
    ...UserDetails
    posts {
      title
    }
  }
}
```

## エンドポイントの検索

### トラフィックの分析

- graphql, query, mutation を含む POST, GET

### Javascript ファイルの検索

- graphql, mutation 等の用語

### 一般的なエンドポイント名のテスト

- /graphql
- /api/graphql
- /v1/graphql
- /gql
- SecLists/Discovery/Web-Content/graphql.txt でファジング

## 一般的な脆弱性

### 過剰なデータ露出

```json
{
  user(id: "1") {
    id
    username
    email
    password
    is_admin
  }
}
```

### SQL インジェクション攻撃

```javascript
const resolvers = {
  Query: {
    user: (_, { id }) => database.query(`SELECT * FROM users WHERE id = ${id}`),
  },
};
```

```json
{
  user(id: "1; DROP TABLE users; --") {
    name
  }
}
```

### 複雑なクエリによる DoS

深いネスト

```json
{
  user(id: "123") {
    friends {
      friends {
        friends {
          name
        }
      }
    }
  }
}
```

バッチクエリ

```json
{
  user1: user(id: "1") { name }
  user2: user(id: "2") { name }
  user3: user(id: "3") { name }
  // Repeat for hundreds or thousands of users
}
```

## イントロスペクション

イントロスペクションは、クライアントがスキーマ自体をクエリできる機能。

API がサポートするすべての型とそのフィールドのリストを返すように要求

```yaml
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

より詳細

```
query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description args { ...InputValue } locations } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
```

スキーマを取得したら、https://graphql-kit.com/graphql-voyager/ でグラフィカルにマッピングできる。

## セキュリティ保護

### 本番環境では、イントロスペクションを無効にする

```javascript
const { ApolloServer } = require("apollo-server");

const server = new ApolloServer({
  schema,
  introspection: false, // Turns introspection off
});
```

特定のユーザー（開発者など）に対してイントロスペクションが必要な場合は、アクセスルールを作成して、承認されたロールのみにイントロスペクションを許可することができる。

### ロールベースのアクセス制御

### エラーメッセージで過剰な情報を表示しない

### クエリの深さと複雑さを制限する

深さを制限

```javascript
const { depthLimit } = require("graphql-depth-limit");

const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(5)], // Stops queries deeper than 5 levels
});
```

複雑さを制限

```javascript
const { createComplexityLimitRule } = require("graphql-validation-complexity");

const complexityRule = createComplexityLimitRule(1000); // Stops queries with a score over 1000

const server = new ApolloServer({
  schema,
  validationRules: [complexityRule],
});
```

### 入力にパラメータ化されたクエリを使用する

```javascript
const query = username
  ? `SELECT * FROM users WHERE username = ?`
  : `SELECT * FROM users`;

const [rows] = await connection.execute(query, username ? [username] : []);
```
