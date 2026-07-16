# Python

https://tryhackme.com/room/webframeworkspython

## Django

- DEBUG = True
- SECRET_KEY の漏洩

### ORM をすり抜けるSQLインジェクション

| 方法                      | その機能                                    | なぜ危険なのか                                                       |
| ----------------------- | --------------------------------------- | ------------------------------------------------------------- |
| `.extra(where=[...])`   | 生のSQLの`WHERE`句に断片を追加する。                 | この断片はクエリにそのまま追加されるため、`f`文字列などで入力値を直接埋め込むと、SQLインジェクションの原因となる。  |
| `.raw("...")`           | 手書きのSQL文字列を実行し、取得した行をモデルインスタンスにマッピングする。 | クエリ文字列を文字列フォーマットで組み立てると、入力値によってSQL文の内容が変化し、SQLインジェクションの原因となる。 |
| `cursor.execute("...")` | 生のデータベースカーソルを介して任意のSQLを実行する。            | `%`演算子や`f`文字列でSQL文を組み立てると、入力値が直接SQLに連結され、SQLインジェクションの原因となる。   |

## Flask

### セッション

```sh
flask-unsign --decode --cookie '<your session cookie>'
```

```sh
flask-unsign --sign --cookie "{'role': 'admin'}" --secret 'django-insecure-................'
```

## Flask, Jinja SSTI

```python
template = PAGE_HEAD + q + PAGE_TAIL
return render_template_string(template)
```
