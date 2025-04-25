# CVE

## CVE-2025-32433

https://github.com/ProDefense/CVE-2025-32433/blob/main/CVE-2025-32433.py

- Erlang/OTP SSH
- 修正：OTP-27.3.3, OTP-26.2.5.11, or OTP-25.3.2.20.
- 認証情報不要

上記 URL の PoC は無害なファイルを作るだけ。

```
file:write_file("/lab.txt", <<"pwned">>)
```
