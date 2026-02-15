# hashclash

https://github.com/cr-marcstevens/hashclash

リリースバイナリがあるのでそれを使うのが楽。

https://github.com/cr-marcstevens/hashclash/releases/tag/hashclash-static-release-v1.2b

共通のPrefixを持ち、共通のMD5ハッシュを持つ異なる2つのファイルを生成する。

```sh
$ echo GIF87a > prefix

$ ./scripts/poc_no.sh prefix

$ md5sum ./collision1.bin                                    
eb3e08807d0f8d166986a5b2790c387b  ./collision1.bin

$ md5sum ./collision2.bin 
eb3e08807d0f8d166986a5b2790c387b  ./collision2.bin

$ diff ./collision1.bin ./collision2.bin 
Binary files ./collision1.bin and ./collision2.bin differ
```
