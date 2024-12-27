# Frida

https://frida.re/docs/quickstart/

### install

```shell
sudo pip install frida-tools
```

### ハンドラーファイル作成

```shell
frida-trace ./main -i '*'
```

```shell
frida-trace ./main -i 'libtarget.so!*'
```

### 引数を調べる

```js
Interceptor.attach(Module.findExportByName("libtarget.so", "target_function"), {
  onEnter: function (args) {
    console.log("[*] target_function called");

    // 最大10個表示する
    for (var i = 0; i < 10; i++) {
      try {
        console.log("arg[" + i + "]: " + args[i].toInt32());
      } catch (e) {
        console.log("arg[" + i + "]: out of range");
        break;
      }
    }

    // 値が大きいときは文字列のポインタかも？
    log("PARAMETER:" + Memory.readCString(args[0]));

    // 変数を改ざん
    args[1] = ptr(0);
  },
  onLeave: function (retval) {
    log("retval:" + retval);

    // 戻り値を改ざん
    retval.replace(ptr(1));
  },
});
```
