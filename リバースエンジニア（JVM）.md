# リバースエンジニア（JVM）

https://tryhackme.com/room/jvmreverseengineering

バイトコード  
https://en.wikipedia.org/wiki/Java_bytecode_instruction_listings

記述子の詳細  
https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3

```sh
javap -v -p HelloWorld.class
```

## 高度な解析

### ASM

https://asm.ow2.io/

バイトコードを操作するための強力なオープンソースライブラリ

### deobfuscator

https://github.com/java-deobfuscator/deobfuscator

ASM を用いて一般的な難読化を解除することを目的としたオープンソースプロジェクト

detect.yml

```yaml
input: input.jar
detect: true
```

```sh
java -jar /home/kali/tools/deobfuscator.jar --config detect.yml
```

config.yml

```yaml
input: input.jar
output: output.jar
transformers:
  - [fully-qualified-name-of-transformer]
  - [fully-qualified-name-of-transformer]
  - [fully-qualified-name-of-transformer]
  - ... etc
```

```sh
java -jar /home/kali/tools/deobfuscator.jar
```

### ghidra

結局これが一番簡単かもしれない。



## リフレクション

main関数呼び出しは一見必要ないようだが、main関数を呼ぶことでクラスの初期化処理が実行されるため必要。

```java
public class aaa {

    public static void main(String[] args) throws Exception {
    	Class<?> cls0 = Class.forName("0");
        Class<?> cls1 = Class.forName("1");
        
        java.lang.reflect.Method methodMain = cls0.getMethod("main", String[].class);
        methodMain.invoke(null, (Object) new String[] {""} );
        
        java.lang.reflect.Method methodA = cls1.getMethod("a", int.class, int.class);
        String result = (String)methodA.invoke(cls1, 1, 0x5f);
        java.lang.reflect.Method methodC = cls0.getMethod("c", String.class);
        String finalResult = (String)methodC.invoke(cls0, result);
        System.out.println("Result: " + finalResult);
    }
}
```