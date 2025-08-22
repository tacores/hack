# リバースエンジニア（JVM）

https://tryhackme.com/room/jvmreverseengineering

バイトコード  
https://en.wikipedia.org/wiki/Java_bytecode_instruction_listings

記述子の詳細  
https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3

```sh
javap -v -p HelloWorld.class
```

## 高度な

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
