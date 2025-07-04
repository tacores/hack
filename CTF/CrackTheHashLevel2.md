# Crack The Hash Level 2 CTF

https://tryhackme.com/room/crackthehashlevel2

## 1

```
John Neige @john
Hi, my name is John. I'm looking for a good advice to get a strong password. Usually I use the name of my son but I fear it's not secure enough.

Hacker @h4ck
You can use border mutation. It's commonly used, add a combination of digits and special symbols at the end or at the beginning, or both.
```

```
[List.Rules:task1_rule]
c $[0-9] $[0-9] $[0-9] $[0-9] $[!@#$%^&*]
c ^[!@#$%^&*] $[0-9] $[0-9] $[0-9] $[0-9] $[!@#$%^&*]
c ^[!@#$%^&*] $[0-9] $[0-9] $[0-9] $[!@#$%^&*]
c ^[!@#$%^&*] $[0-9] $[0-9] $[!@#$%^&*]
c ^[!@#$%^&*] $[0-9] $[!@#$%^&*]
```


```sh
$ sudo ./wordlistctl.py fetch -l malenames-usa-top1000 -d fetch_term

$ john hash.txt --format=Raw-MD5 --wordlist=/usr/share/wordlists/usernames/malenames-usa-top1000.txt -rules=task1_rule
```

## 2

```
Levy Tate @levy
Hi, my name is Levy. I'm looking for a good advice to get a strong password too. Usually I use the name of my daughter but I fear it's not secure too.

Hacker @h4ck
Like John, use border mutation.
```

```
[List.Rules:task2_rule]
c$[0-9]$[$%&*-_+=#@~!]
c$[0-9]$[0-9]$[$%&*-_+=#@~!]
c$[0-9]$[0-9]$[0-9]$[$%&*-_+=#@~!]
c$[0-9]$[0-9]$[0-9]$[0-9]$[$%&*-_+=#@~!]
```


```sh
john hash2.txt --format=Raw-MD5 --wordlist=/usr/share/wordlists/seclists/Usernames/Names/femalenames-usa-top1000.txt -rules=task2_rule
```


## 3

```
Charlotte Ofreize @charlotte
I'm Charlotte, 23 y/o. During my holidays in Mexico my professional account password expired. I need a new one, any idea?

Hacker @h4ck
Maybe pick a town you visited during your trip?

Charlotte Ofreize @charlotte
Good idea. But it's not matching my company's password policy.

Hacker @h4ck
Use freak/1337 mutation. Replace some letters with similarly looking special symbols.
```

```
[List.Rules:task3_rule]
sa@so0
```

```sh
# 失敗
/usr/share/wordlists/misc/towns_mx.dic

# 模範解答によるとcity-state-countryを使うが、wordlistctlでダウンロードできなかった。
cat /usr/share/wordlists/misc/city_state_country.txt | grep 'Mexico$' | sed 's/,.*//' | sed 's/\s//g' > ./mexico.txt
```

https://github.com/kkrypt0nn/wordlists/blob/main/wordlists/security_question_answers/city_state_country.txt からリストを入手。

```sh
john hash3.txt --format=Raw-MD5 --wordlist=./mexico.txt -rules=task3_rule
```

## 4

```
David Guettapan @david
Hi, I'm David, I'm a dj. But I also love rap. For example this, Eminem song: https://www.youtube.com/watch?v=sNPnbI1arSE

"Hi, my name is, what? My name is, who?"
I really love this song.

Hacker @h4ck
... What can I do for you? You need a password right?

David Guettapan @david
Yeah I'll use my awesome name.

Hacker @h4ck
That's too easy. Use case mutation, make variations of uppercase or lowercase letters for any character.
```

どの部分を使うか判然としないので、3行を names.txt に保存。
```
david
guettapan
davidguettapan
```

大文字小文字の全組み合わせを試す、既存のNTルール。

```sh
john hash4.txt --format=Raw-SHA1 --wordlist=./names.txt -rules=NT
```

## 5

```
Jack Pott @jack
I love Adele, the singer, such powerful lyrics, such beautiful songs ... anyway ...
Hi hacker, how can I strengthen my password?

Hacker @h4ck
Make it longer.

Jack Pott @jack
Yeah but it is already pretty long.

Hacker @h4ck
So just reverse the characters order.
```

長い名前を単に逆にしてみたが、ハズレ。ルールはこれしかないと思うが。

```
AdeleLaurieBlueAdkins
adelelaurieblueadkins
```

```
[List.Rules:task5_rule]
r
```

ヒントに [lyricpass](https://github.com/initstring/lyricpass) と書かれていた。  
しかし、エラーを返すばかりで機能していない。作者によると、スクレイピング防止のため取得できていないと思われるとのこと。進行不能のバグ。

```sh
$ python ./lyricpass.py -a "Adele"
[+] Looking up artist Adele
[+] Found 368 songs for artists Adele
Checking song 1/368...       
[!] Found no lyrics at https://www.lyrics.com/db-print.php?id=33851146
Checking song 1/368...       
```

## 6

```
Crystal Ball @crystal
Hi, I need an easily rememberable password.

Hacker @h4ck
Just pick your phone number! lol

Crystal Ball @crystal
Even if I'm from Sint Maarten?

Hacker @h4ck
Why not. lol
```

https://en.wikipedia.org/wiki/Area_code_721

Sint Maartenの電話番号は、1721の後に7桁。

```sh
seq -w 0 9999999 | sed 's/^/+1721/' > nums.txt

john hash6.txt --format=Raw-MD5 --wordlist=./nums.txt
```


## 7

```
Justin Thyme @justin
Hi, I have a common password that I want to keep, I need a stronger way to store it than MD5.

Hacker @h4ck
Take a look at the last Competition Project of NIST.

Justin Thyme @justin
SHA1?

Hacker @h4ck
NO! lol lel kek keccak topkek
```

keccak は SHA3-512。

```sh
john hash7.txt --format=Raw-SHA3 --wordlist=/usr/share/wordlists/rockyou.txt
```

## 8

※ here で http://10.10.68.130/rtfm.re/en/sponsors/index.html にリンクされている。

```
Robyn Banks @robyn
Hi hacker, we need a true military grade password.

Hacker @h4ck
Hey Robyn, sure yeah! Let's start by randomly picking a word here. Then let's repeat 2, 3, 4 or maybe 5 times so it will be longer. Finally let's pick a hardcore cryptographic hash function.

Robyn Banks @robyn
Yeah yeah yeah, I like it. Like a finalist of SHA-3 project. But one that is used by PHC winner KDF.

Hacker @h4ck
Yeah good choice, plus it will be handy as it is included in GNU core utilities. Wow even WireGuard use it.
```

```
[List.Rules:task8_rule]
d
dd
ddd
dddd
```

```sh
cewl -d 5 -w ./cewl.txt http://10.10.68.130/rtfm.re/en/sponsors/index.html

john hash8.txt --format=Raw-Blake2 --wordlist=./cewl.txt -rules=task8_rule
```

## 9

```
Warren Peace @warren
Why are you spreading your stupid mutations? Strong hash + salt is enought.

Hacker @h4ck
Wow that's rude. Let's see if I can hack you.
```

これは明らかに hashcat が妥当。

```sh
.\hashcat.exe -m 1800 hash.txt rockyou.txt
```

## 振り返り

- 勉強になった。外部環境に依存しすぎて一部壊れているのは残念。
- john のルールについて、まだまだ理解できていないことが大半という実感。