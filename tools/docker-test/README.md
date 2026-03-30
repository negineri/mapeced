# mapeced 特権統合テスト用 Docker 環境

root に Rust がインストールされていない環境で、`CAP_NET_ADMIN` を必要とする統合テストを実行するための Docker 環境です。

## 前提

- Docker がインストールされていること
- Docker デーモンが実行中であること（`docker info` で確認）

## 使い方

### すべての統合テスト（Phase 2–4）を実行

```bash
./tools/docker-test/run-tests.sh
```

### テスト種別を指定して実行

```bash
# Netlink テストのみ（Phase 2）
./tools/docker-test/run-tests.sh netlink

# nftables / tc テストのみ（Phase 3）
./tools/docker-test/run-tests.sh nftables

# ライフサイクルテストのみ（Phase 4）
./tools/docker-test/run-tests.sh lifecycle

# ユニットテスト + 非特権統合テスト（Phase 1）
./tools/docker-test/run-tests.sh unit

# 複数指定
./tools/docker-test/run-tests.sh netlink lifecycle
```

### イメージを強制再ビルドして実行

```bash
./tools/docker-test/run-tests.sh --build
```

## Docker イメージの内容

| ソフトウェア | バージョン |
|---|---|
| ベースイメージ | Ubuntu 24.04 |
| Rust | stable（rustup によるインストール） |
| iproute2 (`ip`, `tc`) | Ubuntu パッケージ |
| nftables (`nft`) | Ubuntu パッケージ |

## 仕組み

```
ホスト（非 root）
  └── docker run --privileged
        ├── ソースコードをリードオンリーマウント（/workspace）
        ├── Cargo レジストリキャッシュをボリュームマウント（再ビルド短縮）
        ├── target/ ディレクトリは tmpfs（高速 I/O）
        └── cargo test --test-threads=1 で直列実行
```

`--privileged` フラグにより、コンテナ内で `ip netns add` などのネットワーク名前空間操作が可能になります。
各テストは独立した名前空間内で実行され、ホストのネットワーク設定には影響しません。

## キャッシュについて

Cargo のレジストリキャッシュは `mapeced-cargo-cache` という Docker ボリュームに保存されます。
初回は依存クレートのコンパイルに時間がかかりますが、2 回目以降はキャッシュが再利用されます。

```bash
# キャッシュを削除してクリーンビルドする場合
docker volume rm mapeced-cargo-cache
./tools/docker-test/run-tests.sh --build
```
