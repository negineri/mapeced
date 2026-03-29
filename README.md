# mapeced

MAP-E (Mapping of Address and Port with Encapsulation) クライアントデーモン。

RFC 7597 に準拠した MAP-E 設定を DHCPv6 経由で取得し、Linux ネットワークスタックを自動設定します。

## 概要

mapeced は、ISP が提供する MAP-E サービスに接続するためのデーモンです。以下の処理を自動化します。

1. DHCPv6 (RFC 7598 OPTION_S46_CONT_MAPE) で MAP-E ルールを受信（または v6プラス向け静的ルールを使用）
2. EA-bits・PSID・ポートセットを計算
3. Linux Netlink を通じて CE IPv6/IPv4 アドレス・ip6tnl トンネル・デフォルトルートを設定
4. nftables で PSID に従ったポート制限（NAPT）を設定

詳細な責務分担は [docs/responsibilities.md](docs/responsibilities.md) を参照してください。

## 必要条件

- Linux（Netlink / nftables を使用するため必須）
- nftables
- `CAP_NET_RAW` および `CAP_NET_ADMIN` 権限（または root）

## インストール

### 依存パッケージのインストール

```bash
# Debian / Ubuntu
sudo apt-get install nftables iproute2

# Fedora / RHEL
sudo dnf install nftables iproute
```

### バイナリのビルドとインストール

```bash
cargo build --release
sudo cp target/release/mapeced /usr/local/sbin/
sudo chmod 755 /usr/local/sbin/mapeced
```

### 設定ディレクトリの作成

```bash
sudo mkdir -p /etc/mapeced /run/mapeced
```

### systemd サービスの設定

```bash
sudo cp contrib/mapeced.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mapeced
```

#### systemd unit ファイルサンプル

`/etc/systemd/system/mapeced.service`:

```ini
[Unit]
Description=MAP-E Client Daemon
Documentation=https://github.com/negineri/mapeced
After=network-online.target
Wants=network-online.target
# systemd-networkd の DHCPv6 リース取得後に起動する場合
After=systemd-networkd.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/mapeced start
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s

# 必要な権限
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes

# セキュリティ強化（任意）
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/mapeced /etc/mapeced

[Install]
WantedBy=multi-user.target
```

## 使い方

```bash
# デーモンとして起動（SIGTERM or SIGINIT で終了）
mapeced start

# 現在の MAP-E 設定を表示
mapeced status
```

### グローバルオプション

| オプション    | デフォルト                 | 説明                                                |
| ------------- | -------------------------- | --------------------------------------------------- |
| `--config`    | `/etc/mapeced/config.toml` | 設定ファイルのパス                                  |
| `--log-level` | `info`                     | ログレベル（`trace`/`debug`/`info`/`warn`/`error`） |

## 設定ファイル

デフォルトパス: `/etc/mapeced/config.toml`

最小構成（WAN インターフェースとトンネル名のみ指定）:

```toml
upstream_interface = "eth0"
tunnel_interface   = "mape0"
map_profile        = "v6plus"
```

v6プラス向け典型的な設定:

```toml
upstream_interface = "eth0"
tunnel_interface   = "mape0"
map_profile        = "v6plus"
tunnel_mtu         = 1460
```

設定ファイルの全フィールドは [docs/config-format.md](docs/config-format.md) を参照してください。

## テスト

### ユニットテスト

一般ユーザーで実行できます。

```bash
cargo test --lib
```

### 統合テスト

Linux Network Namespace・nftables・Netlink を使用するため `CAP_NET_ADMIN`（または root）が必要です。

```bash
sudo -E cargo test --test '*_integration' -- --nocapture --test-threads=1
```

| テストファイル               | 対象                                  | 必要な権限       |
| ---------------------------- | ------------------------------------- | ---------------- |
| `netlink_integration`        | ip6tnl トンネル・アドレス・ルート操作 | `CAP_NET_ADMIN`  |
| `nftables_integration`       | nft ルールセット適用・構文検証        | `CAP_NET_ADMIN`  |
| `inotify_integration`        | リースファイル監視（inotify）         | 一般ユーザーで可 |
| `sysctl_integration`         | `/proc/sys/net/` 読み書き             | `CAP_NET_ADMIN`  |
| `full_lifecycle_integration` | apply/update/cleanup E2E              | `CAP_NET_ADMIN`  |

> **注意**: `sudo -E` で `CARGO_HOME` 等の環境変数を引き継ぐことで、既存のビルドキャッシュが再利用されます。`--test-threads=1` は Network Namespace の `setns` がスレッド単位で有効なため必須です。

### Docker を使ったテスト（root に Rust が不要）

ホストに Rust をインストールせずに統合テストを実行できます。

```bash
# ユニットテスト + 統合テストをまとめて実行
docker compose -f docker-compose.test.yml run --rm test

# ユニットテストのみ
docker compose -f docker-compose.test.yml run --rm test cargo test --lib

# 統合テストのみ
docker compose -f docker-compose.test.yml run --rm test \
  cargo test --test '*_integration' -- --nocapture --test-threads=1
```

Cargo のビルドキャッシュは Docker ボリュームに保持されるため、2 回目以降は高速に実行されます。

## ログ

`--log-level` オプションでログレベルを指定します。tracing の directive 構文も使用できます。

```bash
mapeced --log-level debug start
mapeced --log-level "mapeced=debug,warn" start
```

## v6プラス対応

v6プラスでは DHCPv6 で MAP ルールが配信されません。
`map_profile = "v6plus"` を設定すると、組み込みの静的 MAP ルールテーブルを使用します。
静的ルールは `assets/v6plus_rules.json` に格納されており、`tools/gen_v6plus_rules.py` で更新できます。

詳細は [docs/v6plus-spec.md](docs/v6plus-spec.md) を参照してください。

## ディレクトリ構成

| パス                       | 用途                         |
| -------------------------- | ---------------------------- |
| `/etc/mapeced/config.toml` | 設定ファイル（デフォルト）   |
| `/run/mapeced.pid`         | PID ファイル                 |
| `/run/mapeced/rules.cache` | MAP ルールキャッシュ（JSON） |
| `/var/lib/mapeced/duid`    | DHCPv6 DUID ファイル         |

## 対応プラットフォーム

- Linux（Netlink / nftables を使用するため Linux 必須）

## 関連仕様・ドキュメント

- [RFC 7597](https://www.rfc-editor.org/rfc/rfc7597) — Mapping of Address and Port with Encapsulation (MAP-E)
- [RFC 7598](https://www.rfc-editor.org/rfc/rfc7598) — DHCPv6 Options for Configuration of Softwire Address and Port-Mapped Clients
- [docs/config-format.md](docs/config-format.md) — 設定ファイル仕様
- [docs/responsibilities.md](docs/responsibilities.md) — 責務定義・外部コンポーネントとの境界
- [docs/v6plus-spec.md](docs/v6plus-spec.md) — v6プラス技術仕様
