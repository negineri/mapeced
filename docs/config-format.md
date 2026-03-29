# 設定ファイル仕様

## ファイルパス

デフォルト: `/etc/mapecd/config.toml`

起動時に `--config <path>` オプションで変更できる。

---

## 完全なサンプル

```toml
# ── インターフェース設定 ───────────────────────────────────────────────────

# WAN 側インターフェース名（必須）
upstream_interface = "eth0"

# MAP-E トンネルインターフェース名（必須）
tunnel_interface = "mape0"

# ── オプション設定 ────────────────────────────────────────────────────────

# MAP-Eで利用しないポートの最大値
# デフォルトはwell-knownポートを除外する1023、ISPによって4095などの可能性もある
# デフォルト: 1023
# p_exclude_max = 1023

# トンネルインターフェースの MTU（バイト）
# IPv6 ヘッダー 40 bytes 分を差し引いた値を推奨
# 省略時はシステムに依存（ip6tnl デフォルト MTU）
# 有効範囲: 1280〜65535
# tunnel_mtu = 1460

# v6プラス向け組み込み静的 MAP ルールを使用するか
# true の場合、起動時から静的ルールテーブル（690 件）を使用し、
# DHCPv6 Option 94 由来のルール受信・キャッシュ保存をスキップする
# CE IPv6の導出アルゴリズムがDraftのものになる
# デフォルト: false
# use_v6plus_static_rules = false

# ── 内部ファイルパス（通常変更不要）─────────────────────────────────────

# PID ファイルのパス
# デフォルト: "/run/mapecd.pid"
# pid_file = "/run/mapecd.pid"

# MAP ルールキャッシュファイルのパス（JSON 形式）
# デフォルト: "/run/mapecd/rules.cache"
# map_rules_cache_file = "/run/mapecd/rules.cache"

# DHCPv6 DUID ファイルのパス
# デフォルト: "/var/lib/mapecd/duid"
# duid_file = "/var/lib/mapecd/duid"
```

---

## フィールド一覧

| キー                      | 型      | 必須     | デフォルト                  | 説明                                                                                         |
| ------------------------- | ------- | -------- | --------------------------- | -------------------------------------------------------------------------------------------- |
| `upstream_interface`      | string  | **はい** | なし                        | WAN 側インターフェース名。最大 15 文字、使用可能文字: 英数字・`-`・`_`・`.`                  |
| `tunnel_interface`        | string  | **はい** | なし                        | ip6tnl トンネルインターフェース名。最大 15 文字、`upstream_interface` と異なる名前であること |
| `p_exclude_max`           | integer | いいえ   | 1023                        | 除外ポート上限値                                                                             |
| `tunnel_mtu`              | integer | いいえ   | なし（システム依存）        | トンネル MTU（バイト）。1280〜65535 の範囲                                                   |
| `use_v6plus_static_rules` | bool    | いいえ   | `false`                     | v6プラス組み込み静的 MAP ルールを使用する                                                    |
| `pid_file`                | string  | いいえ   | `"/run/mapecd.pid"`         | PID ファイルのパス                                                                           |
| `map_rules_cache_file`    | string  | いいえ   | `"/run/mapecd/rules.cache"` | MAP ルールキャッシュファイルのパス                                                           |
| `duid_file`               | string  | いいえ   | `"/var/lib/mapecd/duid"`    | DHCPv6 DUID ファイルのパス                                                                   |

---

## インターフェース名バリデーション

`upstream_interface` および `tunnel_interface` は起動時に以下の条件で検証される。

- 空文字列でないこと
- 15 文字以内（Linux の `IFNAMSIZ - 1`）
- 使用可能文字: 英数字・ハイフン（`-`）・アンダースコア（`_`）・ドット（`.`）
- `upstream_interface` と `tunnel_interface` が異なる名前であること

条件を満たさない場合はエラーで起動を中断する。

---

## ログレベルの設定

ログレベルは設定ファイルではなく CLI の `--log-level` オプションで指定する。

```bash
mapecd --log-level debug start
mapecd --log-level "mapecd=debug,warn" start
```

デフォルトは `"info"`。tracing の directive 構文（`クレート=レベル` 形式）も使用できる。

---

## 最小構成例

WAN インターフェースとトンネルインターフェースのみ指定した最小構成。

```toml
upstream_interface = "eth0"
tunnel_interface   = "mape0"
```

---

## v6プラス向け構成例（DHCPv6 capture モード）

```toml
upstream_interface      = "eth0"
tunnel_interface        = "mape0"
tunnel_mtu              = 1460
use_v6plus_static_rules = true
```
