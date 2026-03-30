# mapeced 統合テスト実装計画

## 背景・目的

現在のテストスイートはユニットテスト（96件）のみで構成されており、各モジュールの純粋計算ロジックを検証している。しかし以下の領域はユニットテストでは検証されていない。

- **Linux カーネル API との実連携**（Netlink: ip6tnl 作成・アドレス付与・ルート操作）
- **外部コマンドとの連携**（`nft -f -` によるルールセット適用、`tc` コマンド実行）
- **ファイルシステム監視**（inotify による IA_PD リース変化の検知）
- **モジュール間の連携**（MAP-E パラメータ計算 → Netlink 設定 → nftables 適用の一連フロー）
- **ライフサイクル全体**（apply → update → cleanup の E2E 動作）

統合テストの目的は、これらの実システムとのインタフェースが正しく機能することを継続的に保証することである。

---

## テスト配置方針

```
tests/
├── common/
│   └── mod.rs            # ネットワーク名前空間ヘルパー・共通フィクスチャ
├── lease_watcher.rs      # inotify 統合テスト（非特権）
├── dhcpv6_e2e.rs         # DHCPv6 パーサー E2E テスト（非特権）
├── netlink.rs            # Netlink 統合テスト（CAP_NET_ADMIN 必要）
├── nftables.rs           # nftables 統合テスト（CAP_NET_ADMIN 必要）
└── lifecycle.rs          # ライフサイクル統合テスト（CAP_NET_ADMIN 必要）
```

**特権要否の分類:**

| テストファイル | CAP_NET_ADMIN | 実行方法 |
|---|---|---|
| `lease_watcher.rs` | 不要 | `cargo test --test lease_watcher` |
| `dhcpv6_e2e.rs` | 不要 | `cargo test --test dhcpv6_e2e` |
| `netlink.rs` | **必要** | `sudo -E cargo test --test netlink -- --test-threads=1` |
| `nftables.rs` | **必要** | `sudo -E cargo test --test nftables -- --test-threads=1` |
| `lifecycle.rs` | **必要** | `sudo -E cargo test --test lifecycle -- --test-threads=1` |

特権テストは **`--test-threads=1`** で直列実行する（ネットワーク名前空間の競合を避けるため）。

---

## テスト実行環境

### ネットワーク名前空間による分離

Netlink・nftables テストはホストの実ネットワーク設定を変更しないよう、テストごとに独立したネットワーク名前空間（netns）内で実行する。

```rust
// tests/common/mod.rs のイメージ
pub struct TestNetns {
    name: String,
    fd: OwnedFd, // 名前空間 fd（スコープ終了時に削除）
}

impl TestNetns {
    pub fn new() -> Self { /* ip netns add <uuid> */ }
    pub fn run<F, R>(&self, f: F) -> R
    where F: FnOnce() -> R { /* setns + f() */ }
}

impl Drop for TestNetns {
    fn drop(&mut self) { /* ip netns del <name> */ }
}
```

### 必要な dev-dependencies 追加

```toml
[dev-dependencies]
tempfile = "3"         # 既存
nix = { version = "0.29", features = ["sched"] }  # setns(2) 用
```

### CI 環境（GitHub Actions）

```yaml
# .github/workflows/test.yml のイメージ
- name: Run privileged integration tests
  run: sudo -E cargo test --test netlink --test nftables --test lifecycle -- --test-threads=1
  # runner: ubuntu-latest（NET_ADMIN 権限あり）
```

---

## Phase 1: 非特権統合テスト

特権不要。通常の `cargo test` で実行可能。

### 1-1. `tests/lease_watcher.rs` — inotify リース監視

`dhcpv6::lease_watcher` モジュールの inotify 統合を検証する。

**テストケース:**

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `lw_01` | リースファイル新規作成 | `LeaseWatcher` が IA_PD プレフィックスを正しく抽出して送信する |
| `lw_02` | リースファイル更新（プレフィックス変更） | 変化を検知し新しいプレフィックスが通知される |
| `lw_03` | リースファイル削除 | `None` または削除通知が送信される |
| `lw_04` | IA_PD エントリ不在のリースファイル | パースエラーにならずスキップされる |
| `lw_05` | 複数のリース変化が連続して発生 | 最終状態のみが反映される（デバウンス動作） |

**実装メモ:**
- `tempfile::tempdir()` で一時ディレクトリを作成し、リースファイルを書き込む
- `tokio::time::timeout` でイベント到達を待機し、到達しない場合はテスト失敗

### 1-2. `tests/dhcpv6_e2e.rs` — DHCPv6 パーサー E2E

実際の DHCPv6 キャプチャデータを用いた E2E パーステスト。
ユニットテストで検証済みのバイトレベルパースに対して、MapRule → MapeParams 計算までの一気通貫を検証する。

**テストケース:**

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `dhcp_e2e_01` | v6plus BMR のキャプチャバイト列 | パース結果 MapRule の全フィールドが期待値と一致する |
| `dhcp_e2e_02` | 複数の BMR を含むオプション | Vec<MapRule> のサイズと各 MapRule の整合性 |
| `dhcp_e2e_03` | パース成功 → calc::try_compute まで | 実際の IA_PD プレフィックスを与えて MapeParams を導出できる |
| `dhcp_e2e_04` | マッチする BMR が存在しない IA_PD | `NoPrefixMatch` エラーが返る |

---

## Phase 2: Netlink 統合テスト

`CAP_NET_ADMIN` 必要。ネットワーク名前空間内で実行する。

### 2-1. `tests/netlink.rs` — トンネル管理

`netlink::tunnel` の Netlink 操作を実カーネルで検証する。

**テストケース:**

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `tnl_01` | `ensure_tunnel()` — 新規作成 | ip6tnl インターフェースが名前空間内に出現する |
| `tnl_02` | `ensure_tunnel()` — 冪等性 | 既存トンネルに同一パラメータで呼び出しても成功する |
| `tnl_03` | `ensure_tunnel()` — パラメータ更新 | ローカル IPv6 変更後に IFLA_IPTUN_LOCAL が更新される |
| `tnl_04` | `ensure_tunnel()` — MTU 設定 | 指定 MTU がインターフェースに反映される |
| `tnl_05` | `delete_tunnel()` | インターフェースが名前空間から削除される |
| `tnl_06` | 存在しないトンネルを削除 | エラーにならず成功（冪等） |

### 2-2. `tests/netlink.rs` — アドレス管理

`netlink::addr` の Netlink 操作を実カーネルで検証する。

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `addr_01` | `add_ipv6_addr()` — WAN インターフェース | アドレスが `ip addr show` 相当の Netlink 問い合わせで確認できる |
| `addr_02` | `add_ipv4_addr()` — トンネルインターフェース | IPv4 アドレスが付与される |
| `addr_03` | 同一アドレスの重複付与 | エラーにならず成功（冪等） |
| `addr_04` | `del_addr()` — アドレス削除 | 削除後にアドレスが存在しない |

### 2-3. `tests/netlink.rs` — ルート管理

`netlink::route` の Netlink 操作を実カーネルで検証する。

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `rt_01` | `add_default_route()` | `0.0.0.0/0` のルートがトンネル経由で設定される |
| `rt_02` | `add_fmr_route()` | FMR プレフィックスのルートが追加される |
| `rt_03` | ルート削除 | `del_default_route()` / `del_fmr_route()` 後にルートが消える |
| `rt_04` | 同一ルートの重複追加 | エラーにならず成功（冪等） |

---

## Phase 3: nftables / tc 統合テスト

`CAP_NET_ADMIN` 必要。`nft` および `tc` コマンドの存在を前提とする。

### 3-1. `tests/nftables.rs` — nftables ルールセット適用

`nftables::manager::NftManager` の実 nft コマンド連携を検証する。

**テストケース:**

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `nft_01` | `apply()` — 基本 SNAT ルール | `nft list table` でテーブル・チェーンが存在する |
| `nft_02` | `apply()` — ポートレンジ適用 | SNAT ルールに `masquerade to :<start>-<end>` が含まれる |
| `nft_03` | `apply()` 後に `delete()` | テーブルが削除される |
| `nft_04` | `apply()` の冪等性 | 2回連続 apply が成功し、ルールが重複しない |
| `nft_05` | `apply()` → `apply()` （パラメータ更新） | 古いルールが置き換えられる |

### 3-2. `tests/nftables.rs` — tc qdisc / filter / pedit

`nftables::manager::TcManager` の実 tc コマンド連携を検証する。

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `tc_01` | `apply()` — qdisc 作成 | `tc qdisc show dev <iface>` で HTB qdisc が確認できる |
| `tc_02` | `apply()` — filter/pedit 作成 | `tc filter show dev <iface>` でポート変換フィルタが確認できる |
| `tc_03` | `delete()` | qdisc 削除後に filter も消える |
| `tc_04` | `apply()` の冪等性 | 2回連続 apply でエラーにならない |

---

## Phase 4: ライフサイクル統合テスト

`CAP_NET_ADMIN` 必要。最も重要な E2E テスト。実際の `daemon::lifecycle` 関数を使用する。

### 4-1. `tests/lifecycle.rs` — apply / update / cleanup

`daemon::lifecycle::{apply, update, cleanup}` を通じたシステム全体の整合性を検証する。

**テストケース:**

| テストID | シナリオ | 検証内容 |
|---|---|---|
| `lc_01` | `apply()` — 初回適用（RFC 7597） | トンネル・アドレス・ルート・nftables が全て設定される |
| `lc_02` | `apply()` — 初回適用（v6plus CE 計算） | v6plus 固有の CE IPv6 アドレスが正しく設定される |
| `lc_03` | `apply()` — FMR あり | FMR ルートが追加される |
| `lc_04` | `update()` — BR アドレス変更 | トンネルのリモートエンドポイントが更新される |
| `lc_05` | `update()` — IA_PD プレフィックス変更 | CE IPv4/IPv6・ポート・nftables が全て再設定される |
| `lc_06` | `update()` — FMR なし → あり | FMR ルートが追加される |
| `lc_07` | `update()` — FMR あり → なし | FMR ルートが削除される |
| `lc_08` | `update()` — パラメータ変化なし | Netlink/nft 呼び出しがスキップされる（冪等） |
| `lc_09` | `cleanup()` — apply 後にクリーンアップ | トンネル・アドレス・ルート・nftables が全て削除される |
| `lc_10` | `cleanup()` — 未適用状態でのクリーンアップ | エラーにならず成功（冪等） |
| `lc_11` | `apply()` → `cleanup()` → `apply()` | 2回目の apply が正常に動作する |
| `lc_12` | `startup_cleanup()` — 古い設定が残っている場合 | 起動時に残存設定が除去される |

**検証方法:**

各テストケースで `apply()` / `update()` 後に以下を Netlink 経由で問い合わせる。

- `get_link` でトンネルインターフェースの存在・IPTUN 属性を確認
- `get_address` で CE IPv4/IPv6 アドレスの存在を確認
- `get_route` でデフォルトルート・FMR ルートの存在を確認
- `nft list table <name>` でルールセットの内容を確認

---

## 実装優先順位

```
Phase 1 (非特権) → Phase 2 (Netlink) → Phase 3 (nftables/tc) → Phase 4 (ライフサイクル)
```

Phase 4 のライフサイクルテストは Phase 2・3 のインフラが揃ってから実装する。
Phase 1 は CI ですぐに実行可能なため最初に着手する。

---

## テストヘルパー設計（`tests/common/mod.rs`）

```rust
/// ネットワーク名前空間を管理するハンドル
pub struct TestNetns { ... }

impl TestNetns {
    /// 新しい名前空間を作成し、ハンドルを返す
    pub fn new() -> anyhow::Result<Self>;

    /// 名前空間内で非同期クロージャを実行する
    pub async fn run_async<F, Fut, R>(&self, f: F) -> R
    where F: FnOnce() -> Fut, Fut: Future<Output = R>;
}

impl Drop for TestNetns {
    fn drop(&mut self); // `ip netns del` で自動削除
}

/// テスト用のダミー MapeParams を生成するビルダー
pub fn dummy_mape_params() -> MapeParams { ... }

/// テスト用のダミー MapRule を生成するビルダー  
pub fn dummy_map_rule() -> MapRule { ... }
```

---

## Cargo.toml への追記

```toml
[dev-dependencies]
tempfile = "3"                                         # 既存
nix = { version = "0.29", features = ["sched", "mount"] }  # setns 用（追加）
anyhow = "1"                                           # テストエラー簡略化（追加）
tokio = { version = "1.50", features = ["full"] }      # 非同期テスト（追加）

[[test]]
name = "lease_watcher"
path = "tests/lease_watcher.rs"

[[test]]
name = "dhcpv6_e2e"
path = "tests/dhcpv6_e2e.rs"

[[test]]
name = "netlink"
path = "tests/netlink.rs"
required-features = []

[[test]]
name = "nftables"
path = "tests/nftables.rs"

[[test]]
name = "lifecycle"
path = "tests/lifecycle.rs"
```

---

## 考慮事項・制約

### テスト分離

- 特権テストはネットワーク名前空間を使用し、ホストのネットワーク設定を汚染しない
- 各テストは独立した名前空間で実行し、並列実行しない（`--test-threads=1`）
- テスト後のクリーンアップは `Drop` で保証する

### 環境依存

- `nft`・`tc`・`ip` コマンドの存在を前提とする（環境にない場合は skip）
- Linux カーネル 5.4 以上を対象とする（ip6tnl netlink 属性の互換性）
- CI では `ubuntu-latest` runner を使用（GitHub Actions は NET_ADMIN 権限あり）

### 既存ユニットテストとの関係

- 統合テストはユニットテストの代替ではなく補完
- MAP-E アルゴリズム（`map::calc`、`map::port_set`）の詳細な数値検証はユニットテストに委ねる
- 統合テストは「実際のカーネル API 呼び出しが正しく行われるか」に焦点を当てる
