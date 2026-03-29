# mapeced 実装計画

## モジュール構成

```text
src/
├── main.rs                    # エントリポイント: CLI・ログ初期化・コマンドディスパッチ
├── cli.rs                     # clap CLI 定義 (start / status / stop / --config / --log-level)
├── config.rs                  # 設定読み込み・バリデーション
├── error.rs                   # 共通エラー型 (thiserror)
│
├── map/
│   ├── mod.rs
│   ├── rule.rs                # MapRule, PortParams, MapeParams 型定義
│   ├── calc.rs                # EA-bits / IPv4 / PSID / CE IPv6 計算
│   ├── port_set.rs            # ポートセット計算 Port(R, m) 式
│   └── v6plus_rules.rs        # v6プラス向け静的 BMR テーブル
│
├── dhcpv6/
│   ├── mod.rs
│   ├── capture.rs             # AF_PACKET キャプチャモード [Linux only]
│   ├── parser.rs              # OPTION_S46_CONT_MAPE パース（手書きバイトパーサー）
│   └── lease_watcher.rs       # inotify による /run/systemd/netif/leases/ 監視 [Linux only]
│
├── netlink/                   # [Linux only]
│   ├── mod.rs
│   ├── addr.rs                # RTM_NEWADDR / RTM_DELADDR（IPv6 /128 および IPv4）
│   ├── tunnel.rs              # RTM_NEWLINK / RTM_DELLINK (ip6tnl)
│   └── route.rs               # RTM_NEWROUTE / RTM_DELROUTE
│
├── nftables/
│   ├── mod.rs
│   └── manager.rs             # ルールセット生成・nft -f - 適用
│
└── daemon/
    ├── mod.rs
    ├── state.rs               # DaemonState (MapeParams スナップショット)
    ├── lifecycle.rs           # apply / update / cleanup
    └── runner.rs              # tokio select! イベントループ
```

## 実装フェーズ（TDD サイクル前提）

### Phase 1: 基盤整備

目標: `mapeced --help` が動く最小骨格。

| ステップ | 内容                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1-1      | `error.rs` に `MapEError` 定義（thiserror）。定義すべき主要 variant: `ConfigNotFound { path: PathBuf }`, `InvalidConfig(String)`, `InvalidCePrefix`（EA-bits 長と CE prefix 長の不一致）, `NoPrefixMatch`（IA_PD にマッチする MAP Rule が `pending_map_rules` に存在しない場合。`try_compute` が `Err` を返す際に使用）, `MissingBrAddress`（`OPTION_S46_BR` が省略された場合）, `EmptyPortRanges`（`calc_port_ranges` の結果が空の場合の nftables 適用ガード）, `NetlinkError(String)`（Netlink 操作失敗）, `NftError(String)`（nft コマンド実行失敗） |
| 1-2      | `config.rs` の型定義と serde デシリアライズ（詳細は下記参照）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 1-3      | `cli.rs` の clap Derive 実装。サブコマンドなし。`--config <PATH>`（デフォルト: `/etc/mapeced/config.toml`）と `--log-level <LEVEL>`（デフォルト: `info`）のみ定義する。起動・停止・状態確認は systemctl に委譲する（`systemctl start/stop/status mapeced`）。 |
| 1-4      | `main.rs` に tokio ランタイム + ロガー初期化（`tracing-subscriber`。`--log-level` 値を反映し、`/run/systemd/journal/socket` が存在する場合は `tracing-journald` を優先し、そうでない場合は stderr に出力）                                                                                                                                                                                                                                                                                                                                              |

テスト: `config.rs` のフィールドごとにデシリアライズ単体テスト。デフォルト値・必須バリデーションの確認。

#### ステップ 1-2 詳細: `config.rs`（型定義・デシリアライズ・バリデーション）

設定ファイルの読み込みは `toml` crate を直接使用（`fs::read_to_string` + `toml::from_str`）。`config` crate は使用しない（TOML 単一ファイルで十分なため）。

**エラー処理:**

- 設定ファイルが存在しない場合（`io::ErrorKind::NotFound`）: `MapEError::ConfigNotFound { path: PathBuf }` を返し、`error!` ログを出力して終了コード 1 で即終了する

**デシリアライズ後バリデーション**（違反時はすべて `MapEError::InvalidConfig`）:

- `upstream_interface` / `tunnel_interface` が空文字列でなく、かつ 15 文字以内（IFNAMSIZ-1）であること
- 両フィールドが英数字・`-`・`_`・`.` のみで構成されていること（スペース・クォート・バックスラッシュ・セミコロン等は不許可。`generate_ruleset` での文字列インジェクションを設定読み込み段階で防ぐ）
- `upstream_interface` と `tunnel_interface` が異なる名前であること（WAN インターフェースと ip6tnl トンネルに同一インターフェースは使用不可）
- `tunnel_mtu` が `Some(v)` の場合、`v` が 1280 以上（IPv6 最小 MTU）かつ 65535 以下であること（0 や極小値を防ぐ。`v < 1280` の場合は `MapEError::InvalidConfig` を返す）

**`Config` の全フィールド一覧**（TOML キー名 = フィールド名）:

| フィールド | 型 | デフォルト | 説明 |
|---|---|---|---|
| `upstream_interface` | `String` | 必須 | WAN 側インターフェース名 |
| `tunnel_interface` | `String` | 必須 | ip6tnl トンネル名 |
| `tunnel_mtu` | `Option<u32>` | `None`（設定しない） | トンネル MTU（1280–65535） |
| `map_rules_cache_file` | `Option<PathBuf>` | `None`（キャッシュなし） | MAP ルールキャッシュ JSON パス |
| `use_v6plus_static_rules` | `bool` | `true` | `true` の場合 v6プラス静的 BMR を使用し DHCPv6 capture からのルール更新を無視する |
| `p_exclude_max` | `u16` | `1023` | 除外するポート上限（inclusive）。0–1023 は Well-Known Ports |

**`use_v6plus_static_rules` と `use_v6plus` IID 方式の関係**:

- `use_v6plus_static_rules = true` のとき: `try_compute` の `use_v6plus` 引数は `true`（`build_ce_ipv6_v6plus` を使用）
- `use_v6plus_static_rules = false` のとき: `try_compute` の `use_v6plus` 引数は `false`（RFC 7597 標準の `build_ce_ipv6_rfc` を使用）
- すなわち `use_v6plus` は `Config` フィールドとしては持たず、`use_v6plus_static_rules` から導出する

### Phase 2: MAP-E 純粋計算ロジック（優先度最高・Linux 不要）

目標: RFC 7597 および v6プラス固有仕様に基づくアドレス・ポートセット計算を純粋関数として実装する。Linux カーネル依存なし。

| ステップ | 内容 |
| -------- | ---- |
| 2-1 | `map/rule.rs` に型定義を追加（詳細は下記参照） |
| 2-2 | `map/calc.rs` に EA-bits 抽出・IPv4 アドレス導出・PSID 計算・CE IPv6 アドレス構成を実装 |
| 2-3 | `map/port_set.rs` にポートセット計算・連続レンジ変換を実装 |

テスト: `map/calc.rs`・`map/port_set.rs` の各関数に対し、v6プラス固定パラメータ（a=4, k=8）を用いた具体値ベースの単体テスト。境界値（最小 PSID=0、最大 PSID=255）も含める。

#### ステップ 2-1 詳細: `map/rule.rs`（型定義）

```rust
/// MAP Rule（BMR: Basic Mapping Rule）1 件分
pub struct MapRule {
    pub ipv4_prefix: Ipv4Addr,   // IPv4 プレフィックスアドレス
    pub prefix4_len: u8,         // IPv4 プレフィックス長（0–32）
    pub ipv6_prefix: Ipv6Addr,   // MAP Rule IPv6 プレフィックス
    pub prefix6_len: u8,         // IPv6 プレフィックス長（0–128）
    pub ea_len: u8,              // EA-bits 長
    pub port_params: PortParams, // PSID パラメータ
    pub br_addr: Ipv6Addr,       // BR の IPv6 アドレス
    pub is_fmr: bool,            // FMR フラグ（RFC 7598 OPTION_S46_RULE flags bit0）
}

pub struct PortParams {
    pub psid_offset: u8,  // a: PSID offset（v6プラスは 4）
    pub psid_len: u8,     // k: PSID length（v6プラスは 8）
    pub psid: u16,        // この CE に割り当てられた PSID 値
}

/// CE（Customer Edge）に対して計算された MAP-E パラメータ一式
pub struct MapeParams {
    pub ipv4_addr: Ipv4Addr,    // CE の IPv4 アドレス
    pub ce_ipv6_addr: Ipv6Addr, // CE の IPv6 アドレス（トンネル local）
    pub br_ipv6_addr: Ipv6Addr, // BR の IPv6 アドレス（トンネル remote）
    pub psid: u16,
    pub port_params: PortParams,
    pub port_ranges: Vec<(u16, u16)>, // 利用可能ポートレンジ一覧
    pub port_start: u16,              // nftables SNAT 用連続レンジ開始
    pub port_end: u16,                // nftables SNAT 用連続レンジ終了
    pub a_min: u16,                   // 実効的な R 下限
}
```

`MapRule` に `try_compute(ce_prefix: Ipv6Addr, ce_prefix_len: u8, p_exclude_max: u16, use_v6plus: bool) -> Result<MapeParams, MapEError>` メソッドを実装する。`ce_prefix_len < rule.prefix6_len + rule.ea_len` の場合は `MapEError::InvalidCePrefix` を返す。`p_exclude_max` は `Config::p_exclude_max`（デフォルト 1023）を渡す。`use_v6plus` は `Config::use_v6plus_static_rules` と同値とする（上記「`use_v6plus_static_rules` と `use_v6plus` IID 方式の関係」参照）。

v6プラス向け静的ルールテーブルは `map/v6plus_rules.rs` に定義し、`pub fn v6plus_rules() -> &'static [MapRule]` として公開する。`map/rule.rs` からは re-export する。静的ルールは `Mutex` や `OnceLock` で初期化する。

#### ステップ 2-2 詳細: `map/calc.rs`（計算ロジック）

以下の関数を実装する。すべて `pub fn`・副作用なし・`#[inline]` 推奨。

```rust
/// CE プレフィックスから EA-bits を抽出する
/// ce_prefix の bit[rule_prefix_len .. rule_prefix_len+ea_len] を取り出す
pub fn extract_ea_bits(
    ce_prefix: u128,
    rule_prefix_len: u8,
    ea_len: u8,
) -> u32;

/// EA-bits から IPv4 アドレスを導出する
/// ipv4_suffix = ea_bits >> psid_len
/// ipv4_addr   = ipv4_prefix | (ipv4_suffix << (32 - prefix4_len))
pub fn derive_ipv4_addr(
    ea_bits: u32,
    ipv4_prefix: Ipv4Addr,
    prefix4_len: u8,
    psid_len: u8,
) -> Ipv4Addr;

/// EA-bits から PSID を導出する
/// psid = ea_bits & ((1 << psid_len) - 1)
pub fn derive_psid(ea_bits: u32, psid_len: u8) -> u16;

/// CE の IPv6 アドレスを構成する（RFC 7597 モード）
///   IID: [0x0000(16)] [IPv4(32)] [PSID(16)]
pub fn build_ce_ipv6_rfc(
    rule_ipv6_prefix: u128,
    rule_prefix_len: u8,
    ea_bits: u32,
    ea_len: u8,
    ipv4_addr: Ipv4Addr,
    psid: u16,
    psid_len: u8,
) -> Ipv6Addr;

/// CE の IPv6 アドレスを構成する（v6プラス非公開 Draft モード）
///   IID: [0x00(8)] [IPv4(32)] [PSID(16)] [0x00(8)]
pub fn build_ce_ipv6_v6plus(
    rule_ipv6_prefix: u128,
    rule_prefix_len: u8,
    ea_bits: u32,
    ea_len: u8,
    ipv4_addr: Ipv4Addr,
    psid: u16,
    psid_len: u8,
) -> Ipv6Addr;
```

#### ステップ 2-3 詳細: `map/port_set.rs`（ポートセット計算）

ポート番号の 16 bit 構造:

```
[ R (psid_offset bits) ][ PSID (psid_len bits) ][ m (M bits) ]
```

変数の対応（`docs/mape-port-allocation.md` との対応）:

| 本計画の変数名 | ドキュメント記法 | 意味 |
|---|---|---|
| `psid_offset` | `A` | R フィールドのビット幅（上位） |
| `psid_len` | `PSID_LEN` | PSID フィールドのビット幅 |
| `M` | `M` | 下位フィールドのビット幅 = `16 - A - PSID_LEN` |
| `R`（ポート式中の変数） | `a` | R フィールドの値。範囲 `[a_min, 2^A - 1]` |
| `m`（ポート式中の変数） | `j` | 下位フィールドの値。範囲 `[0, 2^M - 1]` |

`M` は各関数内部で `let m_bits = 16u8.checked_sub(psid_offset + psid_len).expect("psid_offset + psid_len must be < 16");` として計算する（引数には含まない）。`psid_offset + psid_len >= 16`（M ≤ 0）は不正な入力であり、`calc_a_min` 呼び出し前に `config.rs` のバリデーションで弾く（後述）。

```rust
/// a_min を算出する
/// a_min = max(1, ceil((p_exclude_max + 1) / 2^(psid_len + M)))
/// ただし M = 16 - psid_offset - psid_len
/// 前提: psid_offset + psid_len < 16
pub fn calc_a_min(psid_offset: u8, psid_len: u8, p_exclude_max: u16) -> u16;

/// 利用可能なポートレンジ一覧を返す
/// Port(R, m) = (R << (psid_len + M)) + (psid << M) + m
/// R ∈ [a_min, 2^psid_offset - 1], m ∈ [0, 2^M - 1]
/// ただし M = 16 - psid_offset - psid_len
/// 前提: psid_offset + psid_len < 16
pub fn calc_port_ranges(
    psid_offset: u8,
    psid_len: u8,
    psid: u16,
    a_min: u16,
) -> Vec<(u16, u16)>;

/// nftables SNAT 用連続レンジを返す
/// PORT_START = (1 << 15) + (a_min << M)
/// PORT_END   = PORT_START + (2^psid_offset - a_min) * 2^M - 1
/// ただし M = 16 - psid_offset - psid_len
/// 前提: psid_offset + psid_len < 16
pub fn calc_continuous_range(
    psid_offset: u8,
    psid_len: u8,
    a_min: u16,
) -> (u16, u16);
```

`psid_offset == 0` の場合（RFC 定義の連続ポート）は tc 変換不要の特殊ケースとして `calc_port_ranges` は `vec![(0, 65535)]`、`calc_continuous_range` は `(0, 65535)` を返す。このとき `psid_len` も 0 になるため `psid_offset + psid_len < 16` は自明に満たされる。

**`config.rs` バリデーション追加**（`OPTION_S46_PORTPARAMS` を設定ファイルで指定する場合を含む）:
- `psid_offset + psid_len < 16` を満たさない場合は `MapEError::InvalidConfig` を返す（M > 0 が必須）
- この条件は DHCPv6 パーサー（`parser.rs`）でも同様にバリデーションし、違反時は `MapEError::InvalidConfig` を返す

---

### Phase 3: DHCPv6 受信・パース（Linux 必須）

目標: WAN インターフェース上の DHCPv6 パケットから `OPTION_S46_CONT_MAPE` を解析し `MapRule` を生成する。また IA_PD リース情報を監視してプレフィックス変化を検知する。

| ステップ | 内容 |
| -------- | ---- |
| 3-1 | `dhcpv6/parser.rs` に OPTION_S46_CONT_MAPE バイトパーサーを実装 |
| 3-2 | `dhcpv6/capture.rs` に AF_PACKET ソケットを用いた DHCPv6 受信ループを実装 |
| 3-3 | `dhcpv6/lease_watcher.rs` に inotify による `/run/systemd/netif/leases/` 監視を実装 |

追加依存クレート: `nix`（AF_PACKET ソケット・inotify）、`serde`・`serde_json`（MAP ルールキャッシュ）。

テスト: `parser.rs` に対しキャプチャしたバイト列を使ったパーステスト（正常系・OPTION_S46_BR 欠如・不正 ea_len）。`lease_watcher.rs` は tmpdir + テスト用リースファイルで動作確認。

#### ステップ 3-1 詳細: `dhcpv6/parser.rs`

RFC 7598 に従い TLV（Type-Length-Value）構造を手書きパーサーで処理する。

```
OPTION_S46_CONT_MAPE (code 94)
  └─ OPTION_S46_RULE (code 89)
       ├─ flags (1 byte)       bit0: FMR
       ├─ ea-len (1 byte)
       ├─ prefix4-len (1 byte)
       ├─ ipv4-prefix (4 bytes)
       ├─ ipv6-prefix-len (1 byte)
       ├─ ipv6-prefix (可変: ceil(ipv6-prefix-len/8) bytes)
       └─ OPTION_S46_PORTPARAMS (code 93)  ← オプション。省略可能
            ├─ offset (4 bits upper)
            ├─ psid-len (4 bits lower)
            └─ psid (2 bytes)
  └─ OPTION_S46_BR (code 90)  ← 16 bytes
```

`OPTION_S46_PORTPARAMS` が省略された場合は `psid_offset = 0, psid_len = 0, psid = 0` をデフォルト値として使用する（連続ポート割り当て、tc 変換不要）。

実装上の注意:
- `OPTION_S46_BR` が存在しない場合は `MapEError::MissingBrAddress` を返す
- DHCPv6 Message Type は Advertise（2）と Reply（7）のみ受理し、それ以外はスキップする
- OPTION_S46_RULE 内の PSID は後続処理で EA-bits から上書き計算するため、パース時は参考値として保持するだけで良い

公開 API:
```rust
/// DHCPv6 ペイロード（UDP payload の先頭から）から MapRule を抽出する
/// OPTION_S46_CONT_MAPE が含まれない場合は Ok(None) を返す
pub fn parse_mape_option(payload: &[u8]) -> Result<Option<Vec<MapRule>>, MapEError>;
```

#### ステップ 3-2 詳細: `dhcpv6/capture.rs`

- `AF_PACKET` + `SOCK_RAW` ソケットで `upstream_interface` 上の Ethernet フレームを受信する
- BPF フィルタで UDP dst port 546（DHCPv6 クライアント）または src port 547（DHCPv6 サーバー）のみ通過させる
- Ethernet → IPv6 → UDP ヘッダーをスキップして DHCPv6 ペイロードを `parse_mape_option` へ渡す
- `tokio::net::UnixListener` ではなく `tokio::io::unix::AsyncFd` でソケットを非同期ラップする
- チャネル（`tokio::sync::mpsc::Sender<Vec<MapRule>>`）経由でデーモンへ通知する

公開 API:
```rust
pub async fn run_capture(
    ifname: &str,
    tx: mpsc::Sender<Vec<MapRule>>,
) -> Result<(), MapEError>;
```

#### ステップ 3-3 詳細: `dhcpv6/lease_watcher.rs`

- `inotify` で `/run/systemd/netif/leases/<ifindex>` ファイルへの `IN_CLOSE_WRITE` | `IN_MOVED_TO` イベントを監視する
- インターフェース名 → ifindex の変換には `nix::net::if_::if_nametoindex` を使用する
- リースファイルはシェル変数形式（`KEY=VALUE`）で記述されているため、正規表現を用いず行単位で `=` 分割して解析する
- 取得対象フィールド: `PREFIXES`（IA_PD プレフィックス。スペース区切り複数件あり）
- `Ipv6Network`（または `(Ipv6Addr, u8)`）を `tokio::sync::watch::Sender` で送信する

公開 API:
```rust
pub async fn run_lease_watcher(
    ifname: &str,
    tx: watch::Sender<Option<(Ipv6Addr, u8)>>,
) -> Result<(), MapEError>;
```

MAP ルールキャッシュ（`map_rules_cache_file`）: 起動時に既存キャッシュファイルがあれば読み込んで `pending_map_rules` に設定する。DHCPv6 capture で新規取得した場合は上書き保存する（`serde_json` でシリアライズ）。

---

### Phase 4: Netlink 操作（Linux 必須）

目標: Netlink ソケットを直接操作してアドレス付与・ip6tnl トンネル作成・ルーティングを実現する。

追加依存クレート: `rtnetlink`（`netlink-packet-route` を内包する高レベルラッパー）。

テスト: 実際の Netlink 操作は統合テスト（`tests/` 以下・root 権限必要）とし、単体テストはメッセージ構築ロジックのみをカバーする。

| ステップ | 内容 |
| -------- | ---- |
| 4-1 | `netlink/addr.rs` に IPv6 /128 および IPv4 /32 アドレスの追加・削除を実装 |
| 4-2 | `netlink/tunnel.rs` に ip6tnl インターフェースの作成・更新・削除を実装 |
| 4-3 | `netlink/route.rs` にデフォルトルートおよび FMR ルートの追加・削除を実装 |

#### ステップ 4-1 詳細: `netlink/addr.rs`

```rust
/// WAN または tunnel インターフェースに IPv6 /128 アドレスを追加する
pub async fn add_ipv6_addr(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    addr: Ipv6Addr,
) -> Result<(), MapEError>;

/// WAN または tunnel インターフェースから IPv6 /128 アドレスを削除する（存在しない場合は無視）
pub async fn del_ipv6_addr(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    addr: Ipv6Addr,
) -> Result<(), MapEError>;

/// tunnel インターフェースに IPv4 /32 アドレスを追加する（CE IPv4）
pub async fn add_ipv4_addr(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    addr: Ipv4Addr,
) -> Result<(), MapEError>;

pub async fn del_ipv4_addr(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    addr: Ipv4Addr,
) -> Result<(), MapEError>;
```

#### ステップ 4-2 詳細: `netlink/tunnel.rs`

`ip6tnl` インターフェースは `RTM_NEWLINK` + `IFLA_INFO_KIND = "ip6tnl"` + `IFLA_INFO_DATA` でパラメータを設定する。

主要 IFLA_IPTUN パラメータ:
- `IFLA_IPTUN_LOCAL`: CE IPv6 アドレス（16 bytes）
- `IFLA_IPTUN_REMOTE`: BR IPv6 アドレス（16 bytes）
- `IFLA_IPTUN_PROTO`: `IPPROTO_IPIP`（4 = IPv4-in-IPv6）
- `IFLA_IPTUN_LINK`: upstream インターフェースの ifindex
- `IFLA_IPTUN_TTL`: 64（固定）
- MTU 設定は `RTM_SETLINK` で別途 `IFLA_MTU` を設定する（`tunnel_mtu` が `Some` の場合）

```rust
pub async fn create_tunnel(
    handle: &rtnetlink::Handle,
    name: &str,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    link_ifindex: u32,
    mtu: Option<u32>,
) -> Result<u32, MapEError>; // 戻り値: 作成したインターフェースの ifindex

pub async fn delete_tunnel(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<(), MapEError>;

/// トンネルが既に存在する場合は削除して再作成する（初回 apply・CE IPv6 変化時に使用）
pub async fn ensure_tunnel(
    handle: &rtnetlink::Handle,
    name: &str,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    link_ifindex: u32,
    mtu: Option<u32>,
) -> Result<u32, MapEError>;

/// BR アドレス（remote エンドポイント）のみを RTM_NEWLINK + NLM_F_REPLACE で in-place 更新する
/// トンネルを再作成せずに済むため、BR 変化時の通信断を最小化する
pub async fn update_tunnel_remote(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    new_remote: Ipv6Addr,
) -> Result<(), MapEError>;
```

#### ステップ 4-3 詳細: `netlink/route.rs`

```rust
/// デフォルトルート（0.0.0.0/0）を tunnel インターフェース経由に設定する
pub async fn add_default_route(
    handle: &rtnetlink::Handle,
    tunnel_ifindex: u32,
) -> Result<(), MapEError>;

pub async fn del_default_route(
    handle: &rtnetlink::Handle,
    tunnel_ifindex: u32,
) -> Result<(), MapEError>;

/// FMR ルート（MAP Rule の IPv4 プレフィックス宛）を追加する
pub async fn add_fmr_route(
    handle: &rtnetlink::Handle,
    prefix: Ipv4Addr,
    prefix_len: u8,
    tunnel_ifindex: u32,
) -> Result<(), MapEError>;

pub async fn del_fmr_route(
    handle: &rtnetlink::Handle,
    prefix: Ipv4Addr,
    prefix_len: u8,
    tunnel_ifindex: u32,
) -> Result<(), MapEError>;
```

---

### Phase 5: nftables + tc ポートマッピング

目標: PSID に基づく非連続ポートセット制約を nftables SNAT（連続レンジ）と tc pedit（全単射ビット変換）の 2 段構えで実現する。

| ステップ | 内容 |
| -------- | ---- |
| 5-1 | `nftables/manager.rs` にルールセット生成・適用・削除を実装 |
| 5-2 | `nftables/manager.rs` 内に tc コマンド生成ヘルパーを実装し、tc qdisc + filter + pedit を適用する |

追加依存なし（nft / tc コマンドは `std::process::Command` で起動する）。

テスト: `generate_ruleset` はファイル I/O 不要の純粋関数として実装し、生成されたルールセット文字列を単体テストで検証する。tc コマンド生成についても同様。

#### ステップ 5-1 詳細: `nftables/manager.rs`（nftables ルールセット）

ルールセットは `nft -f -`（stdin 経由）で適用する。生成するルールセットの構造:

```nftables
# テーブル名: mapeced
table ip mapeced {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # SNAT: 連続ポートレンジ（PORT_START–PORT_END）を割り当て
        oifname "<tunnel_iface>" ip protocol { tcp, udp } snat to <ce_ipv4>:<port_start>-<port_end>
        # ICMP は別途
        oifname "<tunnel_iface>" ip protocol icmp snat to <ce_ipv4>
    }
    chain prerouting {
        type filter hook prerouting priority dstnat; policy accept;
        # 戻りパケット識別: PSID マッチ && R != 0 で fwmark を付与
        ip daddr <ce_ipv4> ip protocol { tcp, udp } \
            th dport & <psid_check_mask> == <psid_val> \
            th dport & <r_check_mask> != 0 \
            meta mark set 0x1
        ip daddr <ce_ipv4> ip protocol icmp meta mark set 0x1
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        # 送出ポートがPSID外のパケットは破棄（tc変換後の検証）
    }
}
```

`psid_check_mask`・`psid_val`・`r_check_mask` は `port_set.rs` の計算結果から生成する。ここで `M = 16 - psid_offset - psid_len`:
- `psid_check_mask = ((1 << psid_len) - 1) << M`
- `psid_val = psid << M`
- `r_check_mask = ((1 << psid_offset) - 1) << (psid_len + M)`  （R フィールドのビットマスク。これが 0 のポートは予約ポート範囲）

ポートレンジ設定後、tc pedit への受け渡しは fwmark（`meta mark`）で行う。

```rust
pub struct NftManager {
    table_name: String,
}

impl NftManager {
    pub fn new() -> Self;
    
    /// ルールセット文字列を生成する（副作用なし・テスト可能）
    pub fn generate_ruleset(&self, params: &MapeParams, tunnel_iface: &str) -> String;
    
    /// nft -f - でルールセットを適用する
    pub async fn apply(&self, params: &MapeParams, tunnel_iface: &str) -> Result<(), MapEError>;
    
    /// テーブルを削除する（クリーンアップ時）
    pub async fn delete_table(&self) -> Result<(), MapEError>;
}
```

#### ステップ 5-2 詳細: tc ビット変換設定

`psid_offset == 0` の場合は tc 設定を一切行わない（連続ポートなので変換不要）。

tc コマンド列（`A=4, M=4, psid_offset=4, psid_len=8` の場合の概略）:

**送信方向**（tunnel → WAN、SNAT 後の変換）:
```bash
# tunnel インターフェースへの egress に qdisc を設定
tc qdisc add dev <tunnel_iface> handle 1: root prio
# fwmark == 0 のパケット（SNAT 済み = 送信）に pedit を適用
tc filter add dev <tunnel_iface> parent 1: handle 1 fw action pedit ...
```

**受信方向**（WAN → tunnel、DNAT 前の変換）:
```bash
tc qdisc add dev <tunnel_iface> handle ffff: ingress
tc filter add dev <tunnel_iface> parent ffff: handle 1 fw action pedit ...
```

tc pedit のビット変換ロジック（`docs/mape-port-allocation.md` 準拠）。ここでの `M` はポート下位フィールドのビット幅 `M = 16 - psid_offset - psid_len`（v6プラスは 4）を指す。

**送信方向（連続レンジ C → MAP-E ポート集合 S）**:
1. `R`（= a）の MSB が立っていない場合は `0x8000` ビットを下ろす（PORT_START の MSB=1 をクリア）
2. 残りの `R` フィールドのビットを確認し、立っているものを対応する上位ビット（`bit[M+psid_len+R_bit_pos]`）に展開する
3. `psid` を `bit[M+psid_len-1 : M]` に埋め込む
4. TCP/UDP のチェックサムを再計算

**受信方向（MAP-E ポート集合 S → 連続レンジ C）**:
1. `psid` フィールドでフィルタし、対象フローに `fwmark` を付与（nftables で実施済み）
2. `psid` 部分（`bit[M+psid_len-1:M]`）を 0 で埋める（`R` のビットが入ってくる位置を空ける）
3. `R` フィールドのビットを全て確認し、対応する下位ビットを展開する
4. 最上位ビット（`0x8000`）を立てる（連続レンジ C の印に戻す）
5. TCP/UDP のチェックサムを再計算

上記の変換は C と S の間で完全な 1 対 1 対応（全単射）になる。

TCP/UDP に加え、ICMP エラーパケットに内包される TCP/UDP ヘッダー（オフセット 48 bytes: IPv4(20) + ICMP(8) + 内包 IPv4(20)）にも適用する。ただし IPv4 オプション（固定 20 バイトを前提）がある場合は対象外。

```rust
pub struct TcManager;

impl TcManager {
    /// tc 設定全体を適用する（qdisc + filter + pedit）
    pub async fn apply(
        &self,
        params: &MapeParams,
        tunnel_iface: &str,
    ) -> Result<(), MapEError>;
    
    /// tc 設定を削除する（qdisc 削除で filter も連動削除される）
    pub async fn cleanup(&self, tunnel_iface: &str) -> Result<(), MapEError>;
    
    /// tc コマンド文字列列を生成する（副作用なし・テスト可能）
    pub fn generate_tc_commands(
        params: &MapeParams,
        tunnel_iface: &str,
    ) -> Vec<String>;
}
```

---

### Phase 6: デーモン統合・イベントループ

目標: Phase 2〜5 の各モジュールを統合し、tokio の `select!` で複数イベントソースを多重化する完全動作デーモンを実装する。

| ステップ | 内容 |
| -------- | ---- |
| 6-1 | `daemon/state.rs` に `DaemonState` 型を定義する |
| 6-2 | `daemon/lifecycle.rs` に `apply` / `update` / `cleanup` を実装する |
| 6-3 | `daemon/runner.rs` に tokio `select!` イベントループを実装する |
| 6-4 | `main.rs` を更新してサブコマンドなしで `daemon::runner::run(config)` を直接呼び出す。プロセスはフォアグラウンドで動作し続け、SIGTERM / SIGINT で graceful shutdown する。PID 管理・起動/停止は systemd に委譲する。 |

テスト: `lifecycle.rs` の差分検出ロジック（変化なしで何もしない）を単体テストでカバーする。

#### ステップ 6-1 詳細: `daemon/state.rs`

```rust
pub struct DaemonState {
    pub params: Option<MapeParams>,          // 現在適用中のパラメータ（None = 未設定）
    pub pending_map_rules: Vec<MapRule>,     // DHCPv6 capture から受け取った MAP Rule
    pub tunnel_ifindex: Option<u32>,         // 作成済みトンネルの ifindex
    pub wan_ifindex: u32,                    // WAN インターフェースの ifindex（起動時に取得）
}
```

#### ステップ 6-2 詳細: `daemon/lifecycle.rs`

```rust
/// 初回適用: トンネル作成 → アドレス付与 → ルート設定 → nftables + tc 適用
pub async fn apply(
    state: &mut DaemonState,
    new_params: MapeParams,
    config: &Config,
    rtnetlink: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) -> Result<(), MapEError>;

/// 差分更新: 変化した項目のみ更新する
/// - BR アドレス変化のみ → `update_tunnel_remote` で remote エンドポイントを in-place 更新
/// - PSID 変化 → nftables + tc を再適用
/// - CE IPv6 変化 → アドレス差し替え + `ensure_tunnel` でトンネル再作成
/// - 変化なし → 何もしない
pub async fn update(
    state: &mut DaemonState,
    new_params: MapeParams,
    config: &Config,
    rtnetlink: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) -> Result<(), MapEError>;

/// クリーンアップ: tc → nftables → ルート → アドレス → トンネル の順に削除
pub async fn cleanup(
    state: &mut DaemonState,
    config: &Config,
    rtnetlink: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) -> Result<(), MapEError>;
```

IA_PD プレフィックス受信後、`pending_map_rules` から `try_compute` を呼び出してマッチする最初のルールで `MapeParams` を計算する。マッチしない場合は `warn!` ログを出力して次のイベントを待つ（`MapEError::NoPrefixMatch` をエラーとして扱わない）。

#### ステップ 6-3 詳細: `daemon/runner.rs`

```rust
pub async fn run(config: Config) -> Result<(), MapEError>;
```

イベントループの構造:

```rust
loop {
    tokio::select! {
        // IA_PD プレフィックス変化（lease_watcher からの watch チャネル）
        Ok(()) = lease_rx.changed() => { ... }

        // DHCPv6 capture から MAP Rule 受信（mpsc チャネル）
        Some(rules) = capture_rx.recv() => { ... }

        // SIGTERM / SIGINT（tokio::signal）
        _ = signal::ctrl_c() => { break; }
        _ = sigterm.recv() => { break; }
    }
}
// cleanup
lifecycle::cleanup(&mut state, ...).await?;
```

起動時シーケンス:
1. WAN ifindex を `if_nametoindex` で取得
2. MAP ルールキャッシュファイルが存在すれば読み込んで `pending_map_rules` に設定（`config.map_rules_cache_file` が `Some` の場合のみ）
3. `config.use_v6plus_static_rules = true` の場合は v6plus_rules を `pending_map_rules` に設定（キャッシュより優先）
4. `lease_watcher` と `dhcpv6::capture` を tokio タスクとして spawn
5. 既存の MAP-E 由来設定をクリーンアップ（再起動時の冪等性確保）:
   - `nft delete table ip mapeced` を実行（存在しない場合はエラーを無視）
   - `if_nametoindex(config.tunnel_interface)` で既存トンネルを確認し、存在する場合は tc qdisc を削除した後にトンネルインターフェースを削除する
6. イベントループ開始

終了時シーケンス（SIGTERM / SIGINT 受信後）:
1. `cleanup` を呼び出して全設定を削除
2. プロセス終了（exit code 0）

---

### Phase 7: 仕上げ・統合検証

目標: エラー処理の網羅・ログの整備・動作確認。

| ステップ | 内容 |
| -------- | ---- |
| 7-1 | `cargo clippy -- -D warnings` を通す。全 `unwrap` / `expect` を `?` または `match` に置き換える |
| 7-2 | `tracing` の各箇所にログレベルを整理する（`info!`: 状態遷移、`debug!`: パケット受信、`warn!`: NoPrefixMatch、`error!`: 回復不能エラー） |
| 7-3 | `Cargo.toml` に必要な依存クレートを追加し、`cargo build --release` が通ることを確認する |
| 7-4 | `README.md` にインストール手順・設定例・systemd unit ファイルサンプルを追記する |

追加依存クレートまとめ（Phase 1〜6 で必要なもの）:

| クレート | バージョン目安 | 用途 |
| -------- | -------------- | ---- |
| `tokio` | 1 | 非同期ランタイム（features: full） |
| `clap` | 4 | CLI 定義（features: derive） |
| `tracing` | 0.1 | ログ emit マクロ（`info!`/`debug!` 等） |
| `tracing-subscriber` | 0.3 | ログ初期化（stderr 出力・フィルタ） |
| `tracing-journald` | 0.3 | systemd-journald 出力 |
| `thiserror` | 2 | エラー型定義 |
| `serde` | 1 | シリアライズ |
| `serde_json` | 1 | MAP ルールキャッシュ |
| `toml` | 0.8 | 設定ファイル読み込み |
| `nix` | 0.29 | AF_PACKET ソケット・inotify・if_nametoindex |
| `rtnetlink` | 0.14 | Netlink 操作（`netlink-packet-route` を内包） |

---

## 依存関係・実装順序まとめ

```
Phase 1 (基盤整備)
    ↓
Phase 2 (MAP-E 計算) ← Linux 不要・最優先
    ↓
Phase 3 (DHCPv6) ────────────────────────┐
Phase 4 (Netlink) ───────────────────────┤
Phase 5 (nftables + tc) ─────────────────┤
    ↓（3・4・5 は並行実装可能）           ↓
Phase 6 (デーモン統合) ←─────────────────┘
    ↓
Phase 7 (仕上げ)
```
