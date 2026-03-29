# mapeced 実装計画

## モジュール構成

```text
src/
├── main.rs                    # エントリポイント: CLI・ログ初期化・コマンドディスパッチ
├── cli.rs                     # clap CLI 定義 (--config / --log-level)
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
/// キャッシュ保存に serde_json を使用するため `#[derive(Serialize, Deserialize, Clone)]` を付与する
#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
pub struct PortParams {
    pub psid_offset: u8,  // a: PSID offset（v6プラスは 4）
    pub psid_len: u8,     // k: PSID length（v6プラスは 8）
    /// この CE に割り当てられた PSID 値。
    /// DHCPv6 パース時は受信値を格納するが、`try_compute` では EA-bits から再計算した値で上書きする。
    /// `v6plus_rules.rs` の静的ルール構築時はプレースホルダーとして `0` を設定する（実際の PSID は `try_compute` が上書き）。
    pub psid: u16,
}

/// CE（Customer Edge）に対して計算された MAP-E パラメータ一式
#[derive(Clone)]
pub struct MapeParams {
    pub ipv4_addr: Ipv4Addr,    // CE の IPv4 アドレス
    pub ce_ipv6_addr: Ipv6Addr, // CE の IPv6 アドレス（トンネル local）
    pub br_ipv6_addr: Ipv6Addr, // BR の IPv6 アドレス（トンネル remote）
    /// PSID 値。`port_params.psid` と常に同値であり `try_compute` が設定する。
    /// nftables / tc コマンド生成時の利便性のため冗長に保持する（更新は `try_compute` 内でのみ行うこと）。
    pub psid: u16,
    pub port_params: PortParams,
    pub port_ranges: Vec<(u16, u16)>, // 利用可能ポートレンジ一覧（MAP-E ポート集合 S）
    pub port_start: u16,              // nftables SNAT 用連続レンジ開始（ポート集合 C の先頭）
    pub port_end: u16,                // nftables SNAT 用連続レンジ終了（ポート集合 C の末尾）
    /// 実効的な R 下限。`calc_a_min` の結果。
    /// `calc_continuous_range` の PORT_START 計算（`(1 << 15) + (a_min << M)`）および
    /// `generate_tc_commands` 内のレンジ計算に必要なため保持する。
    pub a_min: u16,
    /// マッチした `MapRule::is_fmr` の値。`try_compute` が `self.is_fmr` をそのままコピーする。
    /// `lifecycle::apply` / `update` で FMR ルートの追加要否判定に使用する。
    pub is_fmr: bool,
}
```

`MapRule` に `try_compute(ce_prefix: Ipv6Addr, ce_prefix_len: u8, p_exclude_max: u16, use_v6plus: bool) -> Result<MapeParams, MapEError>` メソッドを実装する。`ce_prefix_len < rule.prefix6_len + rule.ea_len` の場合は `MapEError::InvalidCePrefix` を返す。`p_exclude_max` は `Config::p_exclude_max`（デフォルト 1023）を渡す。`use_v6plus` は `Config::use_v6plus_static_rules` と同値とする（上記「`use_v6plus_static_rules` と `use_v6plus` IID 方式の関係」参照）。`MapeParams::is_fmr` は `self.is_fmr` をそのままコピーする。

v6プラス向け静的ルールテーブルは `map/v6plus_rules.rs` に定義し、`pub fn v6plus_rules() -> &'static [MapRule]` として公開する。`map/rule.rs` からは re-export する。静的ルールは `std::sync::OnceLock<Vec<MapRule>>` で遅延初期化する（読み取り専用のため `Mutex` は不要）。

#### ステップ 2-2 詳細: `map/calc.rs`（計算ロジック）

以下の関数を実装する。すべて `pub fn`・副作用なし・`#[inline]` 推奨。

```rust
/// CE プレフィックスから EA-bits を抽出する
/// ce_prefix は IPv6 アドレスを big-endian で u128 に格納した値（MSB = IPv6 先頭ビット = bit127）。
/// `Ipv6Addr::from(addr).to_bits()` または `u128::from_be_bytes(addr.octets())` で変換する。
/// ce_prefix の bit[rule_prefix_len .. rule_prefix_len+ea_len] を取り出す。
/// シフト量は `128 - rule_prefix_len - ea_len`（ce_prefix_len は引数に不要）。
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
///   PSID フィールド（16 bit）への配置: RFC 7597 Section 5.2 に従い**右詰め**（`psid` をそのまま下位に配置）。
///   `psid_len` は PSID 値が `psid_len` ビット幅に収まることの確認用。IID 構成時のシフト量には使用しない。
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
///   PSID フィールド（16 bit）への配置: v6プラス仕様に従い**左詰め**（`psid << (16 - psid_len)` で上位に詰める）。
///   すなわち `v6plus-spec.md` の `psid << (16 - k)` に相当し、`psid_len` がシフト量の計算に使用される。
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

`M` は各関数内部で `let m_bits = 16u8.checked_sub(psid_offset + psid_len).expect("psid_offset + psid_len must be < 16");` として計算する（引数には含まない）。`psid_offset + psid_len >= 16`（M ≤ 0）は不正な入力であり、`calc_a_min` 呼び出し前に `parser.rs` または `v6plus_rules.rs` のバリデーションで弾く（後述）。

```rust
/// a_min を算出する
/// a_min = max(1, ceil((p_exclude_max + 1) / 2^(psid_len + M)))
/// ただし M = 16 - psid_offset - psid_len
/// 前提: psid_offset + psid_len < 16
pub fn calc_a_min(psid_offset: u8, psid_len: u8, p_exclude_max: u16) -> u16;

/// 利用可能なポートレンジ一覧を返す
/// psid_offset > 0 の場合:
///   Port(R, m) = (R << (psid_len + M)) + (psid << M) + m
///   R ∈ [a_min, 2^psid_offset - 1], m ∈ [0, 2^M - 1]
///   ただし M = 16 - psid_offset - psid_len
///   前提: psid_offset + psid_len < 16
/// psid_offset == 0 の場合:
///   単一連続ブロック vec![(psid << M, (psid << M) + (1 << M) - 1)]
///   ただし M = 16 - psid_len（a_min は使用しない）
pub fn calc_port_ranges(
    psid_offset: u8,
    psid_len: u8,
    psid: u16,
    a_min: u16,
) -> Vec<(u16, u16)>;

/// nftables SNAT 用連続レンジを返す
/// psid_offset > 0 の場合:
///   PORT_START = (1 << 15) + (a_min << M)
///   PORT_END   = PORT_START + (2^psid_offset - a_min) * 2^M - 1
///   ただし M = 16 - psid_offset - psid_len
///   前提: psid_offset + psid_len < 16
///   PORT_END が u16::MAX（65535）を超える場合は `u16::MAX` に飽和させる（`saturating_add` を使用）。
///   実用パラメータ（v6plus A=4 等）では超えないが、バリデーション通過済みの極端な値（psid_offset=15 等）に対する防護。
/// psid_offset == 0 の場合:
///   PORT_START = psid << M  （M = 16 - psid_len）
///   PORT_END   = PORT_START + (1 << M) - 1
///   tc 変換不要のためそのまま MAP-E ポートレンジと一致する
pub fn calc_continuous_range(
    psid_offset: u8,
    psid_len: u8,
    psid: u16,
    a_min: u16,
) -> (u16, u16);
```

`psid_offset == 0` の場合（RFC 定義の「R フィールドなし・単一連続ブロック」）は tc 変換不要の特殊ケースとして扱う。
CE に割り当てられるポートは PSID に対応する単一の連続ブロックであり、`psid_len` の値に関わらず次式で求まる:

```
M = 16 - psid_len
start = psid << M
end   = start + (1 << M) - 1
calc_port_ranges      → vec![(start, end)]
calc_continuous_range → (start, end)   // MAP-E ポートレンジと既に一致
```

`psid_len == 0` の場合は `start = 0, end = 65535`（全ポート）に自然に退化する。
ただし `psid_offset == 0` かつ `psid_len == 0` のとき M = 16 となり、`psid << M` や `1u16 << M` が Rust の u16 シフト範囲（0–15）を超えてパニックするため、**この条件を関数冒頭で特別処理する**こと（`return vec![(0, u16::MAX)]` / `return (0, u16::MAX)`）。
`psid_offset == 0` かつ `psid_len == 16` は M = 0 となり不正なため、後述のバリデーションで弾く。

**`psid_offset + psid_len` バリデーション**（実装箇所: `dhcpv6/parser.rs` および `map/v6plus_rules.rs` のルール構築時）:
- `psid_offset + psid_len < 16` を満たさない場合は `MapEError::InvalidConfig` を返す（M > 0 が必須）
- このバリデーションは `PortParams` を生成する箇所（`parser.rs` の DHCPv6 パース処理、`v6plus_rules.rs` の静的ルール構築）で実施する。`Config` 構造体には `psid_offset`・`psid_len` フィールドが存在しないため `config.rs` での実施は対象外

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
- `OPTION_S46_BR` が複数存在する場合は**先頭の 1 件を使用**し、残りは無視する
- DHCPv6 Message Type は Advertise（2）と Reply（7）のみ受理し、それ以外はスキップする
- OPTION_S46_RULE 内の PSID は後続処理で EA-bits から上書き計算するため、パース時は参考値として保持するだけで良い
- `OPTION_S46_PORTPARAMS` の PSID フィールド（2 バイト）は RFC 7598 に従い**左詰め**（MSB 側に `psid_len` ビット分の値を格納）。パース時は `u16::from_be_bytes(...)` で読み出した後、`>> (16 - psid_len)` で右詰めの整数値に変換して `PortParams::psid` に格納する。ただし **`psid_len == 0` の場合はシフトを行わず `psid = 0` を直接格納すること**（`>> 16` は u16 のシフト範囲を超えて debug ビルドでパニックする）

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

- `inotify` で `/run/systemd/netif/leases/<ifindex>` ファイルへの `IN_CLOSE_WRITE` | `IN_MOVED_TO` イベントを監視する。**ファイルが起動時に存在しない場合、直接 watch できないため親ディレクトリ `/run/systemd/netif/leases/` を `IN_CLOSE_WRITE` | `IN_MOVED_TO` | `IN_DELETE` で監視し、イベント発生時にファイル名が `<ifindex>` と一致するもののみ処理する**
- リースファイルへの `IN_DELETE` イベントが発生した場合、または `IN_CLOSE_WRITE` / `IN_MOVED_TO` 後のパース結果に有効プレフィックスが存在しない場合は `watch::Sender` に `None` を送信する（インターフェースダウン・リース失効を示す）
- 親ディレクトリ `/run/systemd/netif/leases/` 自体が起動時に存在しない場合は `MapEError::InvalidConfig` を返す
- インターフェース名 → ifindex の変換には `nix::net::if_::if_nametoindex` を使用する
- リースファイルはシェル変数形式（`KEY=VALUE`）で記述されているため、正規表現を用いず行単位で `=` 分割して解析する
- 取得対象フィールド: `PREFIXES`（IA_PD プレフィックス。スペース区切り複数件あり）
- 複数プレフィックスが含まれる場合は先頭の 1 件を使用する（スペースで `split_whitespace` して最初の要素）。プレフィックス長が 64 以下の CIDR 表記のみを有効とする（`/128` などプレフィックス長が 64 を超えるものは IA_PD として不適切なため除外。`/` を含まないエントリも除外する）。
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

ルールセットは `nft -f -`（stdin 経由）で適用する。`psid_offset > 0` の場合に生成するルールセットの構造:

```nftables
# テーブル名: mapeced
table ip mapeced {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # SNAT: 連続ポートレンジ（PORT_START–PORT_END）を割り当て、tc egress pedit のために fwmark を付与
        oifname "<tunnel_iface>" ip protocol { tcp, udp } snat to <ce_ipv4>:<port_start>-<port_end> meta mark set 0x1
        # ICMP も SNAT + fwmark（tc egress で ICMP エラー内包ヘッダを処理するため）
        oifname "<tunnel_iface>" ip protocol icmp snat to <ce_ipv4> meta mark set 0x1
    }
    # prerouting チェーンは不要。
    # 受信方向の MAP-E ポート変換は tc ingress（nftables prerouting より前に実行）が担当するため、
    # nftables から tc へ fwmark を渡す必要がない。
}
```

`psid_offset == 0` の場合（tc 不要・連続ポート直接割り当て）は fwmark を省略した簡略テンプレートを生成する:

```nftables
table ip mapeced {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "<tunnel_iface>" ip protocol { tcp, udp } snat to <ce_ipv4>:<port_start>-<port_end>
        oifname "<tunnel_iface>" ip protocol icmp snat to <ce_ipv4>
    }
}
```

`psid_check_mask`・`psid_val`・`r_check_mask` の定義（tc ingress u32 フィルタ生成に使用。`M = 16 - psid_offset - psid_len`）:
- `psid_check_mask = ((1 << psid_len) - 1) << M`  （PSID フィールドのビットマスク）
- `psid_val = psid << M`  （PSID の期待値）
- `r_check_mask = ((1 << psid_offset) - 1) << (psid_len + M)`  （R フィールドのビットマスク。R=0 は禁止ポート範囲）

これらは `generate_tc_commands` 内でのみ使用する。

ポートレンジ設定後、tc pedit への受け渡しは egress 方向のみ fwmark（`meta mark`）で行う（postrouting → tc egress の順序は保証される）。

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

**送信方向**（tunnel egress、nftables postrouting 後の変換）:
```bash
# tunnel インターフェースへの egress に qdisc を設定
tc qdisc add dev <tunnel_iface> handle 1: root prio
# fwmark == 1 のパケット（nftables postrouting で SNAT 済み）に pedit を適用
# postrouting → tc egress の順序は保証されるため fwmark フィルタが正しく機能する
tc filter add dev <tunnel_iface> parent 1: handle 1 fw action pedit ...
```

**受信方向**（tunnel ingress、ip6tnl デカプセル後の変換）:
```bash
tc qdisc add dev <tunnel_iface> handle ffff: ingress
# 【重要】tc ingress は nftables prerouting より前に実行されるため、
# この時点で fwmark は未設定。fw フィルタは使用できない。
# 代わりに u32 フィルタで宛先 IPv4 アドレス・PSID・R 値を直接照合する。
# egress 同様、R 値ごとに個別の filter + pedit ルールを生成する（v6plus: R ∈ [1,15] × TCP/UDP = 最大 30 ルール）。
# 各 R 値 r に対する TCP（proto=6）の例:
tc filter add dev <tunnel_iface> parent ffff: protocol ip u32 \
    match ip dst <ce_ipv4>/32 \
    match ip protocol 6 0xff \
    match u16 <(r<<(psid_len+M))|(psid<<M)> <((2^psid_offset-1)<<(psid_len+M))|psid_check_mask> at nexthdr+2 \
    action pedit ex munge u16 and 0x000F or <(0x8000|(r<<M))> at nexthdr+2 \
    action csum ip4h l4
# UDP（proto=17）も R 値ごとに同様に生成
# ICMP エラー内包ヘッダ（オフセット 48 bytes）は別途 u32 フィルタで処理
```

`psid_check_mask`・`psid_val`・`r_check_mask` は `generate_tc_commands` 内で `port_set.rs` の計算結果から生成する（定義は Phase 5-1 参照）。

**パケット処理順序とフィルタ方式の根拠**:

| 方向 | 処理順序 | フィルタ方式 |
|---|---|---|
| 送信（egress） | nftables postrouting → tc egress | `fw`（fwmark）フィルタ ✓ |
| 受信（ingress） | tc ingress → nftables prerouting | `u32`（PSID ビット直接照合）フィルタ ✓ |

受信方向の R=0 チェック（禁止ポート範囲の除外）: `u32` フィルタで `r_check_mask` を用いた照合も可能だが、実運用では CE 宛ての R=0 MAP-E ポートへの着信は発生しないため、PSID チェックのみで十分。

tc pedit のビット変換ロジック（`docs/mape-port-allocation.md` 準拠）。ここでの `M` はポート下位フィールドのビット幅 `M = 16 - psid_offset - psid_len`（v6プラスは 4）を指す。

**tc pedit の実装方針（一意化のため明記）**:

tc pedit の `munge` 操作は固定マスク/値の静的適用であり、「ビット値を条件として別ビットへ移動する」動的なビット複製を1命令では実現できない。そのため、**egress・ingress ともに有効な R 値（`a_min` から `2^psid_offset - 1` まで）ごとに個別の tc filter + pedit ルールを生成する**方針を採用する。

各 R 値に対して filter が `u16 match <(1<<15)|(R<<M)> <(1<<15)|((2^psid_offset-1)<<M)> at nexthdr+0`（TCP/UDP **送信元**ポートフィールド。C 空間のポート値で照合）でマッチし、対応する pedit が C ポートを S ポートへ変換する固定値ルールを適用する。

- v6plus（A=4）の場合: R ∈ [1, 15] の 15 値 × プロトコル（TCP/UDP）= 最大 30 filter ルール（egress）
- `generate_tc_commands` はこのループを生成する

**送信方向（連続レンジ C → MAP-E ポート集合 S）**:
1. `R`（= a）の MSB が立っていない場合は `0x8000` ビットを下ろす（PORT_START の MSB=1 をクリア）
2. 残りの `R` フィールドのビットを確認し、立っているものを対応する上位ビット（`bit[M+psid_len+R_bit_pos]`）に展開する
3. `psid` を `bit[M+psid_len-1 : M]` に埋め込む
4. IP ヘッダ・TCP/UDP チェックサムを再計算（pedit の次のアクションとして `action csum ip4h l4` を連鎖させる）

**受信方向（MAP-E ポート集合 S → 連続レンジ C）**:
egress 同様、**R 値ごとに個別の filter + pedit ルールを生成する**。各 R 値 r に対して:
1. u32 フィルタで宛先ポートの R+PSID フィールドを照合: `(r<<(psid_len+M))|(psid<<M)` を値、`((2^psid_offset-1)<<(psid_len+M))|psid_check_mask` をマスクとして `at nexthdr+2`（宛先ポート）で照合
2. pedit munge の固定値変換: `and 0x000F or (0x8000|(r<<M))` を `at nexthdr+2` に適用
   （PSID・R の両フィールドを一括クリアし、C 空間の R 位置 `bit[M+psid_offset-1:M]` と bit15=1 を設定。m フィールド[3:0]のみ保持）
3. IP ヘッダ・TCP/UDP チェックサムを再計算（`action csum ip4h l4` を pedit の次のアクションとして連鎖）

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
/// アドレス付与: CE IPv6（`new_params.ce_ipv6_addr`）は `state.wan_ifindex`（WAN インターフェース）に `add_ipv6_addr` で付与し、
///   CE IPv4（`new_params.ipv4_addr`）はトンネルインターフェース（`state.tunnel_ifindex`）に `add_ipv4_addr` で付与する。
///   （ip6tnl はローカルエンドポイントの IPv6 アドレスが WAN 上にルーティング可能であることを必要とするため）
/// ルート設定では、デフォルトルート（`add_default_route`）を常に追加し、
/// `new_params.is_fmr == true` の場合のみ `add_fmr_route` でその IPv4 プレフィックスへの FMR ルートを追加する
pub async fn apply(
    state: &mut DaemonState,
    new_params: MapeParams,
    config: &Config,
    rtnetlink: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) -> Result<(), MapEError>;

/// 差分更新: 変化した項目のみ更新する
/// 複数の項目が同時に変化した場合は以下の優先順位で処理する（上位が下位を包含）:
///   1. CE IPv6 変化（最優先）→ 旧 IPv6 アドレス削除 + `ensure_tunnel` でトンネル再作成 +
///      新 IPv6 アドレス付与。CE IPv4・PSID・ポートセットも連動変化するため
///      IPv4 アドレス差し替え + nftables + tc 再適用も必ず実施する。
///      また `ensure_tunnel` でトンネルの ifindex が変わりうるため、旧ルート（デフォルトルートおよび FMR ルート）を
///      削除したうえで新 `tunnel_ifindex` でルートを再追加する（`add_default_route` + 必要に応じ `add_fmr_route`）。
///      （PSID は EA-bits の下位ビットとして CE IPv6 IID に埋め込まれるため、
///       PSID のみが単独で変化することはなく、IPv4・PSID 変化は常にこのケースに包含される）
///   2. BR アドレス変化のみ（CE IPv6 に変化なし）→ `update_tunnel_remote` で remote エンドポイントを in-place 更新
///   3. 変化なし → 何もしない
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

`use_v6plus_static_rules = true` の場合は DHCPv6 capture タスクを spawn しないため、`capture_rx` は `Option<mpsc::Receiver<Vec<MapRule>>>` 型として保持し、`None` の場合は `select!` の capture アームを無効化する。具体的には `tokio::select!` の当該アームを `if let Some(ref mut rx) = capture_rx_opt` ガード付きで定義するか、`std::future::pending::<Option<Vec<MapRule>>>()` で永遠にブロックするダミー Future に差し替える（`std::future::pending` は Rust 標準ライブラリに含まれるため追加クレート不要）。

```rust
// capture_rx_opt: Option<mpsc::Receiver<Vec<MapRule>>>
loop {
    tokio::select! {
        // IA_PD プレフィックス変化（lease_watcher からの watch チャネル）
        Ok(()) = lease_rx.changed() => { ... }

        // DHCPv6 capture から MAP Rule 受信（mpsc チャネル）
        // use_v6plus_static_rules = true の場合は capture_rx_opt が None のため
        // このアームは永遠に select されない
        Some(rules) = async {
            match capture_rx_opt.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending::<Option<Vec<MapRule>>>().await,
            }
        } => { ... }

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
2. `config.use_v6plus_static_rules = false` かつ `config.map_rules_cache_file` が `Some` の場合のみ: キャッシュファイルが存在すれば読み込んで `pending_map_rules` に設定する（`use_v6plus_static_rules = true` の場合は次のステップで静的ルールを設定するためキャッシュ読み込みは不要）
3. `config.use_v6plus_static_rules = true` の場合は v6plus_rules を `pending_map_rules` に設定
4. `lease_watcher` を tokio タスクとして spawn する（`watch::channel(None)` で初期値 `None` のチャネルを生成し `tx` を渡す）。`config.use_v6plus_static_rules = false` の場合のみ `dhcpv6::capture` タスクも spawn し `capture_rx_opt = Some(rx)` とする。`true` の場合は `capture_rx_opt = None`
5. 既存の MAP-E 由来設定をクリーンアップ（再起動時の冪等性確保）:
   - `nft delete table ip mapeced` を `std::process::Command` で実行し、終了コードを確認する。nft コマンドがゼロ以外で終了した場合は stderr 文字列に `"No such file or directory"` または `"Could not process rule"` が含まれるかを確認し、テーブル未存在由来のエラーであれば無視する（それ以外は `MapEError::NftError` として伝播）
   - `if_nametoindex(config.tunnel_interface)` で既存トンネルを確認し、存在する場合は `tc qdisc del dev <tunnel_interface> root 2>/dev/null` および `tc qdisc del dev <tunnel_interface> ingress 2>/dev/null` を実行した後にトンネルインターフェースを削除する
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
| `anyhow` | 1 | `main` や統合テストでの汎用エラー伝播（`MapEError` 以外の一時的エラーラップ用）。既に `Cargo.toml` に含まれる |
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
