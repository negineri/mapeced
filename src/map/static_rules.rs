use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use serde::Deserialize;

use super::rule::{MapRule, PortParams};

/// CE IPv6 アドレスの計算方式。設定ファイルの `ce_calc` フィールドで指定する。
///
/// | 値         | 計算方式                              | 対象 ISP 例              |
/// |------------|---------------------------------------|--------------------------|
/// | `rfc7597`  | RFC 7597 標準方式（デフォルト）       | DHCPv6 対応 ISP 全般     |
/// | `draft`    | Internet Draft 方式（v6プラス互換）   | v6プラス、OCN VC 等      |
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CeCalcMethod {
    /// RFC 7597 標準方式。
    #[default]
    Rfc7597,
    /// Internet Draft 方式（v6プラス互換）。
    Draft,
}

impl CeCalcMethod {
    /// `calc::build_ce_ipv6_v6plus` を使うか否かを返す。
    pub fn use_v6plus(&self) -> bool {
        matches!(self, CeCalcMethod::Draft)
    }
}

/// `assets/static_rules.json` のトップレベル構造。
#[derive(Deserialize)]
struct StaticRulesFile {
    rules: Vec<RuleEntry>,
}

/// `rules` 配列の各要素。すべてのパラメータをルール単位で保持する。
#[derive(Deserialize)]
struct RuleEntry {
    br_addr: Ipv6Addr,
    psid_offset: u8,
    psid_len: u8,
    ipv4_prefix: Ipv4Addr,
    prefix4_len: u8,
    ipv6_prefix: Ipv6Addr,
    prefix6_len: u8,
    ea_len: u8,
    is_fmr: bool,
}

static RULES_JSON: &str = include_str!("../../assets/static_rules.json");

/// 静的 BMR テーブルを返す。
///
/// ルールは `assets/static_rules.json` にコンパイル時埋め込みされる。
/// `static_rule = true` の場合にのみ使用される。
///
/// # Panics
/// `assets/static_rules.json` の JSON が不正な場合にパニックする。
pub fn static_rules() -> &'static [MapRule] {
    static RULES: OnceLock<Vec<MapRule>> = OnceLock::new();
    RULES.get_or_init(build_rules)
}

fn build_rules() -> Vec<MapRule> {
    let file: StaticRulesFile =
        serde_json::from_str(RULES_JSON).expect("assets/static_rules.json is invalid");

    file.rules
        .into_iter()
        .map(|entry| MapRule {
            ipv4_prefix: entry.ipv4_prefix,
            prefix4_len: entry.prefix4_len,
            ipv6_prefix: entry.ipv6_prefix,
            prefix6_len: entry.prefix6_len,
            ea_len: entry.ea_len,
            port_params: PortParams {
                psid_offset: entry.psid_offset,
                psid_len: entry.psid_len,
                psid: None,
            },
            br_addr: entry.br_addr,
            is_fmr: entry.is_fmr,
        })
        .collect()
}
