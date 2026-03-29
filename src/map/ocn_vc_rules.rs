use std::sync::OnceLock;

use serde::Deserialize;

use super::rule::{MapRule, PortParams};

/// `assets/ocn_vc_rules.json` のトップレベル構造。
#[derive(Deserialize)]
struct OcnVcRulesFile {
    br_addr: std::net::Ipv6Addr,
    psid_offset: u8,
    psid_len: u8,
    rules: Vec<RuleEntry>,
}

/// `rules` 配列の各要素。
#[derive(Deserialize)]
struct RuleEntry {
    ipv4_prefix: std::net::Ipv4Addr,
    prefix4_len: u8,
    ipv6_prefix: std::net::Ipv6Addr,
    prefix6_len: u8,
    ea_len: u8,
    is_fmr: bool,
}

static RULES_JSON: &str = include_str!("../../assets/ocn_vc_rules.json");

/// OCN バーチャルコネクト向け静的 BMR テーブルを返す。
///
/// ルールは `assets/ocn_vc_rules.json` にコンパイル時埋め込みされる。
/// `port_params.psid` はプレースホルダーとして `0` を設定する（実際の PSID は `try_compute` が上書き）。
///
/// # Panics
/// `assets/ocn_vc_rules.json` の JSON が不正な場合にパニックする。
pub fn ocn_vc_rules() -> &'static [MapRule] {
    static RULES: OnceLock<Vec<MapRule>> = OnceLock::new();
    RULES.get_or_init(build_rules)
}

fn build_rules() -> Vec<MapRule> {
    let file: OcnVcRulesFile =
        serde_json::from_str(RULES_JSON).expect("assets/ocn_vc_rules.json is invalid");

    file.rules
        .into_iter()
        .map(|entry| MapRule {
            ipv4_prefix: entry.ipv4_prefix,
            prefix4_len: entry.prefix4_len,
            ipv6_prefix: entry.ipv6_prefix,
            prefix6_len: entry.prefix6_len,
            ea_len: entry.ea_len,
            port_params: PortParams {
                psid_offset: file.psid_offset,
                psid_len: file.psid_len,
                psid: 0, // プレースホルダー（try_compute が上書き）
            },
            br_addr: file.br_addr,
            is_fmr: entry.is_fmr,
        })
        .collect()
}
