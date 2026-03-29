use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use serde::Deserialize;

use super::rule::{MapRule, PortParams};

/// `assets/v6plus_rules.json` のトップレベル構造。
///
/// `br_addr`・`psid_offset`・`psid_len` を共通フィールドとして持ち、
/// ルール固有のアドレス情報のみ `rules` 配列に記述する。
#[derive(Deserialize)]
struct V6PlusRulesFile {
    br_addr: Ipv6Addr,
    psid_offset: u8,
    psid_len: u8,
    rules: Vec<RuleEntry>,
}

/// `rules` 配列の各要素。`br_addr` と `port_params` はトップレベルから補完する。
#[derive(Deserialize)]
struct RuleEntry {
    ipv4_prefix: Ipv4Addr,
    prefix4_len: u8,
    ipv6_prefix: Ipv6Addr,
    prefix6_len: u8,
    ea_len: u8,
    is_fmr: bool,
}

static RULES_JSON: &str = include_str!("../../assets/v6plus_rules.json");

/// v6プラス向け静的 BMR テーブルを返す。
///
/// v6プラスでは MAP ルールは DHCPv6 では配布されず、インターネット上の公開情報を元に
/// アプリケーションに静的に埋め込む方針をとる（`docs/v6plus-spec.md` 参照）。
///
/// ルールは `assets/v6plus_rules.json` にコンパイル時埋め込みされる。
/// `port_params.psid` は `None`（実際の PSID は `try_compute` が EA-bits から算出する）。
///
/// # Panics
/// `assets/v6plus_rules.json` の JSON が不正な場合にパニックする。
pub fn v6plus_rules() -> &'static [MapRule] {
    static RULES: OnceLock<Vec<MapRule>> = OnceLock::new();
    RULES.get_or_init(build_rules)
}

fn build_rules() -> Vec<MapRule> {
    let file: V6PlusRulesFile =
        serde_json::from_str(RULES_JSON).expect("assets/v6plus_rules.json is invalid");

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
                psid: None,
            },
            br_addr: file.br_addr,
            is_fmr: entry.is_fmr,
        })
        .collect()
}
