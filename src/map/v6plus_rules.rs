use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use super::rule::{MapRule, PortParams};

/// v6プラス向け静的 BMR テーブルを返す。
///
/// v6プラスでは MAP ルールは DHCPv6 では配布されず、インターネット上の公開情報を元に
/// アプリケーションに静的に埋め込む方針をとる（`docs/v6plus-spec.md` 参照）。
///
/// v6プラス固有値: `psid_offset = 4, psid_len = 8`
/// `port_params.psid` はプレースホルダーとして `0` を設定する（実際の PSID は `try_compute` が上書き）。
///
/// ea_len の算出式: `ea_len = (32 - prefix4_len) + psid_len`
///   例: prefix4_len=24 → ea_len = 8 + 8 = 16
///
/// # NOTE
/// 以下のルールはインターネット上で公開されている情報に基づく。
/// ISP 固有の最新ルールについては実装を更新すること。
pub fn v6plus_rules() -> &'static [MapRule] {
    static RULES: OnceLock<Vec<MapRule>> = OnceLock::new();
    RULES.get_or_init(build_rules)
}

fn v6plus_port_params() -> PortParams {
    PortParams {
        psid_offset: 4,
        psid_len: 8,
        psid: 0, // プレースホルダー（try_compute が上書き）
    }
}

fn build_rules() -> Vec<MapRule> {
    // v6プラス（JPIX）向け公開情報に基づく MAP ルール一覧
    //
    // 凡例: (IPv4_prefix/len, IPv6_prefix/len, ea_len, BR_addr, is_fmr)
    // ea_len = (32 - prefix4_len) + 8 （psid_len=8 固定）
    //
    // 以下のアドレスはサービス固有の値であり、インターネット上の公開情報を元に設定している。
    // 最新情報に基づく更新が必要な場合はここを変更すること。
    let br: Ipv6Addr = "2404:9200:225:100::64".parse().unwrap();

    vec![
        // IPv4: 14.8.0.0/13 相当の各 /24 ブロック（代表例）
        // ea_len = (32-24) + 8 = 16
        rule("14.8.0.0", 24, "2400:4050::", 32, 16, br, true),
        rule("14.9.0.0", 24, "2400:4050::", 32, 16, br, true),
        rule("14.10.0.0", 24, "2400:4050::", 32, 16, br, true),
        rule("14.11.0.0", 24, "2400:4050::", 32, 16, br, true),
        rule("14.12.0.0", 24, "2400:4050::", 32, 16, br, true),
    ]
}

fn rule(
    ipv4_prefix: &str,
    prefix4_len: u8,
    ipv6_prefix: &str,
    prefix6_len: u8,
    ea_len: u8,
    br_addr: Ipv6Addr,
    is_fmr: bool,
) -> MapRule {
    MapRule {
        ipv4_prefix: ipv4_prefix.parse::<Ipv4Addr>().unwrap(),
        prefix4_len,
        ipv6_prefix: ipv6_prefix.parse::<Ipv6Addr>().unwrap(),
        prefix6_len,
        ea_len,
        port_params: v6plus_port_params(),
        br_addr,
        is_fmr,
    }
}
