//! Phase 1: DHCPv6 パーサー E2E テスト（非特権）
//!
//! `cargo test --test dhcpv6_e2e` で実行する。

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use mapeced::dhcpv6::parser::parse_mape_option;
use mapeced::error::MapEError;

// ── テスト用バイト列 ──────────────────────────────────────────────────────────

/// DHCPv6 Reply: 1 つの MAP-E ルール（v6plus 相当）。
/// parser.rs の VALID_REPLY と同一内容。
///
/// Packet layout:
///   07 11 22 33              – Reply header
///   00 5e 00 2f              – OPTION_S46_CONT_MAPE (len=47)
///     00 59 00 17            – OPTION_S46_RULE (len=23)
///       01 10 0f             – flags=FMR, ea_len=16, prefix4_len=15
///       6a 49 00 00          – ipv4=106.73.0.0
///       40                   – ipv6_prefix_len=64
///       24 04 92 00 02 25 01 00  – ipv6=2404:9200:225:100::
///       00 5d 00 03          – PORTPARAMS
///       48 00 00             – offset=4, psid_len=8, psid=0
///     00 5a 00 10            – OPTION_S46_BR (len=16)
///       ...                  – BR=2404:9200:225:100::64
const SINGLE_RULE_REPLY: &[u8] = &[
    0x07, 0x11, 0x22, 0x33,
    0x00, 0x5e, 0x00, 0x2f,
    0x00, 0x59, 0x00, 0x17,
    0x01, 0x10, 0x0f,
    0x6a, 0x49, 0x00, 0x00,
    0x40,
    0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00,
    0x00, 0x5d, 0x00, 0x03,
    0x48, 0x00, 0x00,
    0x00, 0x5a, 0x00, 0x10,
    0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
];

/// DHCPv6 Reply: 2 つの MAP-E ルールを含む。
///
/// Packet layout:
///   07 aa bb cc              – Reply header
///   00 5e 00 47              – OPTION_S46_CONT_MAPE (len=71)
///     Rule1 (len=23): flags=FMR, ea_len=16, prefix4_len=15, ipv4=106.73.0.0
///                     ipv6=2404:9200:225:100::/64, portparams(offset=4,len=8,psid=0)
///     Rule2 (len=20): flags=0,  ea_len=18, prefix4_len=22, ipv4=133.203.160.0
///                     ipv6=2404:7a82:2000::/38, portparams(offset=4,len=8,psid=0)
///     BR (len=16):    2404:9200:225:100::64
const TWO_RULES_REPLY: &[u8] = &[
    // DHCPv6 Reply header
    0x07, 0xaa, 0xbb, 0xcc,
    // CONT_MAPE (code=0x5e, len=0x47=71)
    0x00, 0x5e, 0x00, 0x47,
    // Rule 1 (code=0x59, len=0x17=23)
    0x00, 0x59, 0x00, 0x17,
    0x01, 0x10, 0x0f,               // flags=FMR, ea_len=16, prefix4_len=15
    0x6a, 0x49, 0x00, 0x00,         // ipv4=106.73.0.0
    0x40,                           // ipv6_prefix_len=64
    0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00, // ipv6=2404:9200:225:100::
    0x00, 0x5d, 0x00, 0x03,         // PORTPARAMS
    0x48, 0x00, 0x00,               // offset=4, psid_len=8, psid=0
    // Rule 2 (code=0x59, len=0x14=20)
    0x00, 0x59, 0x00, 0x14,
    0x00, 0x12, 0x16,               // flags=0, ea_len=18, prefix4_len=22
    0x85, 0xcb, 0xa0, 0x00,         // ipv4=133.203.160.0
    0x26,                           // ipv6_prefix_len=38
    0x24, 0x04, 0x7a, 0x82, 0x20,  // ipv6=2404:7a82:2000:: (5 bytes for /38)
    0x00, 0x5d, 0x00, 0x03,         // PORTPARAMS
    0x48, 0x00, 0x00,               // offset=4, psid_len=8, psid=0
    // BR (code=0x5a, len=0x10=16)
    0x00, 0x5a, 0x00, 0x10,
    0x24, 0x04, 0x92, 0x00, 0x02, 0x25, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // 2404:9200:225:100::64
];

// ── テストケース ──────────────────────────────────────────────────────────────

/// dhcp_e2e_01: v6plus 相当のキャプチャバイト列をパースし全フィールドを検証する。
#[test]
fn dhcp_e2e_01_single_rule_all_fields() {
    let rules = parse_mape_option(SINGLE_RULE_REPLY)
        .expect("parse error")
        .expect("no rules returned");

    assert_eq!(rules.len(), 1);
    let rule = &rules[0];

    assert_eq!(rule.ipv4_prefix, Ipv4Addr::new(106, 73, 0, 0));
    assert_eq!(rule.prefix4_len, 15);
    assert_eq!(rule.ea_len, 16);
    assert_eq!(
        rule.ipv6_prefix,
        "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(rule.prefix6_len, 64);
    assert_eq!(rule.port_params.psid_offset, 4);
    assert_eq!(rule.port_params.psid_len, 8);
    assert_eq!(rule.port_params.psid, Some(0));
    assert_eq!(
        rule.br_addr,
        "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap()
    );
    assert!(rule.is_fmr);
}

/// dhcp_e2e_02: 複数の BMR を含むオプションのパース検証。
#[test]
fn dhcp_e2e_02_two_rules_size_and_fields() {
    let rules = parse_mape_option(TWO_RULES_REPLY)
        .expect("parse error")
        .expect("no rules returned");

    assert_eq!(rules.len(), 2);

    // Rule 1
    let r1 = &rules[0];
    assert_eq!(r1.ipv4_prefix, Ipv4Addr::new(106, 73, 0, 0));
    assert_eq!(r1.prefix4_len, 15);
    assert_eq!(r1.ea_len, 16);
    assert_eq!(r1.prefix6_len, 64);
    assert!(r1.is_fmr);

    // Rule 2
    let r2 = &rules[1];
    assert_eq!(r2.ipv4_prefix, Ipv4Addr::new(133, 203, 160, 0));
    assert_eq!(r2.prefix4_len, 22);
    assert_eq!(r2.ea_len, 18);
    assert_eq!(r2.prefix6_len, 38);
    assert_eq!(
        r2.ipv6_prefix,
        "2404:7a82:2000::".parse::<Ipv6Addr>().unwrap()
    );
    assert!(!r2.is_fmr);

    // 両ルールとも同一の BR アドレス
    let expected_br: Ipv6Addr = "2404:9200:225:100::64".parse().unwrap();
    assert_eq!(r1.br_addr, expected_br);
    assert_eq!(r2.br_addr, expected_br);
}

/// dhcp_e2e_03: パース成功 → try_compute まで MapeParams を導出できることを確認する。
#[test]
fn dhcp_e2e_03_parse_to_try_compute() {
    let rules = parse_mape_option(SINGLE_RULE_REPLY)
        .expect("parse error")
        .expect("no rules returned");

    let rule = &rules[0];

    // CE プレフィックス: 2404:9200:225:100::/80
    // EA-bits（bits 64-79）= 0x0000 → IPv4 suffix=0 → IPv4=106.73.0.0
    // PSID = rule.port_params.psid = Some(0)
    let ce_prefix: Ipv6Addr = "2404:9200:225:100::".parse().unwrap();
    let params = rule
        .try_compute(ce_prefix, 80, 1023, false)
        .expect("try_compute failed");

    assert_eq!(params.ipv4_addr, Ipv4Addr::new(106, 73, 0, 0));
    assert_eq!(params.psid, 0);
    assert_eq!(
        params.br_ipv6_addr,
        "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap()
    );
    // RFC モードの CE IPv6: prefix | EA-bits | IID(0000:ipv4:psid)
    // = 2404:9200:225:100:0:6a49::
    assert_eq!(
        params.ce_ipv6_addr,
        "2404:9200:225:100:0:6a49::".parse::<Ipv6Addr>().unwrap()
    );
    // ポートレンジが空でないことを確認
    assert!(!params.port_ranges.is_empty());
    assert!(params.port_start <= params.port_end);
}

/// dhcp_e2e_04: CE プレフィックス長が不足している場合に InvalidCePrefix が返る。
#[test]
fn dhcp_e2e_04_insufficient_ce_prefix_len() {
    let rules = parse_mape_option(SINGLE_RULE_REPLY)
        .expect("parse error")
        .expect("no rules returned");

    let rule = &rules[0];

    // prefix6_len=64, ea_len=16 → 最低 80 ビット必要
    // ce_prefix_len=79 は不足
    let ce_prefix: Ipv6Addr = "2404:9200:225:100::".parse().unwrap();
    let result = rule.try_compute(ce_prefix, 79, 1023, false);

    assert!(
        matches!(result, Err(MapEError::InvalidCePrefix)),
        "expected InvalidCePrefix"
    );
}
