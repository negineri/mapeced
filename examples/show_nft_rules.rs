/// nftables ルールセットの確認ツール
///
/// 使い方:
///   cargo run --example show_nft_rules
///   cargo run --example show_nft_rules -- --psid 0xab --a-min 1
///
/// デフォルトは v6プラス相当（psid_offset=4, psid_len=8, psid=0xab, a_min=1）

use std::net::{Ipv4Addr, Ipv6Addr};

use mapeced::map::rule::{MapeParams, PortParams};
use mapeced::nftables::manager::NftManager;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // 簡易引数パース
    let psid = parse_arg(&args, "--psid").unwrap_or(0xab);
    let a_min = parse_arg(&args, "--a-min").unwrap_or(1);
    let psid_offset = parse_arg(&args, "--psid-offset").unwrap_or(4);
    let psid_len = parse_arg(&args, "--psid-len").unwrap_or(8);
    let iface = args
        .windows(2)
        .find(|w| w[0] == "--iface")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "ip6tnl0".to_string());

    let params = MapeParams {
        ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
        ce_ipv6_addr: Ipv6Addr::UNSPECIFIED,
        br_ipv6_addr: Ipv6Addr::UNSPECIFIED,
        psid: psid as u16,
        port_params: PortParams {
            psid_offset: psid_offset as u8,
            psid_len: psid_len as u8,
            psid: Some(psid as u16),
        },
        port_ranges: vec![],
        port_start: (1u16 << 15) + (a_min as u16) * 16,
        port_end: (1u16 << 15) + (a_min as u16) * 16 + 240 - 1,
        is_fmr: false,
        fmr_ipv4_prefix: Ipv4Addr::UNSPECIFIED,
        fmr_prefix4_len: 0,
    };

    let mgr = NftManager::new();
    let ruleset = mgr.generate_ruleset(&params, &iface);

    println!(
        "# nft ruleset  iface={iface}  psid=0x{psid:02x}  a_min={a_min}\n"
    );
    print!("{ruleset}");
}

fn parse_arg(args: &[String], name: &str) -> Option<u64> {
    args.windows(2)
        .find(|w| w[0] == name)
        .and_then(|w| {
            let s = &w[1];
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                s.parse().ok()
            }
        })
}
