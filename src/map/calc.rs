use std::net::{Ipv4Addr, Ipv6Addr};

/// CE プレフィックスから EA-bits を抽出する。
///
/// `ce_prefix` は IPv6 アドレスを big-endian で u128 に格納した値（MSB = IPv6 先頭ビット = bit127）。
/// `u128::from_be_bytes(addr.octets())` で変換する。
/// ce_prefix の bit[rule_prefix_len .. rule_prefix_len+ea_len] を取り出す。
/// シフト量は `128 - rule_prefix_len - ea_len`（ce_prefix_len は引数に不要）。
#[inline]
pub fn extract_ea_bits(ce_prefix: u128, rule_prefix_len: u8, ea_len: u8) -> u32 {
    let shift = 128 - rule_prefix_len - ea_len;
    let mask = if ea_len == 0 {
        0u128
    } else {
        (1u128 << ea_len) - 1
    };
    ((ce_prefix >> shift) & mask) as u32
}

/// EA-bits から IPv4 アドレスを導出する。
///
/// `ipv4_suffix = ea_bits >> psid_len`
/// `ipv4_addr   = ipv4_prefix | ipv4_suffix`
#[inline]
pub fn derive_ipv4_addr(
    ea_bits: u32,
    ipv4_prefix: Ipv4Addr,
    _prefix4_len: u8,
    psid_len: u8,
) -> Ipv4Addr {
    let ipv4_suffix = ea_bits >> psid_len;
    let prefix = u32::from(ipv4_prefix);
    Ipv4Addr::from(prefix | ipv4_suffix)
}

/// EA-bits から PSID を導出する。
///
/// `psid = ea_bits & ((1 << psid_len) - 1)`
#[inline]
pub fn derive_psid(ea_bits: u32, psid_len: u8) -> u16 {
    if psid_len == 0 {
        return 0;
    }
    let mask = (1u32 << psid_len) - 1;
    (ea_bits & mask) as u16
}

/// CE の IPv6 アドレスを構成する（RFC 7597 モード）。
///
/// アドレス全体のレイアウト（RFC 7597 Section 5.2 準拠）:
/// `[rule_ipv6_prefix (prefix6_len bits)][EA-bits (ea_len bits)][0x0000 (16 bits)][IPv4 (32 bits)][PSID (16 bits)]`
///
/// IID: `[0x0000(16)] [IPv4(32)] [PSID(16)]`
/// PSID フィールド（16 bit）への配置: 右詰め（`psid` をそのまま下位に配置）。
/// `psid_len` は PSID 値の確認用。IID 構成時のシフト量には使用しない。
#[inline]
pub fn build_ce_ipv6_rfc(
    rule_ipv6_prefix: u128,
    rule_prefix_len: u8,
    ea_bits: u32,
    ea_len: u8,
    ipv4_addr: Ipv4Addr,
    psid: u16,
    _psid_len: u8,
) -> Ipv6Addr {
    let ea_shift = 128 - rule_prefix_len - ea_len;
    let base = rule_ipv6_prefix | ((ea_bits as u128) << ea_shift);

    // IID: [0x0000(16)] [IPv4(32)] [PSID(16)]
    // bits 47..16: IPv4（<< 16）, bits 15..0: PSID
    let iid = ((u32::from(ipv4_addr) as u128) << 16) | (psid as u128);

    let upper = base & (u128::MAX << 64);
    Ipv6Addr::from(upper | iid)
}

/// CE の IPv6 アドレスを構成する（v6プラス Draft モード）。
///
/// アドレス全体のレイアウト（v6plus-spec.md Draft 準拠）:
/// `[rule_ipv6_prefix (prefix6_len bits)][EA-bits (ea_len bits)][0x00 (8 bits)][IPv4 (32 bits)][PSID (16 bits)][0x00 (8 bits)]`
///
/// IID: `[0x00(8)] [IPv4(32)] [PSID left-aligned(16)] [0x00(8)]`
/// PSID フィールド（16 bit）への配置: 左詰め（`psid << (16 - psid_len)` で上位に詰める）。
#[inline]
pub fn build_ce_ipv6_v6plus(
    rule_ipv6_prefix: u128,
    rule_prefix_len: u8,
    ea_bits: u32,
    ea_len: u8,
    ipv4_addr: Ipv4Addr,
    psid: u16,
    psid_len: u8,
) -> Ipv6Addr {
    let ea_shift = 128 - rule_prefix_len - ea_len;
    let base = rule_ipv6_prefix | ((ea_bits as u128) << ea_shift);

    // IID: [0x00(8)] [IPv4(32)] [PSID left-aligned(16)] [0x00(8)]
    // bits 55..24: IPv4（<< 24）, bits 23..8: PSID 左詰め（<< 8）
    let psid_leftpad: u128 = if psid_len == 0 {
        0
    } else {
        (psid as u128) << (16 - psid_len)
    };
    let iid = ((u32::from(ipv4_addr) as u128) << 24) | (psid_leftpad << 8);

    let upper = base & (u128::MAX << 64);
    Ipv6Addr::from(upper | iid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // テスト用パラメータ（v6プラス固定値: a=4, k=8, M=4）
    // rule_prefix: 2001:db8::/32（TEST-NET-1 相当）
    // IPv4 prefix: 203.0.113.0/24（TEST-NET-3, RFC 5737）
    // CE prefix = rule_prefix(32) | ea_bits(16) | zeros
    // EA-bits レイアウト: [IPv4_suffix(8)] [PSID(8)]

    // テスト用 CE プレフィックスを生成する
    fn ce_prefix_u128(ea_bits_val: u16) -> u128 {
        // rule_prefix(32) = 2001:0db8::
        let rule: u128 = 0x20010db8_00000000_00000000_00000000;
        // ea_bits を bits 95..80 に配置（ea_shift = 128 - 32 - 16 = 80）
        rule | ((ea_bits_val as u128) << 80)
    }

    #[test]
    fn test_extract_ea_bits_v6plus() {
        // EA-bits = 0x01AB: IPv4_suffix=1, PSID=0xAB
        assert_eq!(extract_ea_bits(ce_prefix_u128(0x01AB), 32, 16), 0x01AB);
    }

    #[test]
    fn test_extract_ea_bits_psid_zero() {
        // PSID=0, IPv4_suffix=5 → EA-bits = 0x0500
        assert_eq!(extract_ea_bits(ce_prefix_u128(0x0500), 32, 16), 0x0500);
    }

    #[test]
    fn test_extract_ea_bits_psid_max() {
        // PSID=255（最大）, IPv4_suffix=0 → EA-bits = 0x00FF
        assert_eq!(extract_ea_bits(ce_prefix_u128(0x00FF), 32, 16), 0x00FF);
    }

    #[test]
    fn test_derive_ipv4_addr() {
        // ea_bits=0x01AB, psid_len=8 → suffix=1 → 203.0.113.1
        let result = derive_ipv4_addr(
            0x01AB,
            Ipv4Addr::new(203, 0, 113, 0),
            24,
            8,
        );
        assert_eq!(result, Ipv4Addr::new(203, 0, 113, 1));
    }

    #[test]
    fn test_derive_ipv4_addr_psid_zero() {
        // ea_bits=0x0500, psid_len=8 → suffix=5 → 203.0.113.5
        let result = derive_ipv4_addr(
            0x0500,
            Ipv4Addr::new(203, 0, 113, 0),
            24,
            8,
        );
        assert_eq!(result, Ipv4Addr::new(203, 0, 113, 5));
    }

    #[test]
    fn test_derive_ipv4_addr_psid_max() {
        // ea_bits=0x00FF, psid_len=8 → suffix=0 → 203.0.113.0
        let result = derive_ipv4_addr(
            0x00FF,
            Ipv4Addr::new(203, 0, 113, 0),
            24,
            8,
        );
        assert_eq!(result, Ipv4Addr::new(203, 0, 113, 0));
    }

    #[test]
    fn test_derive_psid() {
        // ea_bits=0x01AB, psid_len=8 → psid=0xAB=171
        assert_eq!(derive_psid(0x01AB, 8), 0xAB);
    }

    #[test]
    fn test_derive_psid_zero() {
        // PSID=0
        assert_eq!(derive_psid(0x0500, 8), 0);
    }

    #[test]
    fn test_derive_psid_max() {
        // PSID=255（最大）
        assert_eq!(derive_psid(0x00FF, 8), 255);
    }

    #[test]
    fn test_build_ce_ipv6_rfc() {
        // rule: 2001:db8::/32, ea_bits=0x01AB, ea_len=16
        // IPv4=203.0.113.1 (0xCB007101), PSID=0xAB=171, psid_len=8
        //
        // base upper64: 0x20010DB8_01AB0000（group2 = 0x01AB）
        // IID: (0xCB007101 << 16) | 0xAB = 0x0000CB00_710100AB
        // groups 4..7: 0x0000, 0xCB00, 0x7101, 0x00AB
        // → 2001:0db8:01ab:0000:0000:cb00:7101:00ab
        let rule_prefix: u128 = 0x20010db8_00000000_00000000_00000000;
        let result = build_ce_ipv6_rfc(
            rule_prefix,
            32,
            0x01AB,
            16,
            Ipv4Addr::new(203, 0, 113, 1),
            0xAB,
            8,
        );
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0x01ab, 0x0000, 0x0000, 0xcb00, 0x7101, 0x00ab);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_ce_ipv6_rfc_psid_zero() {
        // PSID=0 の境界値テスト
        // ea_bits=0x0500, IPv4=203.0.113.5 (0xCB007105)
        // IID: (0xCB007105 << 16) | 0 = 0x0000CB00_71050000
        // groups 4..7: 0x0000, 0xCB00, 0x7105, 0x0000
        let rule_prefix: u128 = 0x20010db8_00000000_00000000_00000000;
        let result = build_ce_ipv6_rfc(
            rule_prefix,
            32,
            0x0500,
            16,
            Ipv4Addr::new(203, 0, 113, 5),
            0,
            8,
        );
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0x0500, 0x0000, 0x0000, 0xcb00, 0x7105, 0x0000);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_ce_ipv6_rfc_psid_max() {
        // PSID=255（最大）の境界値テスト
        // ea_bits=0x00FF, IPv4=203.0.113.0 (0xCB007100)
        // IID: (0xCB007100 << 16) | 255 = 0x0000CB00_710000FF
        // groups 4..7: 0x0000, 0xCB00, 0x7100, 0x00FF
        let rule_prefix: u128 = 0x20010db8_00000000_00000000_00000000;
        let result = build_ce_ipv6_rfc(
            rule_prefix,
            32,
            0x00FF,
            16,
            Ipv4Addr::new(203, 0, 113, 0),
            255,
            8,
        );
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0x00ff, 0x0000, 0x0000, 0xcb00, 0x7100, 0x00ff);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_ce_ipv6_v6plus() {
        // rule: 2001:db8::/32, ea_bits=0x01AB, ea_len=16
        // IPv4=203.0.113.1 (0xCB007101), PSID=0xAB=171, psid_len=8
        //
        // psid_leftpad = 0xAB << 8 = 0xAB00
        // IID: (0xCB007101 << 24) | (0xAB00 << 8)
        //    = 0x00CB007101000000 | 0x0000000000AB0000
        //    = 0x00CB007101AB0000
        // groups 4..7: 0x00CB, 0x0071, 0x01AB, 0x0000
        // → 2001:0db8:01ab:0000:00cb:0071:01ab:0000
        let rule_prefix: u128 = 0x20010db8_00000000_00000000_00000000;
        let result = build_ce_ipv6_v6plus(
            rule_prefix,
            32,
            0x01AB,
            16,
            Ipv4Addr::new(203, 0, 113, 1),
            0xAB,
            8,
        );
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0x01ab, 0x0000, 0x00cb, 0x0071, 0x01ab, 0x0000);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_ce_ipv6_v6plus_psid_zero() {
        // PSID=0 の境界値テスト
        // ea_bits=0x0500, IPv4=203.0.113.5 (0xCB007105)
        // psid_leftpad = 0
        // IID: (0xCB007105 << 24) | 0 = 0x00CB007105000000
        // groups 4..7: 0x00CB, 0x0071, 0x0500, 0x0000
        let rule_prefix: u128 = 0x20010db8_00000000_00000000_00000000;
        let result = build_ce_ipv6_v6plus(
            rule_prefix,
            32,
            0x0500,
            16,
            Ipv4Addr::new(203, 0, 113, 5),
            0,
            8,
        );
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0x0500, 0x0000, 0x00cb, 0x0071, 0x0500, 0x0000);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_ce_ipv6_v6plus_psid_max() {
        // PSID=255（最大）の境界値テスト
        // ea_bits=0x00FF, IPv4=203.0.113.0 (0xCB007100)
        // psid_leftpad = 0xFF << 8 = 0xFF00
        // IID: (0xCB007100 << 24) | (0xFF00 << 8)
        //    = 0x00CB007100000000 | 0x0000000000FF0000
        //    = 0x00CB007100FF0000
        // groups 4..7: 0x00CB, 0x0071, 0x00FF, 0x0000
        let rule_prefix: u128 = 0x20010db8_00000000_00000000_00000000;
        let result = build_ce_ipv6_v6plus(
            rule_prefix,
            32,
            0x00FF,
            16,
            Ipv4Addr::new(203, 0, 113, 0),
            255,
            8,
        );
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0x00ff, 0x0000, 0x00cb, 0x0071, 0x00ff, 0x0000);
        assert_eq!(result, expected);
    }
}
