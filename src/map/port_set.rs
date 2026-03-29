/// a_min を算出する。
///
/// `a_min = max(1, ceil((p_exclude_max + 1) / 2^(psid_len + M)))`
/// ただし `M = 16 - psid_offset - psid_len`
///
/// 前提: `psid_offset + psid_len < 16`
#[inline]
pub fn calc_a_min(psid_offset: u8, psid_len: u8, p_exclude_max: u16) -> u16 {
    let m_bits = 16u8
        .checked_sub(psid_offset + psid_len)
        .expect("psid_offset + psid_len must be < 16");
    let divisor = 1u32 << (psid_len + m_bits); // 2^(psid_len + M)
    let numerator = p_exclude_max as u32 + 1;
    // ceil(numerator / divisor) = (numerator + divisor - 1) / divisor
    let a_min = (numerator + divisor - 1) / divisor;
    a_min.max(1) as u16
}

/// 利用可能なポートレンジ一覧を返す。
///
/// `psid_offset > 0` の場合:
///   `Port(R, m) = (R << (psid_len + M)) + (psid << M) + m`
///   `R ∈ [a_min, 2^psid_offset - 1], m ∈ [0, 2^M - 1]`
///   ただし `M = 16 - psid_offset - psid_len`
///
/// `psid_offset == 0` の場合:
///   単一連続ブロック `vec![(psid << M, (psid << M) + (1 << M) - 1)]`
///   ただし `M = 16 - psid_len`（a_min は使用しない）
///
/// 特殊ケース: `psid_offset == 0 && psid_len == 0` は全ポート `(0, u16::MAX)`
pub fn calc_port_ranges(psid_offset: u8, psid_len: u8, psid: u16, a_min: u16) -> Vec<(u16, u16)> {
    // psid_offset=0 && psid_len=0: M=16 となり通常のシフトが u16 範囲を超えるため特別処理
    if psid_offset == 0 && psid_len == 0 {
        return vec![(0, u16::MAX)];
    }

    if psid_offset == 0 {
        // M = 16 - psid_len（psid_len > 0 が保証される）
        let m_bits = 16 - psid_len;
        let start = (psid as u32) << m_bits;
        let end = start + (1u32 << m_bits) - 1;
        return vec![(start as u16, end as u16)];
    }

    // psid_offset > 0: 非連続ポートセット
    let m_bits = 16u8
        .checked_sub(psid_offset + psid_len)
        .expect("psid_offset + psid_len must be < 16");
    let r_max = (1u16 << psid_offset) - 1;

    let mut ranges = Vec::new();
    for r in a_min..=r_max {
        let start = ((r as u32) << (psid_len + m_bits)) | ((psid as u32) << m_bits);
        let end = start + (1u32 << m_bits) - 1;
        ranges.push((start as u16, end as u16));
    }
    ranges
}

/// nftables SNAT 用連続レンジを返す。
///
/// `psid_offset > 0` の場合:
///   `PORT_START = (1 << 15) + (a_min << M)`
///   `PORT_END   = PORT_START + (2^psid_offset - a_min) * 2^M - 1`
///   PORT_END が u16::MAX を超える場合は u16::MAX に飽和させる。
///
/// `psid_offset == 0` の場合:
///   `PORT_START = psid << M`（`M = 16 - psid_len`）
///   `PORT_END   = PORT_START + (1 << M) - 1`
///
/// 特殊ケース: `psid_offset == 0 && psid_len == 0` は `(0, u16::MAX)`
pub fn calc_continuous_range(
    psid_offset: u8,
    psid_len: u8,
    psid: u16,
    a_min: u16,
) -> (u16, u16) {
    // psid_offset=0 && psid_len=0: M=16 となり通常のシフトが u16 範囲を超えるため特別処理
    if psid_offset == 0 && psid_len == 0 {
        return (0, u16::MAX);
    }

    if psid_offset == 0 {
        let m_bits = 16 - psid_len;
        let start = (psid as u32) << m_bits;
        let end = start + (1u32 << m_bits) - 1;
        return (start as u16, end as u16);
    }

    // psid_offset > 0
    let m_bits = 16u8
        .checked_sub(psid_offset + psid_len)
        .expect("psid_offset + psid_len must be < 16");

    // PORT_START = (1 << 15) + (a_min << M)
    let port_start = (1u32 << 15) + ((a_min as u32) << m_bits);
    // PORT_END = PORT_START + (2^psid_offset - a_min) * 2^M - 1
    let num_blocks = (1u32 << psid_offset) - a_min as u32;
    let total_ports = num_blocks * (1u32 << m_bits);
    let port_end = port_start
        .saturating_add(total_ports - 1)
        .min(u16::MAX as u32);

    (port_start as u16, port_end as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // v6プラス固定パラメータ: a=4, k=8, M=4
    // a_min: p_exclude_max=1023 → ceil(1024 / 2^12) = 1

    #[test]
    fn test_calc_a_min_v6plus() {
        // v6plus: a=4, k=8, M=4
        // a_min = max(1, ceil(1024 / 4096)) = max(1, 1) = 1
        assert_eq!(calc_a_min(4, 8, 1023), 1);
    }

    #[test]
    fn test_calc_a_min_larger_p_exclude() {
        // p_exclude_max=4095: ceil(4096 / 4096) = 1
        assert_eq!(calc_a_min(4, 8, 4095), 1);
    }

    #[test]
    fn test_calc_a_min_p_exclude_forces_a_min_2() {
        // p_exclude_max=4096: ceil(4097 / 4096) = 2
        assert_eq!(calc_a_min(4, 8, 4096), 2);
    }

    // calc_port_ranges のテスト

    #[test]
    fn test_calc_port_ranges_v6plus_psid5() {
        // v6plus: a=4, k=8, M=4, PSID=5, a_min=1
        // R∈[1,15]: Port(R,m) = (R<<12) | (5<<4) | m
        let ranges = calc_port_ranges(4, 8, 5, 1);
        assert_eq!(ranges.len(), 15);
        // R=1: (1<<12)|(5<<4) = 4096|80 = 4176, end = 4191
        assert_eq!(ranges[0], (4176, 4191));
        // R=2: (2<<12)|(5<<4) = 8192|80 = 8272, end = 8287
        assert_eq!(ranges[1], (8272, 8287));
        // R=15: (15<<12)|(5<<4) = 61440|80 = 61520, end = 61535
        assert_eq!(ranges[14], (61520, 61535));
    }

    #[test]
    fn test_calc_port_ranges_v6plus_psid_zero() {
        // PSID=0（最小）
        let ranges = calc_port_ranges(4, 8, 0, 1);
        assert_eq!(ranges.len(), 15);
        // R=1: (1<<12)|(0<<4) = 4096, end = 4111
        assert_eq!(ranges[0], (4096, 4111));
        // R=15: (15<<12)|0 = 61440, end = 61455
        assert_eq!(ranges[14], (61440, 61455));
    }

    #[test]
    fn test_calc_port_ranges_v6plus_psid_max() {
        // PSID=255（最大）
        let ranges = calc_port_ranges(4, 8, 255, 1);
        assert_eq!(ranges.len(), 15);
        // R=1: (1<<12)|(255<<4) = 4096|4080 = 8176, end = 8191
        assert_eq!(ranges[0], (8176, 8191));
        // R=15: (15<<12)|(255<<4) = 61440|4080 = 65520, end = 65535
        assert_eq!(ranges[14], (65520, 65535));
    }

    #[test]
    fn test_calc_port_ranges_psid_offset_zero() {
        // psid_offset=0: 単一連続ブロック（a_min は使用しない）
        // M = 16 - 8 = 8, PSID=5
        // start = 5<<8 = 1280, end = 1280 + 255 = 1535
        let ranges = calc_port_ranges(0, 8, 5, 0);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (1280, 1535));
    }

    #[test]
    fn test_calc_port_ranges_psid_offset_zero_psid_len_zero() {
        // 全ポート
        let ranges = calc_port_ranges(0, 0, 0, 0);
        assert_eq!(ranges, vec![(0, u16::MAX)]);
    }

    // calc_continuous_range のテスト

    #[test]
    fn test_calc_continuous_range_v6plus() {
        // v6plus: a=4, k=8, M=4, a_min=1
        // PORT_START = (1<<15) + (1<<4) = 32768 + 16 = 32784
        // PORT_END = 32784 + (16-1)*16 - 1 = 32784 + 239 = 33023
        let (start, end) = calc_continuous_range(4, 8, 5, 1);
        assert_eq!(start, 32784);
        assert_eq!(end, 33023);
    }

    #[test]
    fn test_calc_continuous_range_v6plus_a_min_2() {
        // a_min=2 のケース
        // PORT_START = (1<<15) + (2<<4) = 32768 + 32 = 32800
        // PORT_END = 32800 + (16-2)*16 - 1 = 32800 + 223 = 33023
        let (start, end) = calc_continuous_range(4, 8, 5, 2);
        assert_eq!(start, 32800);
        assert_eq!(end, 33023);
    }

    #[test]
    fn test_calc_continuous_range_psid_offset_zero() {
        // psid_offset=0: MAP-E ポートレンジと一致
        // M=8, PSID=5: start=1280, end=1535
        let (start, end) = calc_continuous_range(0, 8, 5, 0);
        assert_eq!(start, 1280);
        assert_eq!(end, 1535);
    }

    #[test]
    fn test_calc_continuous_range_psid_offset_zero_psid_len_zero() {
        let (start, end) = calc_continuous_range(0, 0, 0, 0);
        assert_eq!((start, end), (0, u16::MAX));
    }
}
