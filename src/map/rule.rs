use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::error::MapEError;

use super::{calc, port_set};

/// MAP Rule（BMR: Basic Mapping Rule）1 件分。
/// キャッシュ保存に serde_json を使用するため `#[derive(Serialize, Deserialize, Clone)]` を付与する。
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

impl MapRule {
    /// CE プレフィックスから MAP-E パラメータ一式を計算する。
    ///
    /// `ce_prefix_len < rule.prefix6_len + rule.ea_len` の場合は `MapEError::InvalidCePrefix` を返す。
    /// `p_exclude_max` は `Config::p_exclude_max`（デフォルト 1023）を渡す。
    /// `use_v6plus` は `Config::use_v6plus_static_rules` と同値とする。
    pub fn try_compute(
        &self,
        ce_prefix: Ipv6Addr,
        ce_prefix_len: u8,
        p_exclude_max: u16,
        use_v6plus: bool,
    ) -> Result<MapeParams, MapEError> {
        if ce_prefix_len < self.prefix6_len + self.ea_len {
            return Err(MapEError::InvalidCePrefix);
        }

        let ce_prefix_bits = u128::from_be_bytes(ce_prefix.octets());
        let rule_prefix_bits = u128::from_be_bytes(self.ipv6_prefix.octets());

        let ea_bits =
            calc::extract_ea_bits(ce_prefix_bits, self.prefix6_len, self.ea_len);

        let ipv4_addr =
            calc::derive_ipv4_addr(ea_bits, self.ipv4_prefix, self.prefix4_len, self.port_params.psid_len);

        let psid = self
            .port_params
            .psid
            .unwrap_or_else(|| calc::derive_psid(ea_bits, self.port_params.psid_len));

        let ce_ipv6_addr = if use_v6plus {
            calc::build_ce_ipv6_v6plus(
                rule_prefix_bits,
                self.prefix6_len,
                ea_bits,
                self.ea_len,
                ipv4_addr,
                psid,
                self.port_params.psid_len,
            )
        } else {
            calc::build_ce_ipv6_rfc(
                rule_prefix_bits,
                self.prefix6_len,
                ea_bits,
                self.ea_len,
                ipv4_addr,
                psid,
                self.port_params.psid_len,
            )
        };

        let a_min = port_set::calc_a_min(
            self.port_params.psid_offset,
            self.port_params.psid_len,
            p_exclude_max,
        );
        let port_ranges = port_set::calc_port_ranges(
            self.port_params.psid_offset,
            self.port_params.psid_len,
            psid,
            a_min,
        );
        let (port_start, port_end) = port_set::calc_continuous_range(
            self.port_params.psid_offset,
            self.port_params.psid_len,
            psid,
            a_min,
        );

        let mut port_params = self.port_params.clone();
        port_params.psid = Some(psid);

        Ok(MapeParams {
            ipv4_addr,
            ce_ipv6_addr,
            br_ipv6_addr: self.br_addr,
            psid,
            port_params,
            port_ranges,
            port_start,
            port_end,
            a_min,
            is_fmr: self.is_fmr,
            fmr_ipv4_prefix: self.ipv4_prefix,
            fmr_prefix4_len: self.prefix4_len,
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PortParams {
    pub psid_offset: u8, // a: PSID offset（v6プラスは 4）
    pub psid_len: u8,    // k: PSID length（v6プラスは 8）
    /// この CE に割り当てられた PSID 値。
    /// `Some(v)` の場合は DHCPv6 の OPTION_S46_PORTPARAMS 等で明示的に割り当てられた値を表し、
    /// `try_compute` はこの値をそのまま使用する。
    /// `None` の場合は `try_compute` が CE プレフィックスの EA-bits から算出する。
    /// 静的ルール（v6plus / ocn_vc）では `None` を設定する。
    #[serde(default)]
    pub psid: Option<u16>,
}

/// CE（Customer Edge）に対して計算された MAP-E パラメータ一式。
#[derive(Clone)]
pub struct MapeParams {
    pub ipv4_addr: Ipv4Addr,    // CE の IPv4 アドレス
    pub ce_ipv6_addr: Ipv6Addr, // CE の IPv6 アドレス（トンネル local）
    pub br_ipv6_addr: Ipv6Addr, // BR の IPv6 アドレス（トンネル remote）
    /// PSID 値。`try_compute` が設定する解決済みの値。
    /// `port_params.psid` が `Some` の場合はその値をそのまま使用し、
    /// `None` の場合は EA-bits から算出した値が格納される。
    pub psid: u16,
    pub port_params: PortParams,
    pub port_ranges: Vec<(u16, u16)>, // 利用可能ポートレンジ一覧（MAP-E ポート集合 S）
    pub port_start: u16,              // nftables SNAT 用連続レンジ開始（ポート集合 C の先頭）
    pub port_end: u16,                // nftables SNAT 用連続レンジ終了（ポート集合 C の末尾）
    /// 実効的な R 下限。`calc_a_min` の結果。
    pub a_min: u16,
    /// マッチした `MapRule::is_fmr` の値。`try_compute` が `self.is_fmr` をそのままコピーする。
    pub is_fmr: bool,
    /// マッチした `MapRule::ipv4_prefix`。FMR ルート設定時（`is_fmr == true`）に使用する。
    pub fmr_ipv4_prefix: Ipv4Addr,
    /// マッチした `MapRule::prefix4_len`。FMR ルート設定時（`is_fmr == true`）に使用する。
    pub fmr_prefix4_len: u8,
}
