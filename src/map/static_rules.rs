use serde::Deserialize;

use super::rule::MapRule;
use super::{ocn_vc_rules, v6plus_rules};

/// MAP 設定プロファイル。設定ファイルの `map_profile` フィールドで必ず指定する。
///
/// `v6plus` と `ocn_vc` はいずれも静的ルールを使用し DHCPv6 キャプチャを行わない。
/// CE IPv6 アドレス導出は両プロファイルとも Internet Draft 方式を使用する。
/// ルールデータのみが異なる。
///
/// | プロファイル | ルール取得元                  | CE IPv6 計算方式              | DHCPv6 キャプチャ |
/// |------------|------------------------------|-------------------------------|-----------------|
/// | `v6plus`   | `assets/v6plus_rules.json`   | Internet Draft 方式           | なし             |
/// | `ocn_vc`   | `assets/ocn_vc_rules.json`   | Internet Draft 方式           | なし             |
/// | `dhcpv6`   | DHCPv6 キャプチャ             | RFC 7597 標準方式             | あり             |
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapProfile {
    /// v6プラス対応サービス向け（JPIX 規格）。
    V6plus,
    /// OCN バーチャルコネクト向け（JPNE 規格）。
    /// v6プラスと同様に静的ルールを使用し DHCPv6 キャプチャを行わない。
    /// CE IPv6 は Internet Draft 方式で導出。ルールデータのみ v6プラスと異なる。
    OcnVc,
    /// DHCPv6 キャプチャモード（RFC 7598 準拠 ISP 向け）。
    Dhcpv6,
}

impl MapProfile {
    /// このプロファイルに対応する静的 BMR テーブルを返す。
    /// `Dhcpv6` の場合は `None`（DHCPv6 キャプチャからルールを取得する）。
    pub fn static_rules(&self) -> Option<&'static [MapRule]> {
        match self {
            MapProfile::V6plus => Some(v6plus_rules::v6plus_rules()),
            MapProfile::OcnVc => Some(ocn_vc_rules::ocn_vc_rules()),
            MapProfile::Dhcpv6 => None,
        }
    }

    /// CE IPv6 アドレスの計算に v6プラス方式（Internet Draft）を使うか否かを返す。
    ///
    /// `true` の場合は `calc::build_ce_ipv6_v6plus`、`false` の場合は `calc::build_ce_ipv6_rfc` が使われる。
    pub fn use_v6plus_ce_calc(&self) -> bool {
        matches!(self, MapProfile::V6plus | MapProfile::OcnVc)
    }
}
