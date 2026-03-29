use crate::map::rule::{MapeParams, MapRule};

pub struct DaemonState {
    /// 現在適用中のパラメータ（None = 未設定）
    pub params: Option<MapeParams>,
    /// DHCPv6 capture または静的ルールから受け取った MAP Rule
    pub pending_map_rules: Vec<MapRule>,
    /// 作成済みトンネルの ifindex
    pub tunnel_ifindex: Option<u32>,
    /// WAN インターフェースの ifindex（起動時に取得）
    pub wan_ifindex: u32,
}
