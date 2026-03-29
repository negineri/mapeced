use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MapEError {
    #[error("config file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// EA-bits 長と CE prefix 長の不一致
    #[error("EA-bits length and CE prefix length mismatch")]
    InvalidCePrefix,

    /// IA_PD にマッチする MAP Rule が pending_map_rules に存在しない
    #[error("no MAP rule matches the IA_PD prefix")]
    NoPrefixMatch,

    /// OPTION_S46_BR が省略された
    #[error("OPTION_S46_BR is missing")]
    MissingBrAddress,

    /// calc_port_ranges の結果が空（nftables 適用ガード）
    #[error("port ranges are empty")]
    EmptyPortRanges,

    #[error("netlink error: {0}")]
    NetlinkError(String),

    #[error("nft error: {0}")]
    NftError(String),
}
