use tracing::info;

use crate::config::Config;
use crate::error::MapEError;
use crate::map::rule::MapeParams;
use crate::netlink::{addr, route, tunnel};
use crate::nftables::manager::{NftManager, TcManager};

use super::state::DaemonState;

/// 初回適用: トンネル作成 → アドレス付与 → ルート設定 → nftables + tc 適用
pub async fn apply(
    state: &mut DaemonState,
    new_params: MapeParams,
    config: &Config,
    rtnetlink: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) -> Result<(), MapEError> {
    // ポートレンジ空チェック（EmptyPortRanges ガード）
    if new_params.port_ranges.is_empty() {
        return Err(MapEError::EmptyPortRanges);
    }

    // トンネル作成（既存があれば削除して再作成）
    let tunnel_ifindex = tunnel::ensure_tunnel(
        rtnetlink,
        &config.tunnel_interface,
        new_params.ce_ipv6_addr,
        new_params.br_ipv6_addr,
        state.wan_ifindex,
        config.tunnel_mtu,
    )
    .await?;
    state.tunnel_ifindex = Some(tunnel_ifindex);

    // CE IPv6 を WAN インターフェースに付与
    addr::add_ipv6_addr(rtnetlink, state.wan_ifindex, new_params.ce_ipv6_addr).await?;

    // CE IPv4 をトンネルインターフェースに付与
    addr::add_ipv4_addr(rtnetlink, tunnel_ifindex, new_params.ipv4_addr).await?;

    // デフォルトルート追加
    route::add_default_route(rtnetlink, tunnel_ifindex).await?;

    // FMR ルート追加（is_fmr の場合のみ）
    if new_params.is_fmr {
        route::add_fmr_route(
            rtnetlink,
            new_params.fmr_ipv4_prefix,
            new_params.fmr_prefix4_len,
            tunnel_ifindex,
        )
        .await?;
    }

    // nftables 適用
    nft.apply(&new_params, &config.tunnel_interface).await?;

    // tc 適用
    tc.apply(&new_params, &config.tunnel_interface).await?;

    state.params = Some(new_params);
    info!("MAP-E configuration applied");
    Ok(())
}

/// 差分更新: 変化した項目のみ更新する
pub async fn update(
    state: &mut DaemonState,
    new_params: MapeParams,
    config: &Config,
    rtnetlink: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) -> Result<(), MapEError> {
    let old_params = state
        .params
        .as_ref()
        .expect("update called without existing params");

    match params_diff(old_params, &new_params) {
        ParamsDiff::NoChange => {
            info!("MAP-E params unchanged, skipping update");
        }
        ParamsDiff::BrChanged => {
            let tunnel_ifindex = state
                .tunnel_ifindex
                .expect("tunnel_ifindex should be set when params is Some");
            tunnel::update_tunnel_remote(rtnetlink, tunnel_ifindex, new_params.br_ipv6_addr)
                .await?;
            state.params = Some(new_params);
            info!("MAP-E BR address updated");
        }
        ParamsDiff::CeIpv6Changed => {
            let old_params = state.params.take().unwrap();
            let old_tunnel_ifindex = state.tunnel_ifindex.take().unwrap_or(0);

            // 旧 IPv6 アドレス削除
            let _ =
                addr::del_ipv6_addr(rtnetlink, state.wan_ifindex, old_params.ce_ipv6_addr).await;

            // 旧ルート削除（tunnel_ifindex が変わりうるため先に削除）
            let _ = route::del_default_route(rtnetlink, old_tunnel_ifindex).await;
            if old_params.is_fmr {
                let _ = route::del_fmr_route(
                    rtnetlink,
                    old_params.fmr_ipv4_prefix,
                    old_params.fmr_prefix4_len,
                    old_tunnel_ifindex,
                )
                .await;
            }

            // トンネル再作成
            let new_tunnel_ifindex = tunnel::ensure_tunnel(
                rtnetlink,
                &config.tunnel_interface,
                new_params.ce_ipv6_addr,
                new_params.br_ipv6_addr,
                state.wan_ifindex,
                config.tunnel_mtu,
            )
            .await?;
            state.tunnel_ifindex = Some(new_tunnel_ifindex);

            // 新 IPv6 アドレスを WAN に付与
            addr::add_ipv6_addr(rtnetlink, state.wan_ifindex, new_params.ce_ipv6_addr).await?;

            // IPv4 アドレス差し替え
            let _ =
                addr::del_ipv4_addr(rtnetlink, new_tunnel_ifindex, old_params.ipv4_addr).await;
            addr::add_ipv4_addr(rtnetlink, new_tunnel_ifindex, new_params.ipv4_addr).await?;

            // ルート再追加
            route::add_default_route(rtnetlink, new_tunnel_ifindex).await?;
            if new_params.is_fmr {
                route::add_fmr_route(
                    rtnetlink,
                    new_params.fmr_ipv4_prefix,
                    new_params.fmr_prefix4_len,
                    new_tunnel_ifindex,
                )
                .await?;
            }

            // nftables + tc 再適用
            nft.apply(&new_params, &config.tunnel_interface).await?;
            tc.apply(&new_params, &config.tunnel_interface).await?;

            state.params = Some(new_params);
            info!("MAP-E configuration updated (CE IPv6 changed)");
        }
    }

    Ok(())
}

/// クリーンアップ: tc → nftables → ルート → アドレス → トンネル の順に削除
pub async fn cleanup(
    state: &mut DaemonState,
    config: &Config,
    rtnetlink: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) -> Result<(), MapEError> {
    let params = match state.params.take() {
        Some(p) => p,
        None => return Ok(()),
    };

    let tunnel_ifindex = state.tunnel_ifindex.take();

    // tc クリーンアップ
    let _ = tc.cleanup(&config.tunnel_interface).await;

    // nftables テーブル削除
    nft.delete_table().await?;

    if let Some(idx) = tunnel_ifindex {
        // ルート削除
        let _ = route::del_default_route(rtnetlink, idx).await;
        if params.is_fmr {
            let _ = route::del_fmr_route(
                rtnetlink,
                params.fmr_ipv4_prefix,
                params.fmr_prefix4_len,
                idx,
            )
            .await;
        }

        // IPv4 アドレス削除（トンネルインターフェースから）
        let _ = addr::del_ipv4_addr(rtnetlink, idx, params.ipv4_addr).await;
    }

    // CE IPv6 アドレス削除（WAN インターフェースから）
    let _ = addr::del_ipv6_addr(rtnetlink, state.wan_ifindex, params.ce_ipv6_addr).await;

    // トンネル削除
    let _ = tunnel::delete_tunnel(rtnetlink, &config.tunnel_interface).await;

    info!("MAP-E configuration cleaned up");
    Ok(())
}

/// params の差分種別
#[derive(Debug, PartialEq)]
pub enum ParamsDiff {
    /// 変化なし
    NoChange,
    /// BR アドレスのみ変化（CE IPv6 は変化なし）
    BrChanged,
    /// CE IPv6 アドレス変化（最優先: IPv4・PSID・ポートセットも連動変化）
    CeIpv6Changed,
}

/// 旧パラメータと新パラメータを比較して差分種別を返す
pub fn params_diff(old: &MapeParams, new: &MapeParams) -> ParamsDiff {
    if old.ce_ipv6_addr != new.ce_ipv6_addr {
        ParamsDiff::CeIpv6Changed
    } else if old.br_ipv6_addr != new.br_ipv6_addr {
        ParamsDiff::BrChanged
    } else {
        ParamsDiff::NoChange
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::map::rule::{MapeParams, PortParams};

    use super::{params_diff, ParamsDiff};

    fn make_params(ce_ipv6: Ipv6Addr, br_ipv6: Ipv6Addr) -> MapeParams {
        MapeParams {
            ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
            ce_ipv6_addr: ce_ipv6,
            br_ipv6_addr: br_ipv6,
            psid: 5,
            port_params: PortParams {
                psid_offset: 4,
                psid_len: 8,
                psid: 5,
            },
            port_ranges: vec![(32784, 32799)],
            port_start: 32784,
            port_end: 33023,
            a_min: 1,
            is_fmr: false,
            fmr_ipv4_prefix: Ipv4Addr::UNSPECIFIED,
            fmr_prefix4_len: 0,
        }
    }

    #[test]
    fn test_params_diff_no_change() {
        let ce = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let br = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let old = make_params(ce, br);
        let new = make_params(ce, br);
        assert_eq!(params_diff(&old, &new), ParamsDiff::NoChange);
    }

    #[test]
    fn test_params_diff_br_changed() {
        let ce = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let br_old = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let br_new = "2001:db8::3".parse::<Ipv6Addr>().unwrap();
        let old = make_params(ce, br_old);
        let new = make_params(ce, br_new);
        assert_eq!(params_diff(&old, &new), ParamsDiff::BrChanged);
    }

    #[test]
    fn test_params_diff_ce_ipv6_changed() {
        let ce_old = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let ce_new = "2001:db8::9".parse::<Ipv6Addr>().unwrap();
        let br = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let old = make_params(ce_old, br);
        let new = make_params(ce_new, br);
        assert_eq!(params_diff(&old, &new), ParamsDiff::CeIpv6Changed);
    }

    #[test]
    fn test_params_diff_ce_ipv6_changed_takes_priority_over_br() {
        let ce_old = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let ce_new = "2001:db8::9".parse::<Ipv6Addr>().unwrap();
        let br_old = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let br_new = "2001:db8::3".parse::<Ipv6Addr>().unwrap();
        let old = make_params(ce_old, br_old);
        let new = make_params(ce_new, br_new);
        // CE IPv6 変化が最優先
        assert_eq!(params_diff(&old, &new), ParamsDiff::CeIpv6Changed);
    }
}
