use std::net::Ipv6Addr;

use nix::net::if_::if_nametoindex;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::dhcpv6::{capture, lease_watcher};
use crate::error::MapEError;
use crate::map::rule::{MapeParams, MapRule};
use crate::nftables::manager::{NftManager, TcManager};

use super::{lifecycle, state::DaemonState};

pub async fn run(config: Config) -> Result<(), MapEError> {
    // 1. WAN ifindex 取得
    let wan_ifindex = if_nametoindex(config.upstream_interface.as_str()).map_err(|e| {
        MapEError::NetlinkError(format!(
            "if_nametoindex({}): {e}",
            config.upstream_interface
        ))
    })?;

    // rtnetlink 接続
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
    tokio::spawn(connection);

    let nft = NftManager::new();
    let tc = TcManager;

    // 2. キャッシュ読み込み（dhcpv6 プロファイル かつ cache_file が Some の場合）
    let mut initial_rules: Vec<MapRule> = Vec::new();
    if config.map_profile == crate::map::static_rules::MapProfile::Dhcpv6
        && let Some(ref cache_path) = config.map_rules_cache_file
        && cache_path.exists()
    {
        match std::fs::read_to_string(cache_path) {
            Ok(content) => match serde_json::from_str::<Vec<MapRule>>(&content) {
                Ok(rules) => {
                    info!("loaded {} MAP rules from cache", rules.len());
                    initial_rules = rules;
                }
                Err(e) => {
                    warn!("failed to parse cache file: {e}");
                }
            },
            Err(e) => {
                warn!("failed to read cache file: {e}");
            }
        }
    }

    // 3. 静的ルール設定（v6plus / ocn_vc プロファイルの場合）
    if let Some(rules) = config.map_profile.static_rules() {
        initial_rules = rules.to_vec();
        info!("using {} static MAP rules (profile: {:?})", initial_rules.len(), config.map_profile);
    }

    let mut state = DaemonState {
        params: None,
        pending_map_rules: initial_rules,
        tunnel_ifindex: None,
        wan_ifindex,
    };

    // 4. lease_watcher タスク spawn
    let (lease_tx, mut lease_rx) = watch::channel::<Option<(Ipv6Addr, u8)>>(None);
    let upstream_for_watcher = config.upstream_interface.clone();
    tokio::spawn(async move {
        if let Err(e) = lease_watcher::run_lease_watcher(&upstream_for_watcher, lease_tx).await {
            error!("lease_watcher error: {e}");
        }
    });

    // capture タスク（dhcpv6 プロファイルの場合のみ）
    let mut capture_rx_opt: Option<mpsc::Receiver<Vec<MapRule>>> = if config.map_profile.static_rules().is_none() {
        let (capture_tx, capture_rx) = mpsc::channel::<Vec<MapRule>>(16);
        let upstream_for_capture = config.upstream_interface.clone();
        tokio::spawn(async move {
            if let Err(e) = capture::run_capture(&upstream_for_capture, capture_tx).await {
                error!("capture error: {e}");
            }
        });
        Some(capture_rx)
    } else {
        None
    };

    // 5. 起動時クリーンアップ（再起動時の冪等性確保）
    startup_cleanup(&config, &handle).await?;

    // シグナルハンドラ
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )
    .map_err(|e| MapEError::NetlinkError(format!("failed to install SIGTERM handler: {e}")))?;

    // 6. イベントループ
    loop {
        tokio::select! {
            // IA_PD プレフィックス変化
            result = lease_rx.changed() => {
                if result.is_err() {
                    break;
                }
                let prefix_opt = *lease_rx.borrow_and_update();
                handle_lease_change(&mut state, prefix_opt, &config, &handle, &nft, &tc).await;
            }

            // DHCPv6 capture から MAP Rule 受信
            // map_profile 指定時は capture_rx_opt が None のため
            // このアームは永遠に select されない
            rules_opt = async {
                match capture_rx_opt.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<Vec<MapRule>>>().await,
                }
            } => {
                if let Some(rules) = rules_opt {
                    info!("received {} MAP rules from DHCPv6 capture", rules.len());
                    state.pending_map_rules = rules;
                }
            }

            // SIGINT (Ctrl+C)
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT, shutting down");
                break;
            }

            // SIGTERM
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
                break;
            }
        }
    }

    // 終了時クリーンアップ
    if let Err(e) = lifecycle::cleanup(&mut state, &config, &handle, &nft, &tc).await {
        error!("cleanup error: {e}");
    }

    Ok(())
}

/// 起動時クリーンアップ: 既存の MAP-E 由来設定を削除する
async fn startup_cleanup(
    config: &Config,
    handle: &rtnetlink::Handle,
) -> Result<(), MapEError> {
    // nft テーブル削除
    let output = std::process::Command::new("nft")
        .args(["delete", "table", "ip", "mapeced"])
        .output()
        .map_err(|e| MapEError::NftError(format!("failed to run nft: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No such file or directory") && !stderr.contains("Could not process rule") {
            return Err(MapEError::NftError(format!(
                "nft delete table failed: {stderr}"
            )));
        }
    }

    // 既存トンネルがあれば tc + トンネル削除
    if if_nametoindex(config.tunnel_interface.as_str()).is_ok() {
        // tc qdisc 削除（エラーは無視）
        let _ = std::process::Command::new("tc")
            .args(["qdisc", "del", "dev", &config.tunnel_interface, "root"])
            .output();
        let _ = std::process::Command::new("tc")
            .args(["qdisc", "del", "dev", &config.tunnel_interface, "ingress"])
            .output();

        // トンネルインターフェース削除（エラーは無視）
        let _ = crate::netlink::tunnel::delete_tunnel(handle, &config.tunnel_interface).await;
    }

    Ok(())
}

/// IA_PD プレフィックス変化イベントの処理
async fn handle_lease_change(
    state: &mut DaemonState,
    prefix_opt: Option<(Ipv6Addr, u8)>,
    config: &Config,
    handle: &rtnetlink::Handle,
    nft: &NftManager,
    tc: &TcManager,
) {
    match prefix_opt {
        None => {
            // リース削除 → クリーンアップ
            if state.params.is_some() {
                info!("IA_PD lease removed, cleaning up MAP-E configuration");
                if let Err(e) = lifecycle::cleanup(state, config, handle, nft, tc).await {
                    error!("cleanup error: {e}");
                }
            }
        }
        Some((ce_prefix, ce_prefix_len)) => {
            // MAP Rule 選択と MapeParams 計算
            let use_v6plus = config.map_profile.use_v6plus_ce_calc();
            match select_and_compute(&state.pending_map_rules, ce_prefix, ce_prefix_len, config.p_exclude_max, use_v6plus) {
                Some(new_params) => {
                    info!(
                        "computed MAP-E params: ce_ipv6={} ipv4={}",
                        new_params.ce_ipv6_addr, new_params.ipv4_addr
                    );
                    if state.params.is_none() {
                        if let Err(e) = lifecycle::apply(state, new_params, config, handle, nft, tc).await {
                            error!("apply error: {e}");
                        }
                    } else if let Err(e) = lifecycle::update(state, new_params, config, handle, nft, tc).await {
                        error!("update error: {e}");
                    }
                }
                None => {
                    warn!("no MAP rule matches the IA_PD prefix {ce_prefix}/{ce_prefix_len}");
                }
            }
        }
    }
}

/// 最長プレフィックスマッチで MAP Rule を選択し、MapeParams を計算する
fn select_and_compute(
    rules: &[MapRule],
    ce_prefix: Ipv6Addr,
    ce_prefix_len: u8,
    p_exclude_max: u16,
    use_v6plus: bool,
) -> Option<MapeParams> {
    // prefix6_len 降順でソートした後、マッチするルールを試す
    let mut candidates: Vec<&MapRule> = rules
        .iter()
        .filter(|r| ipv6_prefix_matches(ce_prefix, r.ipv6_prefix, r.prefix6_len))
        .collect();
    candidates.sort_by(|a, b| b.prefix6_len.cmp(&a.prefix6_len));

    for rule in candidates {
        if let Ok(params) = rule.try_compute(ce_prefix, ce_prefix_len, p_exclude_max, use_v6plus) {
            return Some(params);
        }
    }
    None
}

/// IPv6 プレフィックスマッチ: `addr` の上位 `prefix_len` ビットが `prefix` と一致するか
fn ipv6_prefix_matches(addr: Ipv6Addr, prefix: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let addr_bits = u128::from_be_bytes(addr.octets());
    let prefix_bits = u128::from_be_bytes(prefix.octets());
    let shift = 128u32.saturating_sub(prefix_len as u32);
    let mask = if shift >= 128 { 0u128 } else { !0u128 << shift };
    (addr_bits & mask) == (prefix_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::ipv6_prefix_matches;
    use std::net::Ipv6Addr;

    #[test]
    fn test_ipv6_prefix_matches_exact() {
        let addr: Ipv6Addr = "2400:4050:1234:5678::".parse().unwrap();
        let prefix: Ipv6Addr = "2400:4050::".parse().unwrap();
        assert!(ipv6_prefix_matches(addr, prefix, 32));
    }

    #[test]
    fn test_ipv6_prefix_no_match() {
        let addr: Ipv6Addr = "2401:4050:1234:5678::".parse().unwrap();
        let prefix: Ipv6Addr = "2400:4050::".parse().unwrap();
        assert!(!ipv6_prefix_matches(addr, prefix, 32));
    }

    #[test]
    fn test_ipv6_prefix_zero_len_always_matches() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let prefix: Ipv6Addr = "::".parse().unwrap();
        assert!(ipv6_prefix_matches(addr, prefix, 0));
    }
}
