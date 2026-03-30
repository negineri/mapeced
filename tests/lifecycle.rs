//! Phase 4: ライフサイクル統合テスト（CAP_NET_ADMIN 必要）
//!
//! `sudo -E cargo test --test lifecycle -- --test-threads=1` で実行する。

#![cfg(target_os = "linux")]

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use mapeced::config::Config;
use mapeced::daemon::lifecycle::{apply, cleanup, startup_cleanup, update};
use mapeced::daemon::state::DaemonState;
use mapeced::map::rule::{MapRule, PortParams};
use mapeced::map::static_rules::CeCalcMethod;
use mapeced::nftables::manager::{NftManager, TcManager};

use common::{
    TestNetns, default_route_exists, fmr_route_exists, ipv4_addr_exists, ipv6_addr_exists,
    link_exists,
};

// ── テスト定数 ────────────────────────────────────────────────────────────────

const TNL_NAME: &str = "mapeced-lc";
const WAN_NAME: &str = "lo";
const LO_IFINDEX: u32 = 1;

// ── ヘルパー ──────────────────────────────────────────────────────────────────

/// テスト用 Config を作成する。
fn test_config() -> Config {
    Config {
        upstream_interface: WAN_NAME.to_string(),
        tunnel_interface: TNL_NAME.to_string(),
        tunnel_mtu: None,
        map_rules_cache_file: None,
        static_rule: false,
        ce_calc: CeCalcMethod::Rfc7597,
        p_exclude_max: 1023,
    }
}

/// RFC 7597 形式の MapeParams を生成する（PSID=5, FMR なし）。
fn rfc_params() -> mapeced::map::rule::MapeParams {
    MapRule {
        ipv4_prefix: Ipv4Addr::new(106, 73, 0, 0),
        prefix4_len: 15,
        ipv6_prefix: "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        prefix6_len: 64,
        ea_len: 16,
        port_params: PortParams {
            psid_offset: 4,
            psid_len: 8,
            psid: Some(5),
        },
        br_addr: "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap(),
        is_fmr: false,
    }
    .try_compute("2404:9200:225:100::".parse().unwrap(), 80, 1023, false)
    .expect("rfc_params: try_compute failed")
}

/// v6plus 形式の MapeParams を生成する（PSID=5, FMR なし）。
fn v6plus_params() -> mapeced::map::rule::MapeParams {
    MapRule {
        ipv4_prefix: Ipv4Addr::new(106, 73, 0, 0),
        prefix4_len: 15,
        ipv6_prefix: "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        prefix6_len: 64,
        ea_len: 16,
        port_params: PortParams {
            psid_offset: 4,
            psid_len: 8,
            psid: Some(5),
        },
        br_addr: "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap(),
        is_fmr: false,
    }
    .try_compute("2404:9200:225:100::".parse().unwrap(), 80, 1023, true)
    .expect("v6plus_params: try_compute failed")
}

/// FMR あり の MapeParams を生成する（PSID=5, is_fmr=true）。
fn fmr_params() -> mapeced::map::rule::MapeParams {
    MapRule {
        ipv4_prefix: Ipv4Addr::new(106, 73, 0, 0),
        prefix4_len: 15,
        ipv6_prefix: "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        prefix6_len: 64,
        ea_len: 16,
        port_params: PortParams {
            psid_offset: 4,
            psid_len: 8,
            psid: Some(5),
        },
        br_addr: "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap(),
        is_fmr: true,
    }
    .try_compute("2404:9200:225:100::".parse().unwrap(), 80, 1023, false)
    .expect("fmr_params: try_compute failed")
}

// ── 検証ヘルパー ──────────────────────────────────────────────────────────────

/// apply() / update() 後のシステム全体の整合性を検証する。
async fn assert_fully_applied(
    handle: &rtnetlink::Handle,
    params: &mapeced::map::rule::MapeParams,
    tunnel_ifindex: u32,
) {
    // トンネルインターフェースが存在する
    assert!(
        link_exists(handle, TNL_NAME).await,
        "tunnel interface should exist"
    );
    // CE IPv6 が WAN (lo) に付与されている
    assert!(
        ipv6_addr_exists(handle, LO_IFINDEX, params.ce_ipv6_addr).await,
        "CE IPv6 should be on WAN interface"
    );
    // CE IPv4 がトンネルに付与されている
    assert!(
        ipv4_addr_exists(handle, tunnel_ifindex, params.ipv4_addr).await,
        "CE IPv4 should be on tunnel interface"
    );
    // デフォルトルートが存在する
    assert!(
        default_route_exists(handle, tunnel_ifindex).await,
        "default route should exist via tunnel"
    );
    // FMR ルート（is_fmr の場合のみ）
    if params.is_fmr {
        assert!(
            fmr_route_exists(
                handle,
                params.fmr_ipv4_prefix,
                params.fmr_prefix4_len,
                tunnel_ifindex
            )
            .await,
            "FMR route should exist"
        );
    }
}

/// cleanup() 後のシステム全体の整合性を検証する。
async fn assert_fully_cleaned(
    handle: &rtnetlink::Handle,
    params: &mapeced::map::rule::MapeParams,
) {
    assert!(
        !link_exists(handle, TNL_NAME).await,
        "tunnel interface should not exist after cleanup"
    );
    assert!(
        !ipv6_addr_exists(handle, LO_IFINDEX, params.ce_ipv6_addr).await,
        "CE IPv6 should be removed after cleanup"
    );
}

// ── Phase 4 テストケース ──────────────────────────────────────────────────────

/// lc_01: apply() — RFC 7597 形式の初回適用でシステム全体が設定される。
#[tokio::test(flavor = "current_thread")]
async fn lc_01_apply_rfc7597() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params = rfc_params();

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("apply failed");

    let tunnel_ifindex = state.tunnel_ifindex.expect("tunnel_ifindex should be set");
    assert_fully_applied(&handle, &params, tunnel_ifindex).await;
}

/// lc_02: apply() — v6plus CE 計算で CE IPv6 が正しく設定される。
#[tokio::test(flavor = "current_thread")]
async fn lc_02_apply_v6plus_ce_addr() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params = v6plus_params();
    let expected_ce_ipv6 = params.ce_ipv6_addr;

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("apply (v6plus) failed");

    assert!(
        ipv6_addr_exists(&handle, LO_IFINDEX, expected_ce_ipv6).await,
        "v6plus CE IPv6 should be on WAN interface"
    );
    // RFC モードとは異なる CE IPv6 アドレスが設定されていることを確認
    let rfc_ce = rfc_params().ce_ipv6_addr;
    assert_ne!(
        expected_ce_ipv6, rfc_ce,
        "v6plus and RFC CE IPv6 should differ"
    );
}

/// lc_03: apply() — FMR あり の場合に FMR ルートが追加される。
#[tokio::test(flavor = "current_thread")]
async fn lc_03_apply_with_fmr() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params = fmr_params();

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("apply with FMR failed");

    let tnl_idx = state.tunnel_ifindex.expect("tunnel_ifindex should be set");
    assert_fully_applied(&handle, &params, tnl_idx).await;
}

/// lc_04: update() — BR アドレス変更でトンネルのリモートエンドポイントが更新される。
#[tokio::test(flavor = "current_thread")]
async fn lc_04_update_br_change() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params1 = rfc_params();

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params1.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("apply failed");

    // BR アドレスのみ変更した新パラメータ
    let mut params2 = params1;
    params2.br_ipv6_addr = "2404:9200:225:100::65".parse().unwrap();

    update(&mut state, params2, &config, &handle, &nft, &tc)
        .await
        .expect("update (BR change) failed");

    // トンネルが依然として存在する（BrChanged: update_tunnel_remote を使用）
    assert!(link_exists(&handle, TNL_NAME).await, "tunnel should still exist after BR update");
}

/// lc_05: update() — IA_PD プレフィックス変更（CE IPv6 変化）で全設定が再設定される。
#[tokio::test(flavor = "current_thread")]
async fn lc_05_update_ce_ipv6_change() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params1 = rfc_params(); // PSID=5
    let old_ce_ipv6 = params1.ce_ipv6_addr;

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params1, &config, &handle, &nft, &tc)
        .await
        .expect("apply failed");

    // CE IPv6 が変わるパラメータ（PSID=10 → CE IPv6 変化）
    let params2 = MapRule {
        ipv4_prefix: Ipv4Addr::new(106, 73, 0, 0),
        prefix4_len: 15,
        ipv6_prefix: "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        prefix6_len: 64,
        ea_len: 16,
        port_params: PortParams {
            psid_offset: 4,
            psid_len: 8,
            psid: Some(10),
        },
        br_addr: "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap(),
        is_fmr: false,
    }
    .try_compute("2404:9200:225:100::".parse().unwrap(), 80, 1023, false)
    .expect("params2: try_compute failed");

    let new_ce_ipv6 = params2.ce_ipv6_addr;
    assert_ne!(old_ce_ipv6, new_ce_ipv6, "CE IPv6 should differ between params");

    update(&mut state, params2.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("update (CE IPv6 change) failed");

    let new_tnl_idx = state.tunnel_ifindex.expect("tunnel_ifindex should be set");
    // 新しい CE IPv6 が WAN に付与されている
    assert!(
        ipv6_addr_exists(&handle, LO_IFINDEX, new_ce_ipv6).await,
        "new CE IPv6 should be on WAN after update"
    );
    // 古い CE IPv6 が削除されている
    assert!(
        !ipv6_addr_exists(&handle, LO_IFINDEX, old_ce_ipv6).await,
        "old CE IPv6 should be removed after update"
    );
    assert_fully_applied(&handle, &params2, new_tnl_idx).await;
}

/// lc_06: update() — FMR なし → あり で FMR ルートが追加される。
#[tokio::test(flavor = "current_thread")]
async fn lc_06_update_fmr_none_to_some() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;

    let params_no_fmr = rfc_params(); // is_fmr=false
    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params_no_fmr, &config, &handle, &nft, &tc)
        .await
        .expect("apply (no FMR) failed");

    // FMR ありのパラメータで update
    let params_with_fmr = fmr_params(); // is_fmr=true, same CE IPv6 (PSID=5)
    let fmr_prefix = params_with_fmr.fmr_ipv4_prefix;
    let fmr_len = params_with_fmr.fmr_prefix4_len;

    update(&mut state, params_with_fmr, &config, &handle, &nft, &tc)
        .await
        .expect("update (add FMR) failed");

    let tnl_idx = state.tunnel_ifindex.expect("tunnel_ifindex should be set");
    assert!(
        fmr_route_exists(&handle, fmr_prefix, fmr_len, tnl_idx).await,
        "FMR route should be added after update"
    );
}

/// lc_07: update() — FMR あり → なし で FMR ルートが削除される。
#[tokio::test(flavor = "current_thread")]
async fn lc_07_update_fmr_some_to_none() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;

    let params_with_fmr = fmr_params(); // is_fmr=true
    let fmr_prefix = params_with_fmr.fmr_ipv4_prefix;
    let fmr_len = params_with_fmr.fmr_prefix4_len;

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params_with_fmr, &config, &handle, &nft, &tc)
        .await
        .expect("apply (with FMR) failed");

    let tnl_idx_before = state.tunnel_ifindex.expect("tunnel_ifindex should be set");
    assert!(
        fmr_route_exists(&handle, fmr_prefix, fmr_len, tnl_idx_before).await,
        "FMR route should exist before update"
    );

    // rfc_params と fmr_params は PSID が同じ → CE IPv6 が同じ → NoChange になる
    // そのため CE IPv6 が変わる PSID=20 を使って CeIpv6Changed パスを通す（FMR なし）
    let params_no_fmr = MapRule {
        ipv4_prefix: Ipv4Addr::new(106, 73, 0, 0),
        prefix4_len: 15,
        ipv6_prefix: "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        prefix6_len: 64,
        ea_len: 16,
        port_params: PortParams {
            psid_offset: 4,
            psid_len: 8,
            psid: Some(20), // PSID 変更 → CE IPv6 変化 → CeIpv6Changed
        },
        br_addr: "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap(),
        is_fmr: false,
    }
    .try_compute("2404:9200:225:100::".parse().unwrap(), 80, 1023, false)
    .expect("params_no_fmr: try_compute failed");

    update(&mut state, params_no_fmr, &config, &handle, &nft, &tc)
        .await
        .expect("update (remove FMR) failed");

    let new_tnl_idx = state.tunnel_ifindex.expect("tunnel_ifindex after update");
    assert!(
        !fmr_route_exists(&handle, fmr_prefix, fmr_len, new_tnl_idx).await,
        "FMR route should be removed after update to no-FMR params"
    );
}

/// lc_08: update() — パラメータ変化なし → Netlink/nft 呼び出しがスキップされる。
#[tokio::test(flavor = "current_thread")]
async fn lc_08_update_no_change_is_noop() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params = rfc_params();

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("apply failed");

    let tnl_idx_before = state.tunnel_ifindex;

    // 同じパラメータで update → NoChange
    update(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("update (no change) failed");

    // トンネル ifindex が変わっていない（再作成されていない）
    assert_eq!(
        state.tunnel_ifindex, tnl_idx_before,
        "tunnel_ifindex should not change for NoChange update"
    );
    assert!(
        link_exists(&handle, TNL_NAME).await,
        "tunnel should still exist"
    );
}

/// lc_09: cleanup() — apply 後にクリーンアップでトンネル・アドレス・ルートが全て削除される。
#[tokio::test(flavor = "current_thread")]
async fn lc_09_cleanup_after_apply() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params = rfc_params();

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("apply failed");

    cleanup(&mut state, &config, &handle, &nft, &tc)
        .await
        .expect("cleanup failed");

    assert_fully_cleaned(&handle, &params).await;
}

/// lc_10: cleanup() — 未適用状態でのクリーンアップはエラーにならない（冪等）。
#[tokio::test(flavor = "current_thread")]
async fn lc_10_cleanup_without_apply_is_ok() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    // params = None のまま cleanup → エラーにならず即 Ok
    cleanup(&mut state, &config, &handle, &nft, &tc)
        .await
        .expect("cleanup without apply should succeed");
}

/// lc_11: apply() → cleanup() → apply() — 2 回目の apply が正常に動作する。
#[tokio::test(flavor = "current_thread")]
async fn lc_11_apply_cleanup_apply() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params = rfc_params();

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    // 1st apply
    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("first apply failed");

    // cleanup
    cleanup(&mut state, &config, &handle, &nft, &tc)
        .await
        .expect("cleanup failed");

    assert_fully_cleaned(&handle, &params).await;

    // 2nd apply
    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("second apply failed");

    let tnl_idx = state.tunnel_ifindex.expect("tunnel_ifindex after 2nd apply");
    assert_fully_applied(&handle, &params, tnl_idx).await;
}

/// lc_12: startup_cleanup() — apply() で設定を残した後に startup_cleanup() を呼ぶと残存設定が除去される。
#[tokio::test(flavor = "current_thread")]
async fn lc_12_startup_cleanup_removes_stale_config() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let config = test_config();
    let nft = NftManager::new();
    let tc = TcManager;
    let params = rfc_params();

    let mut state = DaemonState {
        params: None,
        pending_map_rules: vec![],
        tunnel_ifindex: None,
        wan_ifindex: LO_IFINDEX,
    };

    // apply() で設定を作る（"前回起動時の残存設定" に見立てる）
    apply(&mut state, params.clone(), &config, &handle, &nft, &tc)
        .await
        .expect("apply failed");
    assert!(
        link_exists(&handle, TNL_NAME).await,
        "tunnel should exist after apply"
    );

    // startup_cleanup() → 残存設定を除去
    startup_cleanup(&config, &handle)
        .await
        .expect("startup_cleanup failed");

    // トンネルインターフェースが削除されている
    assert!(
        !link_exists(&handle, TNL_NAME).await,
        "tunnel should be removed by startup_cleanup"
    );

    // nft テーブルが削除されている
    let nft_result = std::process::Command::new("nft")
        .args(["list", "table", "ip", "mapeced"])
        .output()
        .expect("nft command failed");
    assert!(
        !nft_result.status.success(),
        "nft table should be removed by startup_cleanup"
    );
}
