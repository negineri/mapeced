//! Phase 3: nftables / tc 統合テスト（CAP_NET_ADMIN 必要）
//!
//! `sudo -E cargo test --test nftables -- --test-threads=1` で実行する。

#![cfg(target_os = "linux")]

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use mapeced::map::rule::{MapRule, PortParams};
use mapeced::netlink::tunnel;
use mapeced::nftables::manager::{NftManager, TcManager};

use common::TestNetns;

// ── テスト定数 ────────────────────────────────────────────────────────────────

/// テスト用トンネルインターフェース名
const TNL_NAME: &str = "mapeced-t0";
/// テスト名前空間内の lo インターフェース ifindex
const LO_IFINDEX: u32 = 1;

fn local() -> Ipv6Addr {
    "2001:db8::1".parse().unwrap()
}

fn remote() -> Ipv6Addr {
    "2001:db8::2".parse().unwrap()
}

/// nftables テスト用 MapeParams（psid_offset=4, psid_len=8, psid=5）
fn nft_params() -> mapeced::map::rule::MapeParams {
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
    .try_compute(
        "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        80,
        1023,
        false,
    )
    .expect("nft_params: try_compute failed")
}

// ── ヘルパー ──────────────────────────────────────────────────────────────────

/// `nft list table ip mapeced` の出力を返す。
fn nft_list_table() -> String {
    let out = std::process::Command::new("nft")
        .args(["list", "table", "ip", "mapeced"])
        .output()
        .expect("failed to run nft list table");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `tc qdisc show dev <iface>` の出力を返す。
fn tc_qdisc_show(iface: &str) -> String {
    let out = std::process::Command::new("tc")
        .args(["qdisc", "show", "dev", iface])
        .output()
        .expect("failed to run tc qdisc show");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `tc filter show dev <iface> egress` の出力を返す。
fn tc_filter_show_egress(iface: &str) -> String {
    let out = std::process::Command::new("tc")
        .args(["filter", "show", "dev", iface, "egress"])
        .output()
        .expect("failed to run tc filter show egress");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ── Phase 3-1: nftables ルールセット適用テスト ────────────────────────────────

/// nft_01: apply() — 基本 SNAT ルール適用後にテーブルとチェーンが存在する。
#[tokio::test(flavor = "current_thread")]
async fn nft_01_apply_creates_table_and_chains() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (_, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let params = nft_params();
    let nft = NftManager::new();
    nft.apply(&params, TNL_NAME).await.expect("nft.apply failed");

    let output = nft_list_table();
    assert!(
        output.contains("mapeced-clamp"),
        "clamp chain should exist: {output}"
    );
    assert!(
        output.contains("mapeced-mark"),
        "mark chain should exist: {output}"
    );
    assert!(
        output.contains("mapeced-snat"),
        "snat chain should exist: {output}"
    );
}

/// nft_02: apply() — SNAT ルールに正しいポートレンジが含まれる。
#[tokio::test(flavor = "current_thread")]
async fn nft_02_apply_contains_port_range() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (_, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let params = nft_params();
    let port_start = params.port_start;
    let port_end = params.port_end;
    let ipv4 = params.ipv4_addr;

    let nft = NftManager::new();
    nft.apply(&params, TNL_NAME).await.expect("nft.apply failed");

    let output = nft_list_table();
    let expected_snat = format!("snat to {ipv4}:{port_start}-{port_end}");
    assert!(
        output.contains(&expected_snat),
        "SNAT rule should contain port range '{expected_snat}': {output}"
    );
}

/// nft_03: apply() 後に delete_table() → テーブルが削除される。
#[tokio::test(flavor = "current_thread")]
async fn nft_03_delete_table_removes_rules() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (_, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let params = nft_params();
    let nft = NftManager::new();
    nft.apply(&params, TNL_NAME).await.expect("nft.apply failed");

    // テーブルが存在することを確認
    assert!(
        nft_list_table().contains("mapeced-snat"),
        "table should exist before delete"
    );

    nft.delete_table().await.expect("nft.delete_table failed");

    // テーブルが消えたことを確認
    let result = std::process::Command::new("nft")
        .args(["list", "table", "ip", "mapeced"])
        .output()
        .expect("nft command failed");
    assert!(
        !result.status.success(),
        "nft list table should fail after delete_table"
    );
}

/// nft_04: apply() の冪等性 — 2 回連続 apply が成功し、ルールが重複しない。
#[tokio::test(flavor = "current_thread")]
async fn nft_04_apply_is_idempotent() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (_, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let params = nft_params();
    let nft = NftManager::new();

    nft.apply(&params, TNL_NAME).await.expect("first apply failed");
    nft.apply(&params, TNL_NAME).await.expect("second apply failed (idempotency)");

    // テーブルが 1 つだけ存在することを確認（重複なし）
    let output = nft_list_table();
    let snat_count = output.matches("mapeced-snat").count();
    assert_eq!(snat_count, 1, "snat chain should appear exactly once: {output}");
}

/// nft_05: apply() → apply()（パラメータ更新）— 古いルールが置き換えられる。
#[tokio::test(flavor = "current_thread")]
async fn nft_05_second_apply_replaces_old_rules() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (_, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let params1 = nft_params(); // psid=5
    let old_port_start = params1.port_start;

    // p_exclude_max=4096 → a_min=2 → port_start=32800（params1 の 32784 と異なる）
    let params2 = MapRule {
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
    .try_compute(
        "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        80,
        4096, // p_exclude_max 変更 → a_min=2 → port_start が変化
        false,
    )
    .expect("try_compute for params2 failed");
    let new_port_start = params2.port_start;

    // パラメータが異なることを前提とする
    assert_ne!(old_port_start, new_port_start, "params should differ");

    let nft = NftManager::new();
    nft.apply(&params1, TNL_NAME).await.expect("first apply failed");
    nft.apply(&params2, TNL_NAME).await.expect("second apply failed");

    let output = nft_list_table();
    let old_pattern = format!(":{old_port_start}-");
    let new_pattern = format!(":{new_port_start}-");

    assert!(
        !output.contains(&old_pattern),
        "old port range should not appear after update: {output}"
    );
    assert!(
        output.contains(&new_pattern),
        "new port range should appear after update: {output}"
    );
}

// ── Phase 3-2: tc qdisc / filter テスト ──────────────────────────────────────

/// tc_01: apply() — clsact qdisc が作成される。
#[tokio::test(flavor = "current_thread")]
async fn tc_01_apply_creates_qdisc() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    // tc はトンネルインターフェースが必要
    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    let params = nft_params();
    let tc = TcManager;
    tc.apply(&params, TNL_NAME).await.expect("tc.apply failed");

    let output = tc_qdisc_show(TNL_NAME);
    assert!(
        output.contains("clsact"),
        "clsact qdisc should exist: {output}"
    );
}

/// tc_02: apply() — egress フィルタが作成される。
#[tokio::test(flavor = "current_thread")]
async fn tc_02_apply_creates_filters() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    let params = nft_params();
    let tc = TcManager;
    tc.apply(&params, TNL_NAME).await.expect("tc.apply failed");

    let egress = tc_filter_show_egress(TNL_NAME);
    assert!(
        !egress.is_empty(),
        "egress filters should exist after tc.apply: {egress}"
    );
}

/// tc_03: cleanup() — qdisc 削除後に filter も消える。
#[tokio::test(flavor = "current_thread")]
async fn tc_03_cleanup_removes_qdisc() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    let params = nft_params();
    let tc = TcManager;
    tc.apply(&params, TNL_NAME).await.expect("tc.apply failed");
    assert!(
        tc_qdisc_show(TNL_NAME).contains("clsact"),
        "clsact should exist before cleanup"
    );

    tc.cleanup(TNL_NAME).await.expect("tc.cleanup failed");

    assert!(
        !tc_qdisc_show(TNL_NAME).contains("clsact"),
        "clsact qdisc should not exist after cleanup"
    );
}

/// tc_04: apply() の冪等性 — 2 回連続 apply でエラーにならない。
#[tokio::test(flavor = "current_thread")]
async fn tc_04_apply_is_idempotent() {
    require_cap_net_admin!();
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    let params = nft_params();
    let tc = TcManager;

    tc.apply(&params, TNL_NAME).await.expect("first tc.apply failed");
    tc.apply(&params, TNL_NAME).await.expect("second tc.apply failed (idempotency)");

    // 2 回 apply 後も clsact が存在する
    assert!(
        tc_qdisc_show(TNL_NAME).contains("clsact"),
        "clsact should exist after idempotent apply"
    );
}
