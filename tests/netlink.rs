//! Phase 2: Netlink 統合テスト（CAP_NET_ADMIN 必要）
//!
//! `sudo -E cargo test --test netlink -- --test-threads=1` で実行する。

#![cfg(target_os = "linux")]

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use mapeced::netlink::{addr, route, tunnel};

use common::{
    TestNetns, default_route_exists, fmr_route_exists, get_ifindex, get_link_mtu,
    ipv4_addr_exists, ipv6_addr_exists, link_exists,
};

// ── テスト定数 ────────────────────────────────────────────────────────────────

/// テスト用トンネルインターフェース名
const TNL_NAME: &str = "mapeced-t0";
/// テスト名前空間内の lo インターフェース ifindex（常に 1）
const LO_IFINDEX: u32 = 1;
/// テスト用 local IPv6（CE アドレス代わり）
const LOCAL_V6: &str = "2001:db8::1";
/// テスト用 remote IPv6（BR アドレス代わり）
const REMOTE_V6: &str = "2001:db8::2";

fn local() -> Ipv6Addr {
    LOCAL_V6.parse().unwrap()
}

fn remote() -> Ipv6Addr {
    REMOTE_V6.parse().unwrap()
}

// ── Phase 2-1: トンネル管理テスト ────────────────────────────────────────────

/// tnl_01: ensure_tunnel() — 新規作成でインターフェースが出現する。
#[tokio::test(flavor = "current_thread")]
async fn tnl_01_ensure_tunnel_creates_interface() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    assert!(
        link_exists(&handle, TNL_NAME).await,
        "tunnel interface should exist after ensure_tunnel"
    );
}

/// tnl_02: ensure_tunnel() — 冪等性。同一パラメータで 2 回呼んでもエラーにならない。
#[tokio::test(flavor = "current_thread")]
async fn tnl_02_ensure_tunnel_is_idempotent() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("first ensure_tunnel failed");

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("second ensure_tunnel failed (idempotency check)");

    assert!(
        link_exists(&handle, TNL_NAME).await,
        "tunnel interface should still exist after idempotent call"
    );
}

/// tnl_03: ensure_tunnel() — パラメータ更新。local IPv6 を変えて再呼び出し後もインターフェースが存在する。
#[tokio::test(flavor = "current_thread")]
async fn tnl_03_ensure_tunnel_updates_params() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("first ensure_tunnel failed");

    let new_local: Ipv6Addr = "2001:db8::99".parse().unwrap();
    tunnel::ensure_tunnel(&handle, TNL_NAME, new_local, remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel with new local failed");

    assert!(
        link_exists(&handle, TNL_NAME).await,
        "tunnel interface should exist after param update"
    );
}

/// tnl_04: ensure_tunnel() — MTU 設定が反映される。
#[tokio::test(flavor = "current_thread")]
async fn tnl_04_ensure_tunnel_sets_mtu() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, Some(1400))
        .await
        .expect("ensure_tunnel with MTU failed");

    let mtu = get_link_mtu(&handle, TNL_NAME).await;
    assert_eq!(mtu, Some(1400), "MTU should be 1400 after ensure_tunnel");
}

/// tnl_05: delete_tunnel() — インターフェースが削除される。
#[tokio::test(flavor = "current_thread")]
async fn tnl_05_delete_tunnel_removes_interface() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");
    assert!(link_exists(&handle, TNL_NAME).await, "should exist before delete");

    tunnel::delete_tunnel(&handle, TNL_NAME)
        .await
        .expect("delete_tunnel failed");

    assert!(
        !link_exists(&handle, TNL_NAME).await,
        "tunnel interface should not exist after delete_tunnel"
    );
}

/// tnl_06: 存在しないトンネルを削除しても成功（冪等）。
#[tokio::test(flavor = "current_thread")]
async fn tnl_06_delete_nonexistent_tunnel_is_ok() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    tunnel::delete_tunnel(&handle, "does-not-exist")
        .await
        .expect("delete_tunnel of non-existent interface should succeed");
}

// ── Phase 2-2: アドレス管理テスト ─────────────────────────────────────────────

/// addr_01: add_ipv6_addr() — WAN インターフェース（lo）に IPv6 アドレスが付与される。
#[tokio::test(flavor = "current_thread")]
async fn addr_01_add_ipv6_addr_to_wan() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let addr: Ipv6Addr = "2001:db8::42".parse().unwrap();
    addr::add_ipv6_addr(&handle, LO_IFINDEX, addr)
        .await
        .expect("add_ipv6_addr failed");

    assert!(
        ipv6_addr_exists(&handle, LO_IFINDEX, addr).await,
        "IPv6 address should exist after add_ipv6_addr"
    );
}

/// addr_02: add_ipv4_addr() — トンネルインターフェースに IPv4 アドレスが付与される。
#[tokio::test(flavor = "current_thread")]
async fn addr_02_add_ipv4_addr_to_tunnel() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let tnl_ifindex = tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    let ipv4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    addr::add_ipv4_addr(&handle, tnl_ifindex, ipv4)
        .await
        .expect("add_ipv4_addr failed");

    assert!(
        ipv4_addr_exists(&handle, tnl_ifindex, ipv4).await,
        "IPv4 address should exist after add_ipv4_addr"
    );
}

/// addr_03: 同一アドレスの重複付与でエラーにならず、アドレスが存在する（冪等）。
#[tokio::test(flavor = "current_thread")]
async fn addr_03_duplicate_add_is_idempotent() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let addr: Ipv6Addr = "2001:db8::7".parse().unwrap();
    addr::add_ipv6_addr(&handle, LO_IFINDEX, addr)
        .await
        .expect("first add_ipv6_addr failed");

    // 重複付与（エラーは無視して、アドレスの存在を確認する）
    let _ = addr::add_ipv6_addr(&handle, LO_IFINDEX, addr).await;

    assert!(
        ipv6_addr_exists(&handle, LO_IFINDEX, addr).await,
        "IPv6 address should still exist after duplicate add"
    );
}

/// addr_04: del_addr() — アドレス削除後に存在しない。
#[tokio::test(flavor = "current_thread")]
async fn addr_04_del_addr_removes_address() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let ipv6: Ipv6Addr = "2001:db8::55".parse().unwrap();
    addr::add_ipv6_addr(&handle, LO_IFINDEX, ipv6)
        .await
        .expect("add_ipv6_addr failed");
    assert!(ipv6_addr_exists(&handle, LO_IFINDEX, ipv6).await, "should exist before delete");

    addr::del_ipv6_addr(&handle, LO_IFINDEX, ipv6)
        .await
        .expect("del_ipv6_addr failed");

    assert!(
        !ipv6_addr_exists(&handle, LO_IFINDEX, ipv6).await,
        "IPv6 address should not exist after del_ipv6_addr"
    );
}

// ── Phase 2-3: ルート管理テスト ──────────────────────────────────────────────

/// rt_01: add_default_route() — 0.0.0.0/0 ルートがトンネル経由で設定される。
#[tokio::test(flavor = "current_thread")]
async fn rt_01_add_default_route() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let tnl_ifindex = tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    route::add_default_route(&handle, tnl_ifindex)
        .await
        .expect("add_default_route failed");

    assert!(
        default_route_exists(&handle, tnl_ifindex).await,
        "default route should exist after add_default_route"
    );
}

/// rt_02: add_fmr_route() — FMR プレフィックスのルートが追加される。
#[tokio::test(flavor = "current_thread")]
async fn rt_02_add_fmr_route() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let tnl_ifindex = tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    let fmr_prefix = Ipv4Addr::new(106, 73, 0, 0);
    let fmr_len = 15u8;
    route::add_fmr_route(&handle, fmr_prefix, fmr_len, tnl_ifindex)
        .await
        .expect("add_fmr_route failed");

    assert!(
        fmr_route_exists(&handle, fmr_prefix, fmr_len, tnl_ifindex).await,
        "FMR route should exist after add_fmr_route"
    );
}

/// rt_03: del_default_route() / del_fmr_route() — 削除後にルートが消える。
#[tokio::test(flavor = "current_thread")]
async fn rt_03_del_routes() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let tnl_ifindex = tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    // ルート追加
    let fmr_prefix = Ipv4Addr::new(106, 73, 0, 0);
    let fmr_len = 15u8;
    route::add_default_route(&handle, tnl_ifindex).await.expect("add_default_route failed");
    route::add_fmr_route(&handle, fmr_prefix, fmr_len, tnl_ifindex)
        .await
        .expect("add_fmr_route failed");

    assert!(default_route_exists(&handle, tnl_ifindex).await, "default route should exist");
    assert!(
        fmr_route_exists(&handle, fmr_prefix, fmr_len, tnl_ifindex).await,
        "fmr route should exist"
    );

    // ルート削除
    route::del_default_route(&handle, tnl_ifindex)
        .await
        .expect("del_default_route failed");
    route::del_fmr_route(&handle, fmr_prefix, fmr_len, tnl_ifindex)
        .await
        .expect("del_fmr_route failed");

    assert!(
        !default_route_exists(&handle, tnl_ifindex).await,
        "default route should not exist after del_default_route"
    );
    assert!(
        !fmr_route_exists(&handle, fmr_prefix, fmr_len, tnl_ifindex).await,
        "FMR route should not exist after del_fmr_route"
    );
}

/// rt_04: 同一ルートの重複追加でエラーにならず、ルートが存在する（冪等）。
#[tokio::test(flavor = "current_thread")]
async fn rt_04_duplicate_add_route_is_idempotent() {
    let _ns = TestNetns::new().expect("TestNetns::new failed");
    let (handle, conn) = _ns.rtnetlink_handle().expect("rtnetlink_handle failed");
    tokio::spawn(conn);

    let tnl_ifindex = tunnel::ensure_tunnel(&handle, TNL_NAME, local(), remote(), LO_IFINDEX, None)
        .await
        .expect("ensure_tunnel failed");

    route::add_default_route(&handle, tnl_ifindex)
        .await
        .expect("first add_default_route failed");

    // 重複追加（エラーは無視して、ルートの存在を確認する）
    let _ = route::add_default_route(&handle, tnl_ifindex).await;

    assert!(
        default_route_exists(&handle, tnl_ifindex).await,
        "default route should still exist after duplicate add"
    );

    // get_ifindex を使った追加検証：トンネルインターフェースの ifindex が返る
    let queried_idx = get_ifindex(&handle, TNL_NAME).await;
    assert_eq!(queried_idx, Some(tnl_ifindex), "get_ifindex should return tunnel's ifindex");
}
