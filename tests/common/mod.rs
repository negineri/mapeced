use std::net::{Ipv4Addr, Ipv6Addr};

use mapeced::map::rule::{MapRule, MapeParams, PortParams};

/// テスト用のダミー MapRule を返す（v6plus 相当）。
#[allow(dead_code)]
pub fn dummy_map_rule() -> MapRule {
    MapRule {
        ipv4_prefix: Ipv4Addr::new(106, 73, 0, 0),
        prefix4_len: 15,
        ipv6_prefix: "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
        prefix6_len: 64,
        ea_len: 16,
        port_params: PortParams {
            psid_offset: 4,
            psid_len: 8,
            psid: Some(42),
        },
        br_addr: "2404:9200:225:100::64".parse::<Ipv6Addr>().unwrap(),
        is_fmr: false,
    }
}

/// テスト用のダミー MapeParams を返す。
/// `dummy_map_rule()` + PSID=42 を使って `try_compute` で導出する。
#[allow(dead_code)]
pub fn dummy_mape_params() -> MapeParams {
    dummy_map_rule()
        .try_compute(
            "2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(),
            80,
            1023,
            false,
        )
        .expect("dummy_mape_params: try_compute failed")
}

// ── Linux 専用ヘルパー ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    use futures::TryStreamExt;
    use netlink_packet_route::address::AddressAttribute;
    use netlink_packet_route::link::LinkAttribute;
    use netlink_packet_route::route::{RouteAddress, RouteAttribute};
    use nix::sched::CloneFlags;
    use rtnetlink::{Handle, IpVersion};

    // ── TestNetns ──────────────────────────────────────────────────────────────

    /// テスト用ネットワーク名前空間の RAII ガード。
    ///
    /// `new()` でユニークな名前空間を作成し、現在のスレッドをその名前空間に切り替える。
    /// `Drop` で元の名前空間に戻し、`ip netns del` で名前空間を削除する。
    ///
    /// # 注意
    /// `#[tokio::test(flavor = "current_thread")]` と組み合わせて使用すること。
    /// すべての非同期処理が同一スレッドで実行されることを保証する必要がある。
    pub struct TestNetns {
        name: String,
        original_fd: std::fs::File,
    }

    impl TestNetns {
        /// 新しいネットワーク名前空間を作成し、現在のスレッドをその名前空間に切り替える。
        #[allow(dead_code)]
        pub fn new() -> anyhow::Result<Self> {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = format!("mapeced-{}-{}", std::process::id(), n);

            // 現在の名前空間 fd を保存
            let original_fd = std::fs::File::open("/proc/self/ns/net")
                .map_err(|e| anyhow::anyhow!("open /proc/self/ns/net: {e}"))?;

            // 新しい名前空間を作成
            let status = std::process::Command::new("ip")
                .args(["netns", "add", &name])
                .status()
                .map_err(|e| anyhow::anyhow!("ip netns add: {e}"))?;
            anyhow::ensure!(status.success(), "ip netns add {} failed", name);

            // 新しい名前空間の fd を開く
            let netns_path = format!("/var/run/netns/{name}");
            let netns_fd = std::fs::File::open(&netns_path)
                .map_err(|e| anyhow::anyhow!("open {netns_path}: {e}"))?;

            // 現在のスレッドを新しい名前空間に切り替える
            nix::sched::setns(netns_fd.as_fd(), CloneFlags::CLONE_NEWNET)
                .map_err(|e| anyhow::anyhow!("setns: {e}"))?;

            Ok(Self { name, original_fd })
        }

        /// テスト名前空間の名前を返す。
        #[allow(dead_code)]
        pub fn name(&self) -> &str {
            &self.name
        }

        /// この名前空間に対応した rtnetlink Handle を作成する。
        /// `TestNetns::new()` の後、tokio 非同期コンテキスト内で呼び出すこと。
        pub fn rtnetlink_handle(
            &self,
        ) -> anyhow::Result<(Handle, impl std::future::Future<Output = ()> + use<>)> {
            let (conn, handle, _) = rtnetlink::new_connection()
                .map_err(|e| anyhow::anyhow!("rtnetlink::new_connection: {e}"))?;
            Ok((handle, conn))
        }
    }

    impl Drop for TestNetns {
        fn drop(&mut self) {
            // 元の名前空間に戻す
            let _ = nix::sched::setns(self.original_fd.as_fd(), CloneFlags::CLONE_NEWNET);
            // テスト名前空間を削除
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &self.name])
                .status();
        }
    }

    // ── Netlink 検証ヘルパー ──────────────────────────────────────────────────

    /// 指定した名前のリンクが存在するか確認する。
    #[allow(dead_code)]
    pub async fn link_exists(handle: &Handle, name: &str) -> bool {
        handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await
            .unwrap_or(None)
            .is_some()
    }

    /// 指定した名前のリンクの ifindex を返す。存在しない場合は None。
    #[allow(dead_code)]
    pub async fn get_ifindex(handle: &Handle, name: &str) -> Option<u32> {
        handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await
            .unwrap_or(None)
            .map(|msg| msg.header.index)
    }

    /// 指定した名前のリンクの MTU を返す。存在しない場合は None。
    #[allow(dead_code)]
    pub async fn get_link_mtu(handle: &Handle, name: &str) -> Option<u32> {
        let msg = handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await
            .unwrap_or(None)?;

        for attr in &msg.attributes {
            if let LinkAttribute::Mtu(mtu) = attr {
                return Some(*mtu);
            }
        }
        None
    }

    /// 指定した ifindex のインターフェースに IPv6 アドレスが存在するか確認する。
    #[allow(dead_code)]
    pub async fn ipv6_addr_exists(handle: &Handle, ifindex: u32, addr: Ipv6Addr) -> bool {
        let target = IpAddr::V6(addr);
        let mut stream = handle
            .address()
            .get()
            .set_link_index_filter(ifindex)
            .execute();

        while let Ok(Some(msg)) = stream.try_next().await {
            for a in &msg.attributes {
                if let AddressAttribute::Address(a) = a {
                    if *a == target {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// 指定した ifindex のインターフェースに IPv4 アドレスが存在するか確認する。
    #[allow(dead_code)]
    pub async fn ipv4_addr_exists(handle: &Handle, ifindex: u32, addr: Ipv4Addr) -> bool {
        let target = IpAddr::V4(addr);
        let mut stream = handle
            .address()
            .get()
            .set_link_index_filter(ifindex)
            .execute();

        while let Ok(Some(msg)) = stream.try_next().await {
            for a in &msg.attributes {
                if let AddressAttribute::Address(a) = a {
                    if *a == target {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// デフォルトルート（0.0.0.0/0）が指定 ifindex 経由で存在するか確認する。
    #[allow(dead_code)]
    pub async fn default_route_exists(handle: &Handle, tunnel_ifindex: u32) -> bool {
        let mut routes = handle.route().get(IpVersion::V4).execute();
        while let Ok(Some(route)) = routes.try_next().await {
            if route.header.destination_prefix_length != 0 {
                continue;
            }
            if route
                .attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Oif(oif) if *oif == tunnel_ifindex))
            {
                return true;
            }
        }
        false
    }

    /// FMR ルートが指定 ifindex 経由で存在するか確認する。
    #[allow(dead_code)]
    pub async fn fmr_route_exists(
        handle: &Handle,
        prefix: Ipv4Addr,
        prefix_len: u8,
        tunnel_ifindex: u32,
    ) -> bool {
        let mut routes = handle.route().get(IpVersion::V4).execute();
        while let Ok(Some(route)) = routes.try_next().await {
            if route.header.destination_prefix_length != prefix_len {
                continue;
            }
            let has_dest = route.attributes.iter().any(|a| {
                matches!(a, RouteAttribute::Destination(RouteAddress::Inet(d)) if *d == prefix)
            });
            let has_oif = route
                .attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Oif(oif) if *oif == tunnel_ifindex));
            if has_dest && has_oif {
                return true;
            }
        }
        false
    }
}
