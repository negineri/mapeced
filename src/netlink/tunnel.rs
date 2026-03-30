use std::net::Ipv6Addr;

use futures::TryStreamExt;
use netlink_packet_route::link::{InfoData, InfoKind, LinkAttribute, LinkInfo};
use rtnetlink::Handle;

use crate::error::MapEError;

// IFLA_IPTUN_* NLA type 番号（linux/if_tunnel.h）
const IFLA_IPTUN_LINK: u16 = 1;
const IFLA_IPTUN_LOCAL: u16 = 2;
const IFLA_IPTUN_REMOTE: u16 = 3;
const IFLA_IPTUN_TTL: u16 = 4;
const IFLA_IPTUN_PROTO: u16 = 9;

/// IPPROTO_IPIP: IPv4-in-IPv6
const IPPROTO_IPIP: u8 = 4;

/// ネストした NLA を Vec<u8> に書き込む（4 バイトアライメントでパディング）
fn write_nla(buf: &mut Vec<u8>, nla_type: u16, data: &[u8]) {
    let len = 4u16 + data.len() as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&nla_type.to_ne_bytes());
    buf.extend_from_slice(data);
    let remainder = data.len() % 4;
    if remainder != 0 {
        for _ in 0..(4 - remainder) {
            buf.push(0);
        }
    }
}

/// IFLA_IPTUN_DATA 全体（トンネル作成用）
fn build_iptun_data(local: Ipv6Addr, remote: Ipv6Addr, link_ifindex: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    write_nla(&mut buf, IFLA_IPTUN_LINK, &link_ifindex.to_ne_bytes());
    write_nla(&mut buf, IFLA_IPTUN_LOCAL, &local.octets());
    write_nla(&mut buf, IFLA_IPTUN_REMOTE, &remote.octets());
    write_nla(&mut buf, IFLA_IPTUN_TTL, &[64u8]);
    write_nla(&mut buf, IFLA_IPTUN_PROTO, &[IPPROTO_IPIP]);
    buf
}

/// IFLA_IPTUN_DATA（remote のみ更新用）
fn build_iptun_remote_update(remote: Ipv6Addr) -> Vec<u8> {
    let mut buf = Vec::new();
    write_nla(&mut buf, IFLA_IPTUN_REMOTE, &remote.octets());
    buf
}

/// インターフェース名から ifindex を取得する
async fn get_link_index(handle: &Handle, name: &str) -> Result<u32, MapEError> {
    let mut links = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();

    if let Some(msg) = links
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))?
    {
        Ok(msg.header.index)
    } else {
        Err(MapEError::NetlinkError(format!(
            "interface not found: {}",
            name
        )))
    }
}

/// ip6tnl トンネルインターフェースを作成する
/// 戻り値: 作成したインターフェースの ifindex
pub async fn create_tunnel(
    handle: &Handle,
    name: &str,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    link_ifindex: u32,
    mtu: Option<u32>,
) -> Result<u32, MapEError> {
    let iptun_data = build_iptun_data(local, remote, link_ifindex);

    let mut req = handle.link().add();
    {
        let msg = req.message_mut();
        msg.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Other("ip6tnl".to_string())),
            LinkInfo::Data(InfoData::Other(iptun_data)),
        ]));
    }
    req.execute()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))?;

    let ifindex = get_link_index(handle, name).await?;

    if let Some(mtu_val) = mtu {
        handle
            .link()
            .set(ifindex)
            .mtu(mtu_val)
            .execute()
            .await
            .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
    }

    Ok(ifindex)
}

/// ip6tnl トンネルインターフェースを削除する（存在しない場合は成功を返す）
pub async fn delete_tunnel(handle: &Handle, name: &str) -> Result<(), MapEError> {
    let existing = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await;

    if let Ok(Some(msg)) = existing {
        handle
            .link()
            .del(msg.header.index)
            .execute()
            .await
            .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
    }
    Ok(())
}

/// トンネルが既に存在する場合は削除して再作成する（初回 apply・CE IPv6 変化時に使用）
pub async fn ensure_tunnel(
    handle: &Handle,
    name: &str,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    link_ifindex: u32,
    mtu: Option<u32>,
) -> Result<u32, MapEError> {
    // 既存トンネルがあれば削除
    let existing = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await;

    if let Ok(Some(msg)) = existing {
        handle
            .link()
            .del(msg.header.index)
            .execute()
            .await
            .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
    }

    create_tunnel(handle, name, local, remote, link_ifindex, mtu).await
}

/// BR アドレス（remote エンドポイント）のみを RTM_NEWLINK + NLM_F_REPLACE で in-place 更新する
/// トンネルを再作成せずに済むため、BR 変化時の通信断を最小化する
pub async fn update_tunnel_remote(
    handle: &Handle,
    ifindex: u32,
    new_remote: Ipv6Addr,
) -> Result<(), MapEError> {
    let iptun_data = build_iptun_remote_update(new_remote);

    let mut req = handle.link().set(ifindex);
    {
        let msg = req.message_mut();
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Other("ip6tnl".to_string())),
            LinkInfo::Data(InfoData::Other(iptun_data)),
        ]));
    }
    req.execute()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_iptun_data_has_required_nlas() {
        let local = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let remote = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let link_ifindex: u32 = 3;

        let data = build_iptun_data(local, remote, link_ifindex);

        // 少なくとも 5 つの NLA（LINK, LOCAL, REMOTE, TTL, PROTO）が含まれる
        // 各 NLA の最小サイズは 8 バイト (4 header + 4 aligned data)
        assert!(!data.is_empty());

        // IFLA_IPTUN_REMOTE (type=3) の 16 バイトが含まれることを確認
        let remote_bytes = remote.octets();
        let found = data
            .windows(16)
            .any(|window| window == remote_bytes);
        assert!(found, "remote IPv6 address should be present in NLA data");

        // IFLA_IPTUN_LOCAL (type=2) の 16 バイトが含まれることを確認
        let local_bytes = local.octets();
        let found = data
            .windows(16)
            .any(|window| window == local_bytes);
        assert!(found, "local IPv6 address should be present in NLA data");
    }

    #[test]
    fn build_iptun_remote_update_contains_remote() {
        let remote = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);
        let data = build_iptun_remote_update(remote);

        let remote_bytes = remote.octets();
        let found = data
            .windows(16)
            .any(|window| window == remote_bytes);
        assert!(found, "remote IPv6 address should be present");

        // NLA ヘッダー: len = 4 + 16 = 20, type = IFLA_IPTUN_REMOTE = 3
        assert_eq!(&data[..2], &20u16.to_ne_bytes());
        assert_eq!(&data[2..4], &IFLA_IPTUN_REMOTE.to_ne_bytes());
    }

    #[test]
    fn write_nla_pads_to_4_byte_alignment() {
        let mut buf = Vec::new();
        // 1 バイトデータ → 4+1=5 バイト → 3 バイトパディング → 合計 8 バイト
        write_nla(&mut buf, 42, &[0xAB]);
        assert_eq!(buf.len(), 8);
        // length フィールドは 5 (実際のサイズ)
        let len = u16::from_ne_bytes([buf[0], buf[1]]);
        assert_eq!(len, 5);
    }
}
