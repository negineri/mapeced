use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use rtnetlink::Handle;

use crate::error::MapEError;

/// WAN または tunnel インターフェースに IPv6 /128 アドレスを追加する
pub async fn add_ipv6_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv6Addr,
) -> Result<(), MapEError> {
    handle
        .address()
        .add(ifindex, IpAddr::V6(addr), 128)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))
}

/// WAN または tunnel インターフェースから IPv6 /128 アドレスを削除する（存在しない場合は無視）
pub async fn del_ipv6_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv6Addr,
) -> Result<(), MapEError> {
    let target = IpAddr::V6(addr);
    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(ifindex)
        .execute();

    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))?
    {
        for attr in &msg.attributes {
            if let AddressAttribute::Address(a) = attr {
                if *a == target {
                    handle
                        .address()
                        .del(msg)
                        .execute()
                        .await
                        .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// tunnel インターフェースに IPv4 /32 アドレスを追加する（CE IPv4）
pub async fn add_ipv4_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv4Addr,
) -> Result<(), MapEError> {
    handle
        .address()
        .add(ifindex, IpAddr::V4(addr), 32)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))
}

/// tunnel インターフェースから IPv4 /32 アドレスを削除する（存在しない場合は無視）
pub async fn del_ipv4_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv4Addr,
) -> Result<(), MapEError> {
    let target = IpAddr::V4(addr);
    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(ifindex)
        .execute();

    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))?
    {
        for attr in &msg.attributes {
            if let AddressAttribute::Address(a) = attr {
                if *a == target {
                    handle
                        .address()
                        .del(msg)
                        .execute()
                        .await
                        .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}
