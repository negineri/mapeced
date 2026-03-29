use std::net::Ipv4Addr;

use futures::TryStreamExt;
use netlink_packet_route::route::{RouteAttribute, RouteAddress};
use rtnetlink::{Handle, IpVersion};

use crate::error::MapEError;

/// デフォルトルート（0.0.0.0/0）を tunnel インターフェース経由に設定する
pub async fn add_default_route(
    handle: &Handle,
    tunnel_ifindex: u32,
) -> Result<(), MapEError> {
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(tunnel_ifindex)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))
}

/// デフォルトルート（0.0.0.0/0）を tunnel インターフェース経由から削除する（存在しない場合は無視）
pub async fn del_default_route(
    handle: &Handle,
    tunnel_ifindex: u32,
) -> Result<(), MapEError> {
    let mut routes = handle.route().get(IpVersion::V4).execute();

    while let Some(route) = routes
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))?
    {
        if route.header.destination_prefix_length != 0 {
            continue;
        }
        let has_oif = route.attributes.iter().any(|attr| {
            matches!(attr, RouteAttribute::Oif(oif) if *oif == tunnel_ifindex)
        });
        if has_oif {
            handle
                .route()
                .del(route)
                .execute()
                .await
                .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
            return Ok(());
        }
    }
    Ok(())
}

/// FMR ルート（MAP Rule の IPv4 プレフィックス宛）を追加する
pub async fn add_fmr_route(
    handle: &Handle,
    prefix: Ipv4Addr,
    prefix_len: u8,
    tunnel_ifindex: u32,
) -> Result<(), MapEError> {
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(prefix, prefix_len)
        .output_interface(tunnel_ifindex)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))
}

/// FMR ルート（MAP Rule の IPv4 プレフィックス宛）を削除する（存在しない場合は無視）
pub async fn del_fmr_route(
    handle: &Handle,
    prefix: Ipv4Addr,
    prefix_len: u8,
    tunnel_ifindex: u32,
) -> Result<(), MapEError> {
    let mut routes = handle.route().get(IpVersion::V4).execute();

    while let Some(route) = routes
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(e.to_string()))?
    {
        if route.header.destination_prefix_length != prefix_len {
            continue;
        }
        let has_dest = route.attributes.iter().any(|attr| {
            matches!(
                attr,
                RouteAttribute::Destination(RouteAddress::Inet(dest)) if *dest == prefix
            )
        });
        let has_oif = route.attributes.iter().any(|attr| {
            matches!(attr, RouteAttribute::Oif(oif) if *oif == tunnel_ifindex)
        });
        if has_dest && has_oif {
            handle
                .route()
                .del(route)
                .execute()
                .await
                .map_err(|e| MapEError::NetlinkError(e.to_string()))?;
            return Ok(());
        }
    }
    Ok(())
}
