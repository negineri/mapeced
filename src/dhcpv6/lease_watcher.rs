use std::ffi::OsStr;
use std::net::Ipv6Addr;
use std::os::unix::io::{AsFd, AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use nix::net::if_::if_nametoindex;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;
use tracing::warn;

use crate::error::MapEError;

const LEASES_DIR: &str = "/run/systemd/netif/leases/";

/// Wrapper to make `Inotify` usable with `AsyncFd` (which requires `AsRawFd`).
struct InotifyFd(Inotify);

impl AsRawFd for InotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}

impl InotifyFd {
    fn inner(&self) -> &Inotify {
        &self.0
    }
}

/// Read the delegated IPv6 prefix from a systemd-networkd lease file.
/// Looks for a line `PREFIXES=<addr>/<len> ...` and returns the first
/// prefix with len <= 64 (IA_PD prefix).
fn read_lease_prefix(path: &Path) -> Option<(Ipv6Addr, u8)> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("PREFIXES=") {
            // Take the first whitespace-separated entry
            if let Some(first) = value.split_whitespace().next()
                && let Some((addr_str, len_str)) = first.split_once('/')
                && let Ok(len) = len_str.parse::<u8>()
                && len <= 64
                && let Ok(addr) = addr_str.parse::<Ipv6Addr>()
            {
                return Some((addr, len));
            }
        }
    }
    None
}

/// Watch the systemd-networkd lease file for the given interface and send
/// prefix updates via `tx`.
///
/// Sends `Some((addr, len))` when a valid prefix is found, or `None` when
/// the lease file is deleted.
pub async fn run_lease_watcher(
    ifname: &str,
    tx: watch::Sender<Option<(Ipv6Addr, u8)>>,
) -> Result<(), MapEError> {
    let ifindex = if_nametoindex(ifname).map_err(|e| {
        MapEError::NetlinkError(format!("if_nametoindex({ifname}): {e}"))
    })?;

    let leases_dir = Path::new(LEASES_DIR);
    if !leases_dir.exists() {
        return Err(MapEError::InvalidConfig(format!(
            "leases directory not found: {LEASES_DIR}"
        )));
    }

    let ifindex_name = ifindex.to_string();
    let lease_path: PathBuf = leases_dir.join(&ifindex_name);

    // Send initial value if lease file already exists
    if lease_path.exists() {
        let initial = read_lease_prefix(&lease_path);
        let _ = tx.send(initial);
    }

    // Create inotify instance
    let inotify = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK).map_err(|e| {
        MapEError::NetlinkError(format!("inotify init failed: {e}"))
    })?;

    // Watch the leases directory for writes, moves, and deletes
    inotify
        .add_watch(
            leases_dir,
            AddWatchFlags::IN_CLOSE_WRITE
                | AddWatchFlags::IN_MOVED_TO
                | AddWatchFlags::IN_DELETE,
        )
        .map_err(|e| MapEError::NetlinkError(format!("inotify add_watch failed: {e}")))?;

    let async_fd = AsyncFd::new(InotifyFd(inotify)).map_err(|e| {
        MapEError::NetlinkError(format!("AsyncFd::new failed: {e}"))
    })?;

    loop {
        let mut guard = async_fd.readable().await.map_err(|e| {
            MapEError::NetlinkError(format!("readable() failed: {e}"))
        })?;

        let result = guard.try_io(|fd| {
            fd.get_ref()
                .inner()
                .read_events()
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        });

        match result {
            Ok(Ok(events)) => {
                for event in events {
                    let matches = event
                        .name
                        .as_deref()
                        .map(|n| n == OsStr::new(&ifindex_name))
                        .unwrap_or(false);

                    if !matches {
                        continue;
                    }

                    if event.mask.contains(AddWatchFlags::IN_DELETE) {
                        let _ = tx.send(None);
                    } else {
                        let prefix = read_lease_prefix(&lease_path);
                        let _ = tx.send(prefix);
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("inotify read error: {e}");
            }
            Err(_would_block) => {
                // WouldBlock: continue
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Ipv6Addr;

    use super::read_lease_prefix;

    fn write_temp_file(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("failed to create temp file");
        f.write_all(content.as_bytes()).expect("failed to write");
        f
    }

    #[test]
    fn test_read_valid_prefix() {
        let f = write_temp_file("PREFIXES=2404:9200:225:100::/48\n");
        let result = read_lease_prefix(f.path());
        assert_eq!(
            result,
            Some(("2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(), 48))
        );
    }

    #[test]
    fn test_read_multiple_prefixes() {
        let f = write_temp_file(
            "PREFIXES=2404:9200:225:100::/48 2404:9200:225:200::/48\n",
        );
        let result = read_lease_prefix(f.path());
        assert_eq!(
            result,
            Some(("2404:9200:225:100::".parse::<Ipv6Addr>().unwrap(), 48))
        );
    }

    #[test]
    fn test_skip_too_long_prefix() {
        // len=128 > 64, should be skipped
        let f = write_temp_file("PREFIXES=2404:9200:225:100::1/128\n");
        let result = read_lease_prefix(f.path());
        assert_eq!(result, None);
    }

    #[test]
    fn test_no_prefixes() {
        let f = write_temp_file("ADDRESS=2404:9200:225:100::1\nROUTER=fe80::1\n");
        let result = read_lease_prefix(f.path());
        assert_eq!(result, None);
    }
}
