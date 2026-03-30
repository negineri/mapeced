//! Phase 1: inotify リース監視統合テスト（非特権）
//!
//! `cargo test --test lease_watcher` で実行する。
//! Linux の inotify を使用するため Linux 環境限定。

#![cfg(target_os = "linux")]

mod common;

use std::net::Ipv6Addr;
use std::time::Duration;

use mapeced::dhcpv6::lease_watcher::run_lease_watcher_inner;
use tokio::sync::watch;

// ── ヘルパー ──────────────────────────────────────────────────────────────────

/// ウォッチャーを起動し、準備が整うまで待機する。
/// `dir_path` に inotify watch を張る時間を確保するため 100ms スリープする。
async fn spawn_watcher(
    dir_path: std::path::PathBuf,
    ifindex_name: &'static str,
    tx: watch::Sender<Option<(Ipv6Addr, u8)>>,
) {
    tokio::spawn(async move {
        run_lease_watcher_inner(&dir_path, ifindex_name, tx)
            .await
            .ok();
    });
    // inotify watch の登録が完了するまで待機
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// `rx` が `expected` になるまで最大 `timeout` 待つ。タイムアウトでパニック。
async fn wait_for_value(
    rx: &mut watch::Receiver<Option<(Ipv6Addr, u8)>>,
    expected: Option<(Ipv6Addr, u8)>,
    timeout: Duration,
) {
    tokio::time::timeout(timeout, async {
        loop {
            if *rx.borrow() == expected {
                break;
            }
            rx.changed().await.expect("watch channel closed");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout: expected value {expected:?} not received"));
}

// ── テストケース ──────────────────────────────────────────────────────────────

/// lw_01: リースファイル新規作成時に IA_PD プレフィックスが通知される。
#[tokio::test]
async fn lw_01_new_file_sends_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let lease_file = dir_path.join("42");

    let (tx, mut rx) = watch::channel(None);
    spawn_watcher(dir_path, "42", tx).await;

    std::fs::write(&lease_file, "PREFIXES=2404:9200:225:100::/48\n").unwrap();

    let expected: Option<(Ipv6Addr, u8)> =
        Some(("2404:9200:225:100::".parse().unwrap(), 48));
    wait_for_value(&mut rx, expected, Duration::from_secs(5)).await;
}

/// lw_02: リースファイル更新（プレフィックス変更）で新しいプレフィックスが通知される。
#[tokio::test]
async fn lw_02_file_update_sends_new_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let lease_file = dir_path.join("42");

    let (tx, mut rx) = watch::channel(None);
    spawn_watcher(dir_path, "42", tx).await;

    // 初回書き込み
    std::fs::write(&lease_file, "PREFIXES=2001:db8:1::/48\n").unwrap();
    wait_for_value(
        &mut rx,
        Some(("2001:db8:1::".parse().unwrap(), 48)),
        Duration::from_secs(5),
    )
    .await;

    // プレフィックスを変更して更新
    std::fs::write(&lease_file, "PREFIXES=2404:9200:225:200::/56\n").unwrap();
    wait_for_value(
        &mut rx,
        Some(("2404:9200:225:200::".parse().unwrap(), 56)),
        Duration::from_secs(5),
    )
    .await;
}

/// lw_03: リースファイル削除時に None が通知される。
#[tokio::test]
async fn lw_03_file_deletion_sends_none() {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let lease_file = dir_path.join("42");

    // ファイルを先に作成してからウォッチャーを起動（初期値として送信させる）
    std::fs::write(&lease_file, "PREFIXES=2404:9200:225:100::/48\n").unwrap();

    let (tx, mut rx) = watch::channel(None);
    let dir_path2 = dir.path().to_path_buf();
    tokio::spawn(async move {
        run_lease_watcher_inner(&dir_path2, "42", tx).await.ok();
    });

    // 初期値が送信されるまで待機
    wait_for_value(
        &mut rx,
        Some(("2404:9200:225:100::".parse().unwrap(), 48)),
        Duration::from_secs(5),
    )
    .await;

    // ファイルを削除 → None が送信される
    std::fs::remove_file(&lease_file).unwrap();
    wait_for_value(&mut rx, None, Duration::from_secs(5)).await;
}

/// lw_04: IA_PD エントリが存在しないリースファイルの場合、パースエラーにならず None が通知される。
#[tokio::test]
async fn lw_04_no_iapd_entry_sends_none() {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let lease_file = dir_path.join("42");

    let (tx, mut rx) = watch::channel(Some(("::1".parse::<Ipv6Addr>().unwrap(), 128)));
    spawn_watcher(dir_path, "42", tx).await;

    // PREFIXES 行なし（ADDRESS のみ）
    std::fs::write(&lease_file, "ADDRESS=2404:9200:225:100::1\nROUTER=fe80::1\n").unwrap();

    // None が通知される（パースエラーにならず正常終了）
    wait_for_value(&mut rx, None, Duration::from_secs(5)).await;
}

/// lw_05: 複数のリース変化が連続して発生した場合、最終状態が反映される。
#[tokio::test]
async fn lw_05_multiple_rapid_changes_last_state_wins() {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_path_buf();
    let lease_file = dir_path.join("42");

    let (tx, mut rx) = watch::channel(None);
    spawn_watcher(dir_path, "42", tx).await;

    // 3 回連続で書き込む
    std::fs::write(&lease_file, "PREFIXES=2001:db8:1::/48\n").unwrap();
    std::fs::write(&lease_file, "PREFIXES=2001:db8:2::/48\n").unwrap();
    std::fs::write(&lease_file, "PREFIXES=2404:9200:225:100::/48\n").unwrap();

    // 最終状態が反映されることを確認
    let expected_final: Option<(Ipv6Addr, u8)> =
        Some(("2404:9200:225:100::".parse().unwrap(), 48));
    wait_for_value(&mut rx, expected_final, Duration::from_secs(5)).await;
}
