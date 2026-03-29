use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::error::MapEError;
use crate::map::rule::MapeParams;

pub struct NftManager {
    table_name: String,
}

impl NftManager {
    pub fn new() -> Self {
        Self {
            table_name: "mapeced".to_string(),
        }
    }

    /// ルールセット文字列を生成する（副作用なし・テスト可能）。
    ///
    /// `psid_offset > 0` の場合も `psid_offset == 0` の場合も同一テンプレートを使用する。
    /// nftables は SNAT で連続ポートレンジを指定するのみで、ポート変換の詳細は tc が担当する。
    pub fn generate_ruleset(&self, params: &MapeParams, tunnel_iface: &str) -> String {
        let ce_ipv4 = params.ipv4_addr;
        let port_start = params.port_start;
        let port_end = params.port_end;
        let table = &self.table_name;

        format!(
            "table ip {table} {{\n\
            \tchain postrouting {{\n\
            \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
            \t\toifname \"{tunnel_iface}\" ip protocol {{ tcp, udp }} snat to {ce_ipv4}:{port_start}-{port_end}\n\
            \t\toifname \"{tunnel_iface}\" ip protocol icmp snat to {ce_ipv4}\n\
            \t}}\n\
            }}\n"
        )
    }

    /// nft -f - でルールセットを適用する。
    pub async fn apply(&self, params: &MapeParams, tunnel_iface: &str) -> Result<(), MapEError> {
        // 既存テーブルを削除（存在しない場合は無視）
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", &self.table_name])
            .output()
            .await;

        let ruleset = self.generate_ruleset(params, tunnel_iface);

        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| MapEError::NftError(format!("failed to spawn nft: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .await
                .map_err(|e| MapEError::NftError(format!("failed to write to nft stdin: {e}")))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| MapEError::NftError(format!("failed to wait for nft: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MapEError::NftError(format!("nft failed: {stderr}")));
        }

        Ok(())
    }

    /// テーブルを削除する（クリーンアップ時）。
    /// テーブルが存在しない場合はエラーを無視する。
    pub async fn delete_table(&self) -> Result<(), MapEError> {
        let output = Command::new("nft")
            .args(["delete", "table", "ip", &self.table_name])
            .output()
            .await
            .map_err(|e| MapEError::NftError(format!("failed to spawn nft: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // テーブルが存在しない場合は正常終了とみなす
            if !stderr.contains("No such file or directory")
                && !stderr.contains("No such table")
                && !stderr.contains("Could not process")
            {
                return Err(MapEError::NftError(format!(
                    "nft delete table failed: {stderr}"
                )));
            }
        }

        Ok(())
    }
}

pub struct TcManager;

impl TcManager {
    /// tc 設定全体を適用する（qdisc + filter + pedit）。
    /// `psid_offset == 0` の場合は何もしない。
    pub async fn apply(&self, params: &MapeParams, tunnel_iface: &str) -> Result<(), MapEError> {
        if params.port_params.psid_offset == 0 {
            return Ok(());
        }

        // 既存 qdisc を削除（存在しない場合は無視）
        self.cleanup(tunnel_iface).await?;

        let commands = Self::generate_tc_commands(params, tunnel_iface);

        for cmd in &commands {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let output = Command::new(parts[0])
                .args(&parts[1..])
                .output()
                .await
                .map_err(|e| MapEError::NftError(format!("failed to spawn tc: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(MapEError::NftError(format!(
                    "tc command failed [{cmd}]: {stderr}"
                )));
            }
        }

        Ok(())
    }

    /// tc 設定を削除する（qdisc 削除で filter も連動削除される）。
    pub async fn cleanup(&self, tunnel_iface: &str) -> Result<(), MapEError> {
        // egress qdisc 削除（存在しない場合は無視）
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", tunnel_iface, "root"])
            .output()
            .await;

        // ingress qdisc 削除（存在しない場合は無視）
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", tunnel_iface, "ingress"])
            .output()
            .await;

        Ok(())
    }

    /// tc コマンド文字列列を生成する（副作用なし・テスト可能）。
    ///
    /// `psid_offset == 0` の場合は空ベクタを返す。
    ///
    /// ## ポートフィールドオフセット（tc u32 at nexthdr+N）
    ///
    /// | 方向 | パケット種別 | フィールド | オフセット |
    /// |------|-------------|-----------|-----------|
    /// | egress | TCP/UDP | src port | nexthdr+0 |
    /// | egress | ICMP inner | inner src port | nexthdr+48 |
    /// | ingress | TCP/UDP | dst port | nexthdr+2 |
    /// | ingress | ICMP inner | inner dst port | nexthdr+50 |
    ///
    /// nexthdr+48: IPv4(20) + ICMP(8) + 内包 IPv4(20) = 48 bytes（src port）
    /// nexthdr+50: 同上 + dst port オフセット 2 = 50 bytes
    pub fn generate_tc_commands(params: &MapeParams, tunnel_iface: &str) -> Vec<String> {
        let psid_offset = params.port_params.psid_offset;
        let psid_len = params.port_params.psid_len;
        let psid = params.psid;
        let a_min = params.a_min;
        let ce_ipv4 = params.ipv4_addr;

        if psid_offset == 0 {
            return vec![];
        }

        let m_bits = 16u8
            .checked_sub(psid_offset + psid_len)
            .expect("psid_offset + psid_len must be < 16");
        let m = m_bits as u32;
        let a = psid_offset as u32;
        let r_max = (1u32 << a) - 1;

        // PSID フィールドのビットマスク: bits[M+psid_len-1 : M]
        let psid_check_mask: u32 = ((1u32 << psid_len) - 1) << m;

        let mut cmds = Vec::new();

        // Egress qdisc（tunnel インターフェースへの egress）
        cmds.push(format!(
            "tc qdisc add dev {tunnel_iface} handle 1: root prio"
        ));

        // Ingress qdisc（tunnel インターフェースの ingress）
        cmds.push(format!(
            "tc qdisc add dev {tunnel_iface} handle ffff: ingress"
        ));

        // R 値ごとにフィルタルールを生成
        for r in (a_min as u32)..=r_max {
            // === Egress: C 空間 → S 空間 ===
            // C 空間マッチ: bit15=1 かつ R-in-C フィールド = r（m フィールドはワイルドカード）
            let c_match_val = (1u32 << 15) | (r << m);
            let c_match_mask = (1u32 << 15) | (r_max << m);
            // Pedit: bit15 と R-in-C フィールドをクリアし、S 空間の R フィールドと PSID を設定
            let pedit_and = (!c_match_mask & 0xFFFF) as u16;
            let pedit_or = ((r << (psid_len as u32 + m)) | ((psid as u32) << m)) as u16;

            // === Ingress: S 空間 → C 空間 ===
            // S 空間マッチ: R フィールドと PSID フィールドを照合（m フィールドはワイルドカード）
            let s_match_val = (r << (psid_len as u32 + m)) | ((psid as u32) << m);
            let s_match_mask = (r_max << (psid_len as u32 + m)) | psid_check_mask;
            // Pedit: m フィールド以外をクリアし、C 空間の bit15 と R-in-C フィールドを設定
            let ingress_pedit_and: u16 = (1u16 << m_bits) - 1;
            let ingress_pedit_or: u16 = ((1u32 << 15) | (r << m)) as u16;

            // TCP（proto=6）と UDP（proto=17）ごとにルール生成
            for proto in [6u32, 17u32] {
                // Egress: TCP/UDP src port（nexthdr+0）
                cmds.push(format!(
                    "tc filter add dev {tunnel_iface} parent 1: protocol ip u32 \
                    match ip src {ce_ipv4}/32 \
                    match ip protocol {proto} 0xff \
                    match u16 0x{c_match_val:04x} 0x{c_match_mask:04x} at nexthdr+0 \
                    action pedit ex munge u16 and 0x{pedit_and:04x} or 0x{pedit_or:04x} at nexthdr+0 \
                    action csum ip4h l4"
                ));

                // Ingress: TCP/UDP dst port（nexthdr+2）
                cmds.push(format!(
                    "tc filter add dev {tunnel_iface} parent ffff: protocol ip u32 \
                    match ip dst {ce_ipv4}/32 \
                    match ip protocol {proto} 0xff \
                    match u16 0x{s_match_val:04x} 0x{s_match_mask:04x} at nexthdr+2 \
                    action pedit ex munge u16 and 0x{ingress_pedit_and:04x} or 0x{ingress_pedit_or:04x} at nexthdr+2 \
                    action csum ip4h l4"
                ));
            }

            // ICMP エラー内包ヘッダ（outer proto=1）
            // Egress: 内包 TCP/UDP src port（nexthdr+48）
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} parent 1: protocol ip u32 \
                match ip src {ce_ipv4}/32 \
                match ip protocol 1 0xff \
                match u16 0x{c_match_val:04x} 0x{c_match_mask:04x} at nexthdr+48 \
                action pedit ex munge u16 and 0x{pedit_and:04x} or 0x{pedit_or:04x} at nexthdr+48 \
                action csum ip4h l4"
            ));

            // Ingress: 内包 TCP/UDP dst port（nexthdr+50）
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} parent ffff: protocol ip u32 \
                match ip dst {ce_ipv4}/32 \
                match ip protocol 1 0xff \
                match u16 0x{s_match_val:04x} 0x{s_match_mask:04x} at nexthdr+50 \
                action pedit ex munge u16 and 0x{ingress_pedit_and:04x} or 0x{ingress_pedit_or:04x} at nexthdr+50 \
                action csum ip4h l4"
            ));
        }

        cmds
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::map::rule::{MapeParams, PortParams};

    fn make_v6plus_params(psid: u16, a_min: u16) -> MapeParams {
        // v6プラス固定パラメータ: psid_offset=4, psid_len=8, M=4
        // port_start/port_end は calc_continuous_range に準拠
        // PORT_START = (1<<15) + (a_min<<4)
        let port_start = (1u16 << 15) + (a_min << 4);
        // PORT_END = PORT_START + (16 - a_min) * 16 - 1
        let num_blocks = 16u32 - a_min as u32;
        let port_end = (port_start as u32 + num_blocks * 16 - 1) as u16;

        // port_ranges は省略（テストでは使用しない）
        let port_ranges = vec![];

        MapeParams {
            ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
            ce_ipv6_addr: Ipv6Addr::UNSPECIFIED,
            br_ipv6_addr: Ipv6Addr::UNSPECIFIED,
            psid,
            port_params: PortParams {
                psid_offset: 4,
                psid_len: 8,
                psid,
            },
            port_ranges,
            port_start,
            port_end,
            a_min,
            is_fmr: false,
        }
    }

    fn make_psid_offset_zero_params() -> MapeParams {
        MapeParams {
            ipv4_addr: Ipv4Addr::new(192, 0, 2, 1),
            ce_ipv6_addr: Ipv6Addr::UNSPECIFIED,
            br_ipv6_addr: Ipv6Addr::UNSPECIFIED,
            psid: 5,
            port_params: PortParams {
                psid_offset: 0,
                psid_len: 8,
                psid: 5,
            },
            port_ranges: vec![],
            port_start: 1280,
            port_end: 1535,
            a_min: 0,
            is_fmr: false,
        }
    }

    // ─── NftManager テスト ────────────────────────────────────────────────────

    #[test]
    fn test_generate_ruleset_v6plus() {
        let mgr = NftManager::new();
        let params = make_v6plus_params(5, 1);
        let ruleset = mgr.generate_ruleset(&params, "ip6tnl0");

        // テーブル名・チェーン・フックが含まれること
        assert!(ruleset.contains("table ip mapeced"));
        assert!(ruleset.contains("chain postrouting"));
        assert!(ruleset.contains("type nat hook postrouting priority srcnat"));

        // SNAT ルール: ce_ipv4 と port_start-port_end
        // port_start = 32784, port_end = 33023
        assert!(
            ruleset.contains("snat to 192.0.2.1:32784-33023"),
            "ruleset = {ruleset}"
        );

        // ICMP SNAT
        assert!(ruleset.contains("ip protocol icmp snat to 192.0.2.1"));

        // tunnel_iface が正しく埋め込まれること
        assert!(ruleset.contains("oifname \"ip6tnl0\""));
    }

    #[test]
    fn test_generate_ruleset_psid_offset_zero() {
        let mgr = NftManager::new();
        let params = make_psid_offset_zero_params();
        let ruleset = mgr.generate_ruleset(&params, "ip6tnl1");

        assert!(ruleset.contains("table ip mapeced"));
        assert!(ruleset.contains("snat to 192.0.2.1:1280-1535"));
        assert!(ruleset.contains("oifname \"ip6tnl1\""));
    }

    // ─── TcManager テスト ─────────────────────────────────────────────────────

    #[test]
    fn test_generate_tc_commands_psid_offset_zero_returns_empty() {
        let params = make_psid_offset_zero_params();
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_generate_tc_commands_v6plus_qdisc() {
        // v6plus: psid_offset=4, psid_len=8, M=4, a_min=1
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");

        // 最初の 2 コマンドは qdisc add
        assert!(cmds[0].contains("tc qdisc add dev ip6tnl0 handle 1: root prio"));
        assert!(cmds[1].contains("tc qdisc add dev ip6tnl0 handle ffff: ingress"));
    }

    #[test]
    fn test_generate_tc_commands_v6plus_filter_count() {
        // v6plus: R ∈ [1, 15] の 15 値
        // 各 R: TCP egress + UDP egress + TCP ingress + UDP ingress + ICMP inner egress + ICMP inner ingress = 6 ルール
        // 2 (qdisc) + 15 * 6 = 92
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert_eq!(cmds.len(), 2 + 15 * 6, "cmd count = {}", cmds.len());
    }

    #[test]
    fn test_generate_tc_commands_v6plus_r1_egress_tcp() {
        // R=1, psid=5, M=4, psid_offset=4, psid_len=8
        // c_match_val = 0x8000 | (1<<4) = 0x8010
        // c_match_mask = 0x8000 | (15<<4) = 0x80f0
        // pedit_and = ~0x80f0 & 0xffff = 0x7f0f
        // pedit_or = (1<<12) | (5<<4) = 0x1000 | 0x0050 = 0x1050
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");

        // qdisc 2 件 → R=1 の TCP egress は index 2
        let cmd = &cmds[2];
        assert!(cmd.contains("parent 1:"), "cmd = {cmd}");
        assert!(cmd.contains("match ip protocol 6 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("match u16 0x8010 0x80f0 at nexthdr+0"), "cmd = {cmd}");
        assert!(cmd.contains("and 0x7f0f or 0x1050 at nexthdr+0"), "cmd = {cmd}");
        assert!(cmd.contains("action csum ip4h l4"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_v6plus_r1_ingress_tcp() {
        // R=1, psid=5, M=4, psid_offset=4, psid_len=8
        // s_match_val = (1<<12) | (5<<4) = 0x1050
        // s_match_mask = (15<<12) | ((1<<8)-1)<<4 = 0xf000 | 0x0ff0 = 0xfff0
        // ingress_pedit_and = (1<<4)-1 = 0x000f
        // ingress_pedit_or = 0x8000 | (1<<4) = 0x8010
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");

        // qdisc 2 件 → R=1: TCP egress(2), TCP ingress(3)
        let cmd = &cmds[3];
        assert!(cmd.contains("parent ffff:"), "cmd = {cmd}");
        assert!(cmd.contains("match ip protocol 6 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("match u16 0x1050 0xfff0 at nexthdr+2"), "cmd = {cmd}");
        assert!(cmd.contains("and 0x000f or 0x8010 at nexthdr+2"), "cmd = {cmd}");
        assert!(cmd.contains("action csum ip4h l4"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_v6plus_r1_icmp_egress() {
        // R=1 の ICMP inner egress はインデックス 2+4=6 (TCP egress, TCP ingress, UDP egress, UDP ingress, ICMP egress)
        // qdisc(2) + R=1: tcp_eg(2), tcp_in(3), udp_eg(4), udp_in(5), icmp_eg(6)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");

        let cmd = &cmds[6];
        assert!(cmd.contains("parent 1:"), "cmd = {cmd}");
        assert!(cmd.contains("match ip protocol 1 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("match u16 0x8010 0x80f0 at nexthdr+48"), "cmd = {cmd}");
        assert!(cmd.contains("and 0x7f0f or 0x1050 at nexthdr+48"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_v6plus_r1_icmp_ingress() {
        // qdisc(2) + R=1: tcp_eg(2), tcp_in(3), udp_eg(4), udp_in(5), icmp_eg(6), icmp_in(7)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");

        let cmd = &cmds[7];
        assert!(cmd.contains("parent ffff:"), "cmd = {cmd}");
        assert!(cmd.contains("match ip protocol 1 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("match u16 0x1050 0xfff0 at nexthdr+50"), "cmd = {cmd}");
        assert!(cmd.contains("and 0x000f or 0x8010 at nexthdr+50"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_psid0_r1_egress_values() {
        // psid=0, a_min=1 の場合: pedit_or = (1<<12) | 0 = 0x1000
        let params = make_v6plus_params(0, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");

        // R=1 の TCP egress
        let cmd = &cmds[2];
        assert!(cmd.contains("match u16 0x8010 0x80f0 at nexthdr+0"), "cmd = {cmd}");
        assert!(cmd.contains("and 0x7f0f or 0x1000 at nexthdr+0"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_a_min_2() {
        // a_min=2 の場合: R ∈ [2, 15] の 14 値
        // 2 (qdisc) + 14 * 6 = 86
        let params = make_v6plus_params(5, 2);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert_eq!(cmds.len(), 2 + 14 * 6, "cmd count = {}", cmds.len());

        // 先頭フィルタは R=2 の TCP egress
        // c_match_val = 0x8000 | (2<<4) = 0x8020
        let cmd = &cmds[2];
        assert!(cmd.contains("match u16 0x8020 0x80f0 at nexthdr+0"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_includes_ce_ipv4() {
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");

        // Egress フィルタは ce_ipv4 src マッチを含む
        assert!(cmds[2].contains("match ip src 192.0.2.1/32"));
        // Ingress フィルタは ce_ipv4 dst マッチを含む
        assert!(cmds[3].contains("match ip dst 192.0.2.1/32"));
    }
}
