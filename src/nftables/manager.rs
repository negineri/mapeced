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
            \tchain {table}-clamp {{\n\
            \t\ttype filter hook forward priority mangle - 5; policy accept;\n\
            \t\tiifname \"{tunnel_iface}\" counter tcp flags syn tcp option maxseg size set rt mtu\n\
            \t\toifname \"{tunnel_iface}\" counter tcp flags syn tcp option maxseg size set rt mtu\n\
            \t}}\n\
            \tchain {table}-mark {{\n\
            \t\ttype filter hook postrouting priority filter - 5; policy accept;\n\
            \t\toifname \"{tunnel_iface}\" meta l4proto tcp mark set mark & 0xffffff00 | 0x54 counter\n\
            \t\toifname \"{tunnel_iface}\" meta l4proto udp mark set mark & 0xffffff00 | 0x55 counter\n\
            \t\toifname \"{tunnel_iface}\" ip protocol icmp icmp type {{ echo-request }} mark set mark & 0xffffff00 | 0x59 counter\n\
            \t}}\n\
            \tchain {table}-snat {{\n\
            \t\ttype nat hook postrouting priority srcnat - 5; policy accept;\n\
            \t\toifname \"{tunnel_iface}\" meta l4proto {{ tcp, udp, icmp }} counter snat to {ce_ipv4}:{port_start}-{port_end}\n\
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

    /// tc 設定を削除する（clsact qdisc 削除で filter も連動削除される）。
    pub async fn cleanup(&self, tunnel_iface: &str) -> Result<(), MapEError> {
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", tunnel_iface, "clsact"])
            .output()
            .await;

        Ok(())
    }

    /// tc コマンド文字列列を生成する（副作用なし・テスト可能）。
    ///
    /// `psid_offset == 0` の場合は空ベクタを返す。
    ///
    /// ## 設計: マーク + ビット単位ルール（fw handle / u32 分類）
    ///
    /// nftables でマーク付け → tc fw handle / u32 フィルタでポート変換 → チェックサム更新
    /// の順で処理する。R ビット数 `a = psid_offset` に比例した固定ルール数（6a + 20）を生成する。
    ///
    /// ### egress (C 空間 → S 空間)
    ///
    /// ```text
    /// u32 match mark 0x54/0xfe: R ビットを C 空間 bits[M+i] → S 空間 bits[M+psid_len+i] へコピー (a-1 個)
    /// u32 match mark 0x54/0xfe: 最上位 R ビット (top_c_bit) = 0 のとき bit15 をクリア
    /// fw 0x54/0xfe: PSID をポートフィールドに挿入 (TCP + UDP 共通)
    /// fw 0x54/0xff: TCP チェックサム更新
    /// fw 0x55/0xff: UDP チェックサム更新
    /// ```
    ///
    /// ### ingress (S 空間 → C 空間)
    ///
    /// ```text
    /// u32 match ip protocol + PSID: マーク付け (TCP=0x64, UDP=0x65, ICMP=0x69/0x79/0x89)
    /// fw 0x64/0xfe: bit15 セット (C 空間ポートの最上位ビット確立、retain 0xf000)
    /// u32 match mark 0x64/0xfe: R ビットを S 空間 bits[M+psid_len+i] → C 空間 bits[M+i] へコピー (a 個)
    /// u32 match mark 0x64/0xfe: PSID フィールドをゼロクリア
    /// fw 0x64/0xff: TCP チェックサム更新
    /// fw 0x65/0xff: UDP チェックサム更新
    /// ```
    ///
    /// ### オフセット
    ///
    /// | フィールド | `pedit offset` / `u32 at` |
    /// |-----------|--------------------------|
    /// | TCP/UDP src port | `ip sport` |
    /// | TCP/UDP dst port | `ip dport` |
    /// | ICMP identifier | `offset 24` (= nexthdr+4) |
    /// | ICMP error inner src port | `offset 48` (= nexthdr+28) |
    pub fn generate_tc_commands(params: &MapeParams, tunnel_iface: &str) -> Vec<String> {
        let psid_offset = params.port_params.psid_offset;
        let psid_len = params.port_params.psid_len;
        let psid = params.psid;

        if psid_offset == 0 {
            return vec![];
        }

        let m = (16u8 - psid_offset - psid_len) as u32; // M: suffix ビット数
        let a = psid_offset as u32; // A: R ビット数（= psid_offset）

        // PSID フィールド: bits[M+psid_len-1:M]
        let psid_val = (psid as u32) << m;
        let psid_mask = ((1u32 << psid_len) - 1) << m;

        // 最上位 R ビット（C 空間内）: bit(M+a-1)
        let top_c_bit = 1u32 << (m + a - 1);

        let mut cmds = Vec::new();

        cmds.push(format!("tc qdisc add dev {tunnel_iface} clsact"));

        // ── Egress TCP/UDP (C 空間 → S 空間) ──────────────────────────────────
        // marks: TCP=0x54, UDP=0x55（fw handle 0x54/0xfe で両方にマッチ）

        cmds.push(format!(
            "tc filter add dev {tunnel_iface} egress handle 0x55/0xff fw action csum ip4h udp continue"
        ));
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} egress handle 0x54/0xff fw action csum ip4h tcp continue"
        ));
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} egress handle 0x54/0xfe fw action pedit pedit munge ip sport set \"0x{psid_val:04x}\" retain 0x{psid_mask:04x} continue"
        ));
        for i in 0..a - 1 {
            let c_bit = 1u32 << (m + i);
            let s_bit = 1u32 << (m + psid_len as u32 + i);
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} egress u32 match mark 0x54 0x000000fe \
                match ip sport 0x{c_bit:04x} 0x{c_bit:04x} action pedit pedit munge ip sport set 0x{s_bit:04x} retain 0x{s_bit:04x} continue"
            ));
        }
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} egress u32 match mark 0x54 0x000000fe \
            match ip sport 0x0000 0x{top_c_bit:04x} action pedit pedit munge ip sport set 0x0000 retain 0x8000 continue"
        ));

        // ── Egress ICMP echo request (type 8) ──────────────────────────────────
        // identifier フィールド: IP offset 24 (= nexthdr+4)  mark: 0x59

        cmds.push(format!(
            "tc filter add dev {tunnel_iface} egress u32 match mark 0x59 0x000000ff action pedit pedit munge offset 24 u16 set \"0x{psid_val:04x}\" retain 0x{psid_mask:04x} pipe action csum ip4h icmp continue"
        ));
        for i in 0..a - 1 {
            let c_bit = 1u32 << (m + i);
            let s_bit = 1u32 << (m + psid_len as u32 + i);
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} egress u32 match mark 0x59 0x000000ff \
                match u16 0x{c_bit:04x} 0x{c_bit:04x} at 24 action pedit pedit munge offset 24 u16 set 0x{s_bit:04x} retain 0x{s_bit:04x} continue"
            ));
        }
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} egress u32 match mark 0x59 0x000000ff \
            match u16 0x0000 0x{top_c_bit:04x} at 24 action pedit pedit munge offset 24 u16 set 0x0000 retain 0x8000 continue"
        ));

        // ── Ingress TCP/UDP (S 空間 → C 空間) ─────────────────────────────────
        // marks: TCP=0x64, UDP=0x65（fw handle 0x64/0xfe で両方にマッチ）

        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress handle 0x65/0xff fw action csum ip4h udp continue"
        ));
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress handle 0x64/0xff fw action csum ip4h tcp continue"
        ));
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress handle 0x64/0xfe fw action pedit pedit munge ip dport set 0x8000 retain 0xf000 continue"
        ));
        for i in 0..a {
            // 16 = psid_offset + psid_len + m
            let s_bit = 1u32 << (16 - 1 - i);
            let c_bit = 1u32 << (16 - 1 - (i + psid_len as u32));
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} ingress u32 match mark 0x64 0x000000fe \
                match ip dport 0x{s_bit:04x} 0x{s_bit:04x} action pedit pedit munge ip dport set 0x{c_bit:04x} retain 0x{c_bit:04x} continue"
            ));
        }
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress u32 match mark 0x64 0x000000fe \
            action pedit pedit munge ip dport set 0 retain 0x{psid_mask:04x} continue"
        ));
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress u32 match ip protocol 17 0xff \
            match u16 0 1fff at 6 match ip dport \"0x{psid_val:04x}\" 0x{psid_mask:04x} action skbedit mark 0x65/0xff continue"
        ));
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress u32 match ip protocol 6 0xff \
            match u16 0 1fff at 6 match ip dport \"0x{psid_val:04x}\" 0x{psid_mask:04x} action skbedit mark 0x64/0xff continue"
        ));

        // ── Ingress ICMP echo reply (type 0) ────────────────────────────────────
        // identifier: IP offset 24 (= nexthdr+4)  mark: 0x69

        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress handle 0x69/0xff fw action pedit \
            pedit munge offset 24 u16 set 0x8000 retain 0xf000 pipe action csum ip4h icmp continue"
        ));
        for i in 0..a {
            // 16 = psid_offset + psid_len + m
            let s_bit = 1u32 << (16 - 1 - i);
            let c_bit = 1u32 << (16 - 1 - (i + psid_len as u32));
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} ingress u32 match mark 0x69 0x000000ff \
                match u16 0x{s_bit:04x} 0x{s_bit:04x} at 24 action pedit pedit munge offset 24 u16 set 0x{c_bit:04x} retain 0x{c_bit:04x} continue"
            ));
        }
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress u32 match mark 0x69 0x000000ff \
            action pedit pedit munge offset 24 u16 set 0 retain 0x{psid_mask:04x} continue"
        ));
        cmds.push(format!(
            "tc filter add dev {tunnel_iface} ingress u32 match ip protocol 1 0xff \
            match ip icmp_type 0 0xff match ip ihl 0x5 0xf match u16 0 1fff at 6 match u16 \"0x{psid_val:04x}\" 0x{psid_mask:04x} at 24 action skbedit mark 0x69/0xff continue"
        ));

        // ── Ingress ICMP error messages ─────────────────────────────────────────
        // inner src port: IP offset 48 (= nexthdr+28)
        // marks: dest unreachable (type 3)=0x79, time exceeded (type 11)=0x89
        for (icmp_type, mark) in [(3u8, 0x79u32), (11u8, 0x89u32)] {
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} ingress handle 0x{mark:02x}/0xff fw \
                action pedit pedit munge offset 48 u16 set 0x8000 retain 0xf000 pipe \
                action csum ip4h and icmp continue"
            ));

            // pref 30: R ビット変換（inner src port S 空間 → C 空間）
            for i in 0..a {
                // 16 = psid_offset + psid_len + m
                let s_bit = 1u32 << (16 - 1 - i);
                let c_bit = 1u32 << (16 - 1 - (i + psid_len as u32));
                cmds.push(format!(
                    "tc filter add dev {tunnel_iface} ingress u32 match mark 0x{mark:02x} 0x000000ff \
                    match ip dport 0x{s_bit:04x} 0x{s_bit:04x} at 48 action pedit pedit munge offset 48 u16 set 0x{c_bit:04x} retain 0x{c_bit:04x} continue"
                ));
            }
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} ingress handle 0x{mark:02x}/0xff fw \
                action pedit pedit munge offset 48 u16 set 0 retain 0x{psid_mask:04x} continue"
            ));
            cmds.push(format!(
                "tc filter add dev {tunnel_iface} ingress u32 match ip protocol 1 0xff \
                match ip icmp_type {icmp_type} 0xff match ip ihl 0x5 0xf match ip ihl 0x5 0xf at 28 \
                match u16 0 1fff at 6 match ip sport \"0x{psid_val:04x}\" 0x{psid_mask:04x} at 48 action skbedit mark 0x79/0xff continue"
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
                psid: Some(psid),
            },
            port_ranges,
            port_start,
            port_end,
            is_fmr: false,
            fmr_ipv4_prefix: Ipv4Addr::UNSPECIFIED,
            fmr_prefix4_len: 0,
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
                psid: Some(5),
            },
            port_ranges: vec![],
            port_start: 1280,
            port_end: 1535,
            is_fmr: false,
            fmr_ipv4_prefix: Ipv4Addr::UNSPECIFIED,
            fmr_prefix4_len: 0,
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
        assert!(ruleset.contains("chain mapeced-clamp"));
        assert!(ruleset.contains("type nat hook postrouting priority srcnat"));

        // SNAT ルール: ce_ipv4 と port_start-port_end
        // port_start = 32784, port_end = 33023
        assert!(
            ruleset.contains("snat to 192.0.2.1:32784-33023"),
            "ruleset = {ruleset}"
        );

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
    //
    // v6プラス固定値: psid_offset=4, psid_len=8, M=4
    //   psid_val  = psid << 4
    //   psid_mask = 0x0ff0
    //   top_c_bit = 0x0080  (bit7, C 空間最上位 R ビット)
    //
    // ルール数の公式: 6a + 20  (a = psid_offset, qdisc 1 個含む)
    // a=4 → 44 ルール（qdisc 1 + egress TCP/UDP 7 + egress ICMP echo req 5
    //                 + ingress TCP/UDP 10 + ingress ICMP echo reply 7
    //                 + ingress ICMP type3 7 + ingress ICMP type11 7）
    //
    // インデックス早見表（psid=5, v6plus）:
    //   [0]  qdisc clsact
    //   --- egress TCP/UDP ---
    //   [1]  UDP csum fw 0x55/0xff
    //   [2]  TCP csum fw 0x54/0xff
    //   [3]  PSID 挿入 fw 0x54/0xfe
    //   [4]  R-bit i=0: ip sport 0x0010 → 0x1000
    //   [5]  R-bit i=1: ip sport 0x0020 → 0x2000
    //   [6]  R-bit i=2: ip sport 0x0040 → 0x4000
    //   [7]  R-bit top: ip sport 0x0000/0x0080 → bit15 クリア
    //   --- egress ICMP echo request (mark 0x59) ---
    //   [8]  PSID 挿入 + csum: match mark 0x59, offset 24
    //   [9]  R-bit i=0: u16 0x0010 → 0x1000 at 24
    //   [10] R-bit i=1: u16 0x0020 → 0x2000 at 24
    //   [11] R-bit i=2: u16 0x0040 → 0x4000 at 24
    //   [12] R-bit top: u16 0x0000/0x0080 → bit15 クリア at 24
    //   --- ingress TCP/UDP ---
    //   [13] UDP csum fw 0x65/0xff
    //   [14] TCP csum fw 0x64/0xff
    //   [15] bit15 セット fw 0x64/0xfe (ip dport set 0x8000 retain 0xf000)
    //   [16] R-bit i=0: ip dport 0x8000 → 0x0080
    //   [17] R-bit i=1: ip dport 0x4000 → 0x0040
    //   [18] R-bit i=2: ip dport 0x2000 → 0x0020
    //   [19] R-bit i=3: ip dport 0x1000 → 0x0010
    //   [20] PSID クリア: ip dport set 0 retain 0x0ff0
    //   [21] UDP マーク: protocol 17 + PSID match → skbedit 0x65
    //   [22] TCP マーク: protocol 6 + PSID match → skbedit 0x64
    //   --- ingress ICMP echo reply (mark 0x69) ---
    //   [23] bit15 セット + csum fw 0x69/0xff (offset 24)
    //   [24] R-bit i=0: u16 0x8000 → 0x0080 at 24
    //   [25] R-bit i=1: u16 0x4000 → 0x0040 at 24
    //   [26] R-bit i=2: u16 0x2000 → 0x0020 at 24
    //   [27] R-bit i=3: u16 0x1000 → 0x0010 at 24
    //   [28] PSID クリア: offset 24, set 0 retain 0x0ff0
    //   [29] echo reply マーク: icmp_type 0 + PSID match → skbedit 0x69
    //   --- ingress ICMP dest unreachable (type 3, mark 0x79) ---
    //   [30] bit15 セット + csum fw 0x79/0xff (inner src, offset 48)
    //   [31] R-bit i=0: ip dport 0x8000 → 0x0080 at 48
    //   [32] R-bit i=1: ip dport 0x4000 → 0x0040 at 48
    //   [33] R-bit i=2: ip dport 0x2000 → 0x0020 at 48
    //   [34] R-bit i=3: ip dport 0x1000 → 0x0010 at 48
    //   [35] PSID クリア fw 0x79/0xff (offset 48)
    //   [36] type 3 マーク: icmp_type 3 + PSID match → skbedit 0x79
    //   --- ingress ICMP time exceeded (type 11, mark 0x89) ---
    //   [37] bit15 セット + csum fw 0x89/0xff (inner src, offset 48)
    //   [38] R-bit i=0: ip dport 0x8000 → 0x0080 at 48
    //   [39] R-bit i=1: ip dport 0x4000 → 0x0040 at 48
    //   [40] R-bit i=2: ip dport 0x2000 → 0x0020 at 48
    //   [41] R-bit i=3: ip dport 0x1000 → 0x0010 at 48
    //   [42] PSID クリア fw 0x89/0xff (offset 48)
    //   [43] type 11 マーク: icmp_type 11 + PSID match → skbedit 0x79

    #[test]
    fn test_generate_tc_commands_psid_offset_zero_returns_empty() {
        let params = make_psid_offset_zero_params();
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_generate_tc_commands_v6plus_qdisc() {
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert!(cmds[0].contains("tc qdisc add dev ip6tnl0 clsact"));
    }

    #[test]
    fn test_generate_tc_commands_v6plus_rule_count() {
        // a=4 → 6*4+20 = 44
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert_eq!(cmds.len(), 44, "cmd count = {}", cmds.len());
    }

    #[test]
    fn test_generate_tc_commands_a_min_does_not_change_count() {
        // a_min は tc ルール数に影響しない（nftables 側で制御）
        let params = make_v6plus_params(5, 2);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert_eq!(cmds.len(), 44, "cmd count = {}", cmds.len());
    }

    // ── egress TCP/UDP ────────────────────────────────────────────────────────

    #[test]
    fn test_generate_tc_commands_egress_tcp_mark() {
        // [2]: egress TCP チェックサム更新 (fw handle 0x54/0xff)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[2];
        assert!(cmd.contains("egress"), "cmd = {cmd}");
        assert!(cmd.contains("handle 0x54/0xff fw"), "cmd = {cmd}");
        assert!(cmd.contains("csum ip4h tcp"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_egress_rbit_i0() {
        // [4]: egress R-bit i=0 — C 空間 bit4(0x0010) → S 空間 bit12(0x1000)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[4];
        assert!(cmd.contains("match mark 0x54 0x000000fe"), "cmd = {cmd}");
        assert!(cmd.contains("match ip sport 0x0010 0x0010"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge ip sport set 0x1000 retain 0x1000"),
            "cmd = {cmd}"
        );
    }

    #[test]
    fn test_generate_tc_commands_egress_rbit_top() {
        // [7]: egress 最上位 R ビット — bit7=0 のとき bit15 をクリア
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[7];
        assert!(cmd.contains("match mark 0x54 0x000000fe"), "cmd = {cmd}");
        assert!(cmd.contains("match ip sport 0x0000 0x0080"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge ip sport set 0x0000 retain 0x8000"),
            "cmd = {cmd}"
        );
    }

    #[test]
    fn test_generate_tc_commands_egress_psid_insert() {
        // [3]: egress PSID 挿入 (fw handle 0x54/0xfe, TCP + UDP 共通)
        // psid=5, M=4 → psid_val=0x0050, psid_mask=0x0ff0
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[3];
        assert!(cmd.contains("handle 0x54/0xfe fw"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge ip sport set \"0x0050\" retain 0x0ff0"),
            "cmd = {cmd}"
        );
    }

    #[test]
    fn test_generate_tc_commands_egress_psid_zero() {
        // psid=0 → psid_val=0x0000
        let params = make_v6plus_params(0, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        assert!(
            cmds[3].contains("pedit munge ip sport set \"0x0000\" retain 0x0ff0"),
            "cmd = {}",
            cmds[3]
        );
    }

    // ── ingress TCP/UDP ───────────────────────────────────────────────────────

    #[test]
    fn test_generate_tc_commands_ingress_tcp_mark() {
        // [22]: ingress TCP マーク付け (protocol 6, PSID match in dport)
        // psid=5, M=4 → psid_val=0x0050, psid_mask=0x0ff0
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[22];
        assert!(cmd.contains("ingress"), "cmd = {cmd}");
        assert!(cmd.contains("match ip protocol 6 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("match u16 0 1fff at 6"), "cmd = {cmd}");
        assert!(cmd.contains("\"0x0050\" 0x0ff0"), "cmd = {cmd}");
        assert!(cmd.contains("skbedit mark 0x64/0xff"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_ingress_clear_r_area() {
        // [15]: ingress bit15 セット (fw handle 0x64/0xfe, ip dport set 0x8000 retain 0xf000)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[15];
        assert!(cmd.contains("handle 0x64/0xfe fw"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge ip dport set 0x8000 retain 0xf000"),
            "cmd = {cmd}"
        );
    }

    #[test]
    fn test_generate_tc_commands_ingress_rbit_i0() {
        // [19]: ingress R-bit i=3 — S 空間 bit12(0x1000) → C 空間 bit4(0x0010)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[19];
        assert!(cmd.contains("match mark 0x64 0x000000fe"), "cmd = {cmd}");
        assert!(cmd.contains("match ip dport 0x1000 0x1000"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge ip dport set 0x0010 retain 0x0010"),
            "cmd = {cmd}"
        );
    }

    #[test]
    fn test_generate_tc_commands_ingress_set_bit15() {
        // [15]: ingress bit15 セット (fw handle 0x64/0xfe, retain 0xf000)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[15];
        assert!(cmd.contains("handle 0x64/0xfe fw"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge ip dport set 0x8000 retain 0xf000"),
            "cmd = {cmd}"
        );
    }

    // ── egress ICMP echo request ──────────────────────────────────────────────

    #[test]
    fn test_generate_tc_commands_icmp_echo_req_mark() {
        // [8]: egress ICMP echo request PSID 挿入 (match mark 0x59, offset 24)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[8];
        assert!(cmd.contains("egress"), "cmd = {cmd}");
        assert!(cmd.contains("match mark 0x59 0x000000ff"), "cmd = {cmd}");
        assert!(cmd.contains("pedit munge offset 24 u16 set"), "cmd = {cmd}");
        assert!(cmd.contains("csum ip4h icmp"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_icmp_echo_req_psid_insert() {
        // [8]: egress ICMP echo request PSID 挿入 + csum (offset 24)
        // psid=5, M=4 → psid_val=0x0050, psid_mask=0x0ff0
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[8];
        assert!(cmd.contains("match mark 0x59 0x000000ff"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge offset 24 u16 set \"0x0050\" retain 0x0ff0"),
            "cmd = {cmd}"
        );
        assert!(cmd.contains("csum ip4h icmp"), "cmd = {cmd}");
    }

    // ── ingress ICMP echo reply ───────────────────────────────────────────────

    #[test]
    fn test_generate_tc_commands_icmp_echo_reply_mark() {
        // [29]: ingress ICMP echo reply マーク付け (icmp_type 0, PSID match at offset 24)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[29];
        assert!(cmd.contains("ingress"), "cmd = {cmd}");
        assert!(cmd.contains("match ip protocol 1 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("match ip icmp_type 0 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("\"0x0050\" 0x0ff0 at 24"), "cmd = {cmd}");
        assert!(cmd.contains("skbedit mark 0x69/0xff"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_icmp_echo_reply_set_bit15() {
        // [23]: ingress ICMP echo reply bit15 セット + csum (fw handle 0x69/0xff, offset 24)
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[23];
        assert!(cmd.contains("handle 0x69/0xff fw"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge offset 24 u16 set 0x8000 retain 0xf000"),
            "cmd = {cmd}"
        );
        assert!(cmd.contains("csum ip4h icmp"), "cmd = {cmd}");
    }

    // ── ingress ICMP error messages ───────────────────────────────────────────

    #[test]
    fn test_generate_tc_commands_icmp_dest_unreach_mark() {
        // [36]: ingress ICMP dest unreachable (type 3) マーク付け
        // inner src port at offset 48, PSID match
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[36];
        assert!(cmd.contains("match ip icmp_type 3 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("\"0x0050\" 0x0ff0 at 48"), "cmd = {cmd}");
        assert!(cmd.contains("skbedit mark 0x79/0xff"), "cmd = {cmd}");
    }

    #[test]
    fn test_generate_tc_commands_icmp_dest_unreach_rbit_i0() {
        // [34]: ingress ICMP type 3 R-bit i=3 — S 空間 bit12 → C 空間 bit4, offset 48
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[34];
        assert!(cmd.contains("match mark 0x79 0x000000ff"), "cmd = {cmd}");
        assert!(cmd.contains("match ip dport 0x1000 0x1000 at 48"), "cmd = {cmd}");
        assert!(
            cmd.contains("pedit munge offset 48 u16 set 0x0010 retain 0x0010"),
            "cmd = {cmd}"
        );
    }

    #[test]
    fn test_generate_tc_commands_icmp_time_exceeded_mark() {
        // [43]: ingress ICMP time exceeded (type 11) マーク付け
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        let cmd = &cmds[43];
        assert!(cmd.contains("match ip icmp_type 11 0xff"), "cmd = {cmd}");
        assert!(cmd.contains("\"0x0050\" 0x0ff0 at 48"), "cmd = {cmd}");
    }

    // ── PSID 埋め込み確認 ────────────────────────────────────────────────────

    #[test]
    fn test_generate_tc_commands_includes_ce_ipv4() {
        let params = make_v6plus_params(5, 1);
        let cmds = TcManager::generate_tc_commands(&params, "ip6tnl0");
        // egress PSID 挿入ルールに psid_val (0x0050) が含まれること
        assert!(cmds[3].contains("\"0x0050\""), "cmd = {}", cmds[3]);
        // ingress TCP マーク付けルールに psid_val (0x0050) が含まれること
        assert!(cmds[22].contains("0x0050"), "cmd = {}", cmds[22]);
    }
}
