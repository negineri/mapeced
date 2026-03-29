use std::path::{Path, PathBuf};
use serde::Deserialize;

use crate::error::MapEError;
use crate::map::static_rules::CeCalcMethod;

fn default_p_exclude_max() -> u16 {
    1023
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub upstream_interface: String,
    pub tunnel_interface: String,
    #[serde(default)]
    pub tunnel_mtu: Option<u32>,
    #[serde(default)]
    pub map_rules_cache_file: Option<PathBuf>,
    /// `true` のとき `assets/static_rules.json` の埋め込みルールを使用する。
    /// `false`（デフォルト）のとき DHCPv6 キャプチャでルールを取得する。
    #[serde(default)]
    pub static_rule: bool,
    /// CE IPv6 アドレスの計算方式。デフォルトは `rfc7597`。
    /// v6プラス・OCN VC 等 Internet Draft 方式の ISP では `v6plus` を指定する。
    #[serde(default)]
    pub ce_calc: CeCalcMethod,
    #[serde(default = "default_p_exclude_max")]
    pub p_exclude_max: u16,
}

fn validate_interface_name(name: &str, field: &str) -> Result<(), MapEError> {
    if name.is_empty() {
        return Err(MapEError::InvalidConfig(format!(
            "{field} must not be empty"
        )));
    }
    if name.len() > 15 {
        return Err(MapEError::InvalidConfig(format!(
            "{field} must be 15 characters or fewer, got {}",
            name.len()
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(MapEError::InvalidConfig(format!(
            "{field} contains invalid characters (only alphanumeric, '-', '_', '.' are allowed)"
        )));
    }
    Ok(())
}

impl Config {
    pub fn validate(&self) -> Result<(), MapEError> {
        validate_interface_name(&self.upstream_interface, "upstream_interface")?;
        validate_interface_name(&self.tunnel_interface, "tunnel_interface")?;

        if self.upstream_interface == self.tunnel_interface {
            return Err(MapEError::InvalidConfig(
                "upstream_interface and tunnel_interface must be different".to_string(),
            ));
        }

        if let Some(mtu) = self.tunnel_mtu {
            if mtu < 1280 {
                return Err(MapEError::InvalidConfig(format!(
                    "tunnel_mtu must be at least 1280 (IPv6 minimum MTU), got {mtu}"
                )));
            }
            if mtu > 65535 {
                return Err(MapEError::InvalidConfig(format!(
                    "tunnel_mtu must be at most 65535, got {mtu}"
                )));
            }
        }

        Ok(())
    }
}

pub fn load_config(path: &Path) -> Result<Config, MapEError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            MapEError::ConfigNotFound {
                path: path.to_path_buf(),
            }
        } else {
            MapEError::InvalidConfig(e.to_string())
        }
    })?;
    let config: Config =
        toml::from_str(&content).map_err(|e| MapEError::InvalidConfig(e.to_string()))?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::static_rules::CeCalcMethod;

    fn parse(toml: &str) -> Result<Config, MapEError> {
        let config: Config =
            toml::from_str(toml).map_err(|e| MapEError::InvalidConfig(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    // --- 正常系 ---

    #[test]
    fn test_minimal_valid_config() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.upstream_interface, "eth0");
        assert_eq!(cfg.tunnel_interface, "ip6tnl0");
        assert_eq!(cfg.tunnel_mtu, None);
        assert_eq!(cfg.map_rules_cache_file, None);
        assert!(!cfg.static_rule);
        assert_eq!(cfg.ce_calc, CeCalcMethod::Rfc7597);
        assert_eq!(cfg.p_exclude_max, 1023);
    }

    #[test]
    fn test_static_rule_true() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            static_rule = true
            ce_calc = "draft"
            "#,
        )
        .unwrap();
        assert!(cfg.static_rule);
        assert_eq!(cfg.ce_calc, CeCalcMethod::Draft);
    }

    #[test]
    fn test_static_rule_default_false() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            "#,
        )
        .unwrap();
        assert!(!cfg.static_rule);
    }

    #[test]
    fn test_ce_calc_default_rfc7597() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.ce_calc, CeCalcMethod::Rfc7597);
    }

    #[test]
    fn test_ce_calc_draft() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            ce_calc = "draft"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.ce_calc, CeCalcMethod::Draft);
    }

    #[test]
    fn test_ce_calc_invalid() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            ce_calc = "unknown"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_default_p_exclude_max_is_1023() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.p_exclude_max, 1023);
    }

    #[test]
    fn test_explicit_p_exclude_max() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            p_exclude_max = 2047
            "#,
        )
        .unwrap();
        assert_eq!(cfg.p_exclude_max, 2047);
    }

    #[test]
    fn test_tunnel_mtu_valid() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 1500
            "#,
        )
        .unwrap();
        assert_eq!(cfg.tunnel_mtu, Some(1500));
    }

    #[test]
    fn test_tunnel_mtu_minimum_valid() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 1280
            "#,
        )
        .unwrap();
        assert_eq!(cfg.tunnel_mtu, Some(1280));
    }

    #[test]
    fn test_tunnel_mtu_maximum_valid() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 65535
            "#,
        )
        .unwrap();
        assert_eq!(cfg.tunnel_mtu, Some(65535));
    }

    #[test]
    fn test_map_rules_cache_file() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            map_rules_cache_file = "/var/cache/mapeced/rules.json"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.map_rules_cache_file,
            Some(PathBuf::from("/var/cache/mapeced/rules.json"))
        );
    }

    #[test]
    fn test_interface_name_with_dots_and_dashes() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0.100"
            tunnel_interface = "ip6tnl-1"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.upstream_interface, "eth0.100");
        assert_eq!(cfg.tunnel_interface, "ip6tnl-1");
    }

    #[test]
    fn test_interface_name_max_length_15() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0123456789ab"
            tunnel_interface = "ip6tnl0"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.upstream_interface.len(), 15);
    }

    // --- 異常系: 必須フィールド欠落 ---

    #[test]
    fn test_missing_upstream_interface() {
        let result = parse(
            r#"
            tunnel_interface = "ip6tnl0"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_tunnel_interface() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            "#,
        );
        assert!(result.is_err());
    }

    // --- 異常系: インターフェース名バリデーション ---

    #[test]
    fn test_empty_upstream_interface() {
        let result = parse(
            r#"
            upstream_interface = ""
            tunnel_interface = "ip6tnl0"
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_empty_tunnel_interface() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = ""
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_upstream_interface_too_long() {
        let result = parse(
            r#"
            upstream_interface = "eth01234567890ab"
            tunnel_interface = "ip6tnl0"
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_interface_invalid_char_space() {
        let result = parse(
            r#"
            upstream_interface = "eth 0"
            tunnel_interface = "ip6tnl0"
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_interface_invalid_char_semicolon() {
        let result = parse(
            r#"
            upstream_interface = "eth0;rm"
            tunnel_interface = "ip6tnl0"
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_same_upstream_and_tunnel_interface() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "eth0"
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    // --- 異常系: tunnel_mtu バリデーション ---

    #[test]
    fn test_tunnel_mtu_too_small() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 1279
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    #[test]
    fn test_tunnel_mtu_zero() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            tunnel_mtu = 0
            "#,
        );
        assert!(matches!(result, Err(MapEError::InvalidConfig(_))));
    }

    // --- load_config: ファイル不在 ---

    #[test]
    fn test_load_config_not_found() {
        let result = load_config(Path::new("/nonexistent/path/config.toml"));
        assert!(matches!(result, Err(MapEError::ConfigNotFound { .. })));
    }
}
