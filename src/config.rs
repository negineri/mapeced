use std::path::{Path, PathBuf};
use serde::Deserialize;

use crate::error::MapEError;
use crate::map::static_rules::MapProfile;

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
    /// 静的 MAP ルールのプロファイル。必須フィールド。
    /// DHCPv6 キャプチャモードで動作する場合は `"dhcpv6"` を指定する。
    pub map_profile: MapProfile,
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
    use crate::map::static_rules::MapProfile;

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
            map_profile = "v6plus"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.upstream_interface, "eth0");
        assert_eq!(cfg.tunnel_interface, "ip6tnl0");
        assert_eq!(cfg.tunnel_mtu, None);
        assert_eq!(cfg.map_rules_cache_file, None);
        assert_eq!(cfg.map_profile, MapProfile::V6plus);
        assert_eq!(cfg.p_exclude_max, 1023);
    }

    #[test]
    fn test_missing_map_profile() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_map_profile_v6plus() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            map_profile = "v6plus"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.map_profile, MapProfile::V6plus);
    }

    #[test]
    fn test_map_profile_ocn_vc() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            map_profile = "ocn_vc"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.map_profile, MapProfile::OcnVc);
    }

    #[test]
    fn test_map_profile_dhcpv6() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            map_profile = "dhcpv6"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.map_profile, MapProfile::Dhcpv6);
    }

    #[test]
    fn test_default_p_exclude_max_is_1023() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "dhcpv6"
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
    fn test_map_profile_invalid() {
        let result = parse(
            r#"
            upstream_interface = "eth0"
            tunnel_interface = "ip6tnl0"
            map_profile = "unknown_isp"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_interface_name_with_dots_and_dashes() {
        let cfg = parse(
            r#"
            upstream_interface = "eth0.100"
            tunnel_interface = "ip6tnl-1"
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
            map_profile = "v6plus"
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
