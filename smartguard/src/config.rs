use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;

/// Top-level smartguard configuration file.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub interface: Interface,
    #[serde(default, rename = "peer")]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Deserialize)]
pub struct Interface {
    pub private_key: PrivateKeyConfig,
    pub listen_port: Option<u16>,
    /// Tunnel-local address(es) in CIDR form. Accepts either a single string
    /// (`address = "10.0.0.1/24"`, kept for backward compatibility) or an
    /// array (`address = ["10.0.0.1/24", "fd00::1/64"]`) for dual-stack.
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub address: Vec<String>,
    #[serde(alias = "MTU")]
    pub mtu: Option<i32>,
    /// DNS servers to install as the system resolver while the tunnel is up
    /// (mirrors wg-quick's `DNS = ...`). Empty / unset = no change.
    #[serde(default, alias = "DNS")]
    pub dns: Vec<IpAddr>,
    #[serde(default)]
    pub smartcard: SmartcardSettings,
}

/// How the private key is sourced.
#[derive(Debug, Clone, PartialEq)]
pub enum PrivateKeyConfig {
    /// Raw 32-byte software key (base64-encoded in the config file).
    Software([u8; 32]),
    /// Use a specific smartcard by identity string (e.g. "0006:15422467").
    Smartcard(String),
    /// Auto-detect the first connected card with an X25519 decryption key.
    SmartcardAuto,
}

impl<'de> Deserialize<'de> for PrivateKeyConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PrivateKeyVisitor;

        impl<'de> Visitor<'de> for PrivateKeyVisitor {
            type Value = PrivateKeyConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(
                    "a base64 WireGuard private key string, \
                     or a table with a 'smartcard' field",
                )
            }

            // Plain string → base64 software key
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let bytes = BASE64
                    .decode(v)
                    .map_err(|e| de::Error::custom(format!("invalid base64: {e}")))?;
                let key: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| de::Error::custom("private key must be exactly 32 bytes"))?;
                Ok(PrivateKeyConfig::Software(key))
            }

            // Table → { smartcard = "..." }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut smartcard: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "smartcard" => {
                            smartcard = Some(map.next_value()?);
                        }
                        other => {
                            return Err(de::Error::unknown_field(other, &["smartcard"]));
                        }
                    }
                }
                let ident = smartcard.ok_or_else(|| de::Error::missing_field("smartcard"))?;
                if ident == "auto" {
                    Ok(PrivateKeyConfig::SmartcardAuto)
                } else {
                    Ok(PrivateKeyConfig::Smartcard(ident))
                }
            }
        }

        deserializer.deserialize_any(PrivateKeyVisitor)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmartcardSettings {
    /// How to obtain the PIN: "prompt", "env:VARNAME", or "keyring".
    #[serde(default = "default_pin_entry")]
    pub pin_entry: String,
}

fn default_pin_entry() -> String {
    "prompt".to_string()
}

impl Default for SmartcardSettings {
    fn default() -> Self {
        Self {
            pin_entry: default_pin_entry(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Peer {
    /// Peer's public key (base64-encoded, 32 bytes).
    #[serde(deserialize_with = "deserialize_key_base64")]
    pub public_key: [u8; 32],
    /// Optional pre-shared key (base64-encoded, 32 bytes).
    #[serde(default, deserialize_with = "deserialize_option_key_base64")]
    pub preshared_key: Option<[u8; 32]>,
    /// Peer's internet endpoint.
    pub endpoint: Option<SocketAddr>,
    /// Allowed IP ranges for this peer.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Send keepalive every N seconds (0 = disabled).
    pub persistent_keepalive: Option<u16>,
}

/// Accept either a single string or an array of strings — same shape
/// wg-quick parses for `Address = a, b` and what we want for both legacy
/// configs (single address) and dual-stack configs (array).
fn deserialize_string_or_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(vec![v])
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }
    d.deserialize_any(V)
}

fn deserialize_key_base64<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let s = String::deserialize(d)?;
    let bytes = BASE64
        .decode(&s)
        .map_err(|e| de::Error::custom(format!("invalid base64: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| de::Error::custom("key must be exactly 32 bytes"))
}

fn deserialize_option_key_base64<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<[u8; 32]>, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    match s {
        None => Ok(None),
        Some(s) => {
            let bytes = BASE64
                .decode(&s)
                .map_err(|e| de::Error::custom(format!("invalid base64: {e}")))?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| de::Error::custom("key must be exactly 32 bytes"))?;
            Ok(Some(key))
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(s)?;
        Ok(config)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "config I/O error: {e}"),
            ConfigError::Parse(e) => write!(f, "config parse error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::Parse(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_software_key() {
        let toml = r#"
[interface]
private_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
listen_port = 51820
address = "10.0.0.1/24"

[[peer]]
public_key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
endpoint = "203.0.113.2:51820"
allowed_ips = ["10.0.0.2/32"]
persistent_keepalive = 25
"#;
        let config = Config::from_str(toml).unwrap();
        match &config.interface.private_key {
            PrivateKeyConfig::Software(key) => {
                assert_eq!(key.len(), 32);
                // Verify round-trip
                assert_eq!(
                    BASE64.encode(key),
                    "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
                );
            }
            other => panic!("expected Software, got {other:?}"),
        }
        assert_eq!(config.interface.listen_port, Some(51820));
        assert_eq!(config.peers.len(), 1);
        assert_eq!(
            config.peers[0].endpoint.unwrap(),
            "203.0.113.2:51820".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.peers[0].persistent_keepalive, Some(25));
    }

    #[test]
    fn parse_smartcard_explicit() {
        let toml = r#"
[interface]
private_key = { smartcard = "0006:15422467" }
listen_port = 51820

[interface.smartcard]
pin_entry = "env:WG_PIN"
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(
            config.interface.private_key,
            PrivateKeyConfig::Smartcard("0006:15422467".to_string())
        );
        assert_eq!(config.interface.smartcard.pin_entry, "env:WG_PIN");
    }

    #[test]
    fn parse_smartcard_auto() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(
            config.interface.private_key,
            PrivateKeyConfig::SmartcardAuto
        );
    }

    #[test]
    fn parse_no_peers() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }
"#;
        let config = Config::from_str(toml).unwrap();
        assert!(config.peers.is_empty());
    }

    #[test]
    fn parse_multiple_peers() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }

[[peer]]
public_key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
allowed_ips = ["10.0.0.2/32"]

[[peer]]
public_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
endpoint = "192.168.1.1:51820"
allowed_ips = ["10.0.0.3/32", "192.168.1.0/24"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.peers.len(), 2);
        assert!(config.peers[0].endpoint.is_none());
        assert!(config.peers[1].endpoint.is_some());
        assert_eq!(config.peers[1].allowed_ips.len(), 2);
    }

    #[test]
    fn parse_default_smartcard_settings() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.interface.smartcard.pin_entry, "prompt");
    }

    #[test]
    fn parse_peer_with_preshared_key() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }

[[peer]]
public_key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
preshared_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
allowed_ips = ["10.0.0.2/32"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert!(config.peers[0].preshared_key.is_some());
    }

    #[test]
    fn parse_address_single_string_legacy() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }
address = "10.0.0.1/24"
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.interface.address, vec!["10.0.0.1/24"]);
    }

    #[test]
    fn parse_address_dual_stack() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }
address = ["10.0.0.1/24", "fd00::1/64"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(
            config.interface.address,
            vec!["10.0.0.1/24", "fd00::1/64"]
        );
    }

    #[test]
    fn parse_dns_servers() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }
dns = ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.interface.dns.len(), 3);
        assert_eq!(config.interface.dns[0].to_string(), "1.1.1.1");
        assert_eq!(config.interface.dns[2].to_string(), "2606:4700:4700::1111");
    }

    #[test]
    fn parse_dns_default_empty() {
        let toml = r#"
[interface]
private_key = { smartcard = "auto" }
"#;
        let config = Config::from_str(toml).unwrap();
        assert!(config.interface.dns.is_empty());
    }

    #[test]
    fn reject_invalid_base64_key() {
        let toml = r#"
[interface]
private_key = "not-valid-base64!!!"
"#;
        assert!(Config::from_str(toml).is_err());
    }

    #[test]
    fn reject_wrong_length_key() {
        let toml = r#"
[interface]
private_key = "dG9vc2hvcnQ="
"#;
        assert!(Config::from_str(toml).is_err());
    }

    #[test]
    fn reject_unknown_private_key_field() {
        let toml = r#"
[interface]
private_key = { file = "/path/to/key" }
"#;
        assert!(Config::from_str(toml).is_err());
    }
}
