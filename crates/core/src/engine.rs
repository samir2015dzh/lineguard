//! Pinned upstream supply chain and secret-borrowing config generation.
//! There is intentionally no network-activation function in this milestone.
use crate::{Error, Profile};
use serde::{Deserialize, Serialize, ser::SerializeMap};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    net::IpAddr,
};
use zeroize::Zeroize;

pub const MANIFEST_JSON: &str = include_str!("../../../third-party/manifest.json");
pub const IMPORT_INTENT: &str = "ACCEPT-MIHOMO-GPL3-AND-EMBEDDED-WINTUN";
pub const CHECK_INTENT: &str = "CHECK-CONFIG-NO-TUNNEL";
pub const MAX_GENERATED: usize = 16 * 1024;
pub const ACTIVATION_BLOCKER: &str = "隧道数据通路尚不支持：M3精确跨层WFP策略、独占TUN/路由/DNS快照及独立救援未闭合。只允许固定核心的隔离配置检查，不撤M2阻断，不启用TUN或联网。";

#[derive(Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub core: CorePin,
}
#[derive(Deserialize)]
pub struct CorePin {
    pub version: String,
    pub executable_name: String,
    pub executable_size: u64,
    pub executable_sha256: String,
}
pub fn manifest() -> Result<Manifest, Error> {
    let m: Manifest =
        serde_json::from_str(MANIFEST_JSON).map_err(|_| Error::Invalid("编译内置核心清单无效"))?;
    if m.schema != 1
        || m.core.executable_name != "mihomo.exe"
        || m.core.executable_size > 96 * 1024 * 1024
        || m.core.executable_sha256.len() != 64
        || !m
            .core
            .executable_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::Invalid("编译内置核心清单无效"));
    }
    Ok(m)
}
/// Streaming bound is enforced even if the file changes or lies about its size.
pub fn verify_reader(mut reader: impl Read, pin: &CorePin) -> io::Result<()> {
    let mut hash = Sha256::new();
    let mut buf = [0u8; 32 * 1024];
    let mut size = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size = size
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("核心大小溢出"))?;
        if size > pin.executable_size {
            return Err(io::Error::other("核心大小不符"));
        }
        hash.update(&buf[..n]);
    }
    let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if size != pin.executable_size || digest != pin.executable_sha256 {
        return Err(io::Error::other("核心SHA256或大小不符；未执行"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    NotChecked,
    Missing,
    Verified,
    Rejected,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub version: String,
    pub integrity: Integrity,
    pub license_confirmed: bool,
    pub tunnel_supported: bool,
    pub driver_signature_verified: bool,
    pub detail: String,
    pub checked_at_unix_ms: Option<u64>,
}
impl Default for Info {
    fn default() -> Self {
        Self {
            version: manifest()
                .map(|m| m.core.version)
                .unwrap_or_else(|_| "manifest-invalid".into()),
            integrity: Integrity::NotChecked,
            checked_at_unix_ms: None,
            license_confirmed: false,
            tunnel_supported: false,
            driver_signature_verified: false,
            detail: "尚未校验本机核心；不捆绑、不下载、不自动执行核心。".into(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReport {
    pub syntax_accepted: bool,
    pub guard_after: crate::guard::Evidence,
    pub tunnel_started: bool,
    pub detail: String,
}

pub struct Generated(Vec<u8>);
impl Generated {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for Generated {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl std::fmt::Debug for Generated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[受控配置已隐藏]")
    }
}

/// Only our whitelisted template and a borrowed SS secret are serialized.
/// No arbitrary YAML, filesystem path, provider, plugin, script or controller input.
pub fn config_for_check(profile: &Profile) -> Result<Generated, Error> {
    config(profile, None)
}
/// Internal lifecycle must supply an OS-observed physical alias and a fresh owned nonce.
/// Auto-routing is intentionally OFF: route ownership belongs to our write-ahead journal.
pub fn config_for_tunnel(
    profile: &Profile,
    alias: &str,
    physical: &str,
) -> Result<Generated, Error> {
    if !alias.starts_with("LG-")
        || alias.len() != 35
        || !alias[3..].bytes().all(|b| b.is_ascii_hexdigit())
        || physical.is_empty()
        || physical.len() > 256
        || physical.chars().any(char::is_control)
    {
        return Err(Error::Invalid("接口身份无效"));
    }
    config(profile, Some((alias, physical)))
}
fn config(profile: &Profile, tun: Option<(&str, &str)>) -> Result<Generated, Error> {
    let IpAddr::V4(ip) = profile.server else {
        return Err(Error::Invalid("M3只接受单一IPv4端点"));
    };
    let octets = ip.octets();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_link_local()
        || octets[0] >= 240
        || (octets[0] == 198 && octets[1] & 0xfe == 18)
        || profile.port == 0
        || profile.password.is_empty()
        || profile.password.len() > 1024
    {
        return Err(Error::Invalid("M3端点/密码无效或与fake-IP地址冲突"));
    }
    let method = profile.method.as_str();
    #[derive(Serialize)]
    struct Node<'a> {
        name: &'static str,
        #[serde(rename = "type")]
        kind: &'static str,
        server: std::net::Ipv4Addr,
        port: u16,
        cipher: &'static str,
        password: &'a crate::Secret,
        udp: bool,
    }
    struct Document<'a> {
        options: serde_json::Value,
        node: Node<'a>,
    }
    impl Serialize for Document<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let options = self
                .options
                .as_object()
                .ok_or_else(|| serde::ser::Error::custom("template"))?;
            let mut m = serializer.serialize_map(Some(options.len() + 1))?;
            for (k, v) in options {
                m.serialize_entry(k, v)?;
            }
            m.serialize_entry("proxies", &[&self.node])?;
            m.end()
        }
    }
    let mut options: serde_json::Value = serde_json::from_str(include_str!("engine-config.json"))
        .map_err(|_| Error::Invalid("编译内置核心模板无效"))?;
    if let Some((alias, physical)) = tun {
        options["interface-name"] = serde_json::json!(physical);
        options["tun"]["enable"] = true.into();
        options["tun"]["device"] = alias.into();
        options["tun"]["dns-mode"] = "native".into();
    }
    let document = Document {
        options,
        node: Node {
            name: "LG-ONLY",
            kind: "ss",
            server: ip,
            port: profile.port,
            cipher: method,
            password: &profile.password,
            udp: true,
        },
    };
    // Upper bound: password <=1024 UTF8 bytes, worst-case JSON escaping <=6144.
    // Reserve the whole bounded output to avoid reallocating a secret-bearing buffer.
    let mut output = Generated(Vec::with_capacity(MAX_GENERATED));
    serde_json::to_writer(&mut output.0, &document).map_err(|_| Error::Format)?;
    if output.0.len() > MAX_GENERATED {
        return Err(Error::TooLarge);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cipher;
    fn profile() -> Profile {
        Profile {
            name: "离线示例".into(),
            server: "203.0.113.1".parse().unwrap(),
            port: 443,
            method: Cipher::Aes128Gcm,
            password: crate::Secret("\"x\\\n; DIRECT".into()),
        }
    }
    #[test]
    fn secret_escaping_cannot_inject_config() {
        let p = profile();
        let bytes = config_for_check(&p).unwrap();
        let v: serde_json::Value = serde_json::from_slice(bytes.bytes()).unwrap();
        assert_eq!(v["proxies"].as_array().unwrap().len(), 1);
        assert_eq!(v["proxies"][0]["password"].as_str().unwrap(), p.password.0);
        assert_eq!(v["rules"], serde_json::json!(["MATCH,LG-ONLY"]));
        assert!(!v["tun"]["enable"].as_bool().unwrap());
        assert!(!v["tun"]["auto-route"].as_bool().unwrap());
        assert_eq!(v["external-controller"], "");
        assert_eq!(v["mixed-port"], 0);
        assert!(format!("{bytes:?}").find("DIRECT").is_none());
    }
    #[test]
    fn ipv6_broadcast_and_fake_ip_rejected() {
        for address in [
            "2001:db8::1",
            "255.255.255.255",
            "198.18.0.1",
            "198.19.20.3",
            "169.254.1.1",
        ] {
            let mut p = profile();
            p.server = address.parse().unwrap();
            assert!(config_for_check(&p).is_err());
        }
    }
    #[test]
    fn pin_rejects_modified_truncated_or_oversized_content() {
        let pin = CorePin {
            version: "test".into(),
            executable_name: "test".into(),
            executable_size: 3,
            executable_sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                .into(),
        };
        assert!(verify_reader(&b"abc"[..], &pin).is_ok());
        for input in [b"ab".as_slice(), b"abd", b"abcd"] {
            assert!(verify_reader(input, &pin).is_err());
        }
    }
    #[test]
    fn compiled_manifest_has_real_pin_not_signature_claim() {
        let m = manifest().unwrap();
        assert_eq!(m.core.version, "1.19.34");
        assert_eq!(m.core.executable_size, 61_192_704);
        let data: serde_json::Value = serde_json::from_str(MANIFEST_JSON).unwrap();
        assert_eq!(data["core"]["signature_verified"], false);
        assert_eq!(data["driver"]["authenticode_verified"], false);
        assert_eq!(data["bundled"], false);
    }
    #[test]
    fn output_is_bounded_even_for_maximally_escaped_password() {
        let mut p = profile();
        p.password = crate::Secret("\u{0001}".repeat(1024));
        assert!(config_for_check(&p).unwrap().bytes().len() <= MAX_GENERATED);
    }
}

#[cfg(test)]
mod authority_regressions {
    use crate::*;
    #[test]
    fn supplied_admin_field_is_not_authority() {
        let input=br#"{"version":3,"id":1,"command":{"type":"core_check","expected_generation":0,"index":0,"confirmation":"CHECK-CONFIG-NO-TUNNEL","elevated_admin":true}}"#;
        assert!(request(input).is_err());
    }
    #[test]
    fn wrong_version_cannot_reach_core_backend_or_save() {
        let mut c = Controller::new(Config::default(), 0, false, false, Mode::Service);
        let result = c.handle(
            Request {
                version: 2,
                id: 1,
                command: Command::CoreCheck {
                    expected_generation: 0,
                    index: 0,
                    confirmation: super::CHECK_INTENT.into(),
                },
            },
            |_, _| panic!("must not save"),
        );
        assert!(matches!(
            result.result,
            Reply::Failure {
                code: FaultCode::Protocol,
                ..
            }
        ));
        assert_eq!(c.snapshot().phase, Phase::Unknown);
    }
    #[test]
    fn verified_core_is_not_a_protected_or_blocked_state() {
        let mut c = Controller::new(Config::default(), 0, false, false, Mode::Service);
        let mut info = super::Info::default();
        info.integrity = super::Integrity::Verified;
        c.observe_core(info);
        assert_eq!(c.snapshot().phase, Phase::Unknown);
        assert!(c.profile(0, 0).is_err());
        assert!(c.profile(1, 0).is_err());
    }
}
