//! Write-ahead ownership model for an exclusive, disposable Windows TUN.
//! Physical adapters are observed, never mutated. No data-plane permits here.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr};

pub const MAX_JOURNAL: usize = 512 * 1024;
pub const START_INTENT: &str = "START-EXCLUSIVE-TUN-BLOCKED";
pub const RECOVER_INTENT: &str = "RESTORE-OWN-NETWORK";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix: u8,
    pub luid: u64,
    pub next_hop: IpAddr,
    pub metric: u32,
    pub protocol: i32,
    pub site_prefix: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub loopback: bool,
    pub autoconfigure: bool,
    pub publish: bool,
    pub immortal: bool,
}
impl Route {
    pub fn same_key(&self, other: &Self) -> bool {
        self.destination == other.destination
            && self.prefix == other.prefix
            && self.luid == other.luid
            && self.next_hop == other.next_hop
    }
    pub fn default_half(luid: u64, second: bool) -> Self {
        Self {
            destination: IpAddr::V4(if second {
                Ipv4Addr::new(128, 0, 0, 0)
            } else {
                Ipv4Addr::UNSPECIFIED
            }),
            prefix: 1,
            luid,
            next_hop: "198.18.0.2".parse().expect("literal"),
            metric: 7,
            protocol: 3,
            site_prefix: 0,
            valid_lifetime: u32::MAX,
            preferred_lifetime: u32::MAX,
            loopback: false,
            autoconfigure: false,
            publish: false,
            immortal: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub guid: String,
    pub luid: u64,
    pub alias: String,
    pub dns: Vec<IpAddr>,
    pub unicast: Vec<(IpAddr, u8)>,
    pub ipv6_enabled: bool,
    pub up: bool,
    pub mtu: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnedPost {
    pub interface: Interface,
    pub routes: Vec<Route>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prepared,
    CoreStarting,
    TunObserved,
    RoutesApplying,
    Quarantined,
    Restoring,
    Conflict,
    Restored,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub schema: u32,
    pub nonce: String,
    pub generation: u64,
    pub profile_index: usize,
    pub alias: String,
    pub guid: String,
    pub job: String,
    pub stage: Stage,
    pub physical_before: Vec<Interface>,
    pub physical_routes_before: Vec<Route>,
    pub owned_luid: Option<u64>,
    pub instance_id: Option<String>,
    pub expected_after: Option<OwnedPost>,
    /// Each entry was absent before and persisted before its Create call.
    pub added_routes: Vec<Route>,
    pub restored_routes: usize,
    pub last_error: Option<String>,
}
impl Lease {
    pub fn new(
        nonce: String,
        guid: String,
        generation: u64,
        profile_index: usize,
        physical: Vec<Interface>,
        routes: Vec<Route>,
    ) -> Self {
        Self {
            alias: format!("LG-{nonce}"),
            job: format!(r"Global\LineGuard.Tun.{nonce}"),
            schema: 1,
            nonce,
            guid,
            generation,
            profile_index,
            stage: Stage::Prepared,
            physical_before: physical,
            physical_routes_before: routes,
            owned_luid: None,
            instance_id: None,
            expected_after: None,
            added_routes: Vec::new(),
            restored_routes: 0,
            last_error: None,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let id = |s: &str| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.schema != 1
            || !id(&self.nonce)
            || !id(&self.guid)
            || self.guid == "00000000000000000000000000000000"
            || self.alias != format!("LG-{}", self.nonce)
            || self.job != format!(r"Global\LineGuard.Tun.{}", self.nonce)
            || self.profile_index >= crate::MAX_PROFILES
            || self.physical_before.len() > 128
            || self.physical_routes_before.len() > 512
            || self.added_routes.len() > 2
            || self.restored_routes > self.added_routes.len()
            || (self.stage == Stage::Restored && self.restored_routes != self.added_routes.len())
            || self.physical_before.iter().any(|i| {
                i.guid == self.guid || i.alias == self.alias || Some(i.luid) == self.owned_luid
            })
            || self.owned_luid == Some(0)
            || (matches!(
                self.stage,
                Stage::TunObserved | Stage::RoutesApplying | Stage::Quarantined
            ) && (self.owned_luid.is_none()
                || self.expected_after.is_none()
                || self.instance_id.is_none()))
            || (self.stage == Stage::Quarantined
                && (self.added_routes.len() != 2 || self.restored_routes != 0))
            || self
                .instance_id
                .as_ref()
                .is_some_and(|s| s.len() > 512 || s.chars().any(char::is_control))
            || self.last_error.as_ref().is_some_and(|s| s.len() > 512)
        {
            return Err("网络journal身份/边界无效");
        }
        for i in self
            .physical_before
            .iter()
            .chain(self.expected_after.iter().map(|p| &p.interface))
        {
            if !id(&i.guid) || i.alias.len() > 1024 || i.dns.len() > 32 || i.unicast.len() > 64 {
                return Err("网卡快照越界");
            }
        }
        if let Some(post) = &self.expected_after {
            if post.interface.guid != self.guid
                || post.interface.alias != self.alias
                || Some(post.interface.luid) != self.owned_luid
                || post.routes.len() > 128
                || post.routes.iter().any(|r| r.luid != post.interface.luid)
            {
                return Err("后态身份不匹配");
            }
        }
        for (index, r) in self.added_routes.iter().enumerate() {
            if self.owned_luid != Some(r.luid) || *r != Route::default_half(r.luid, index == 1) {
                return Err("journal含非产品路由");
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let payload = serde_json::to_vec(self).map_err(|_| "journal编码失败")?;
        let digest = hex(&Sha256::digest(&payload));
        let encoded = serde_json::to_vec(&Envelope {
            schema: 1,
            sha256: digest,
            document: self.clone(),
        })
        .map_err(|_| "journal编码失败")?;
        if encoded.len() > MAX_JOURNAL {
            return Err("journal过大");
        }
        Ok(encoded)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_JOURNAL {
            return Err("journal过大");
        }
        let e: Envelope = serde_json::from_slice(bytes).map_err(|_| "journal格式无效")?;
        if e.schema != 1 {
            return Err("journal版本不支持");
        }
        let data = serde_json::to_vec(&e.document).map_err(|_| "journal格式无效")?;
        if hex(&Sha256::digest(&data)) != e.sha256 {
            return Err("journal校验和不符");
        }
        e.document.validate()?;
        Ok(e.document)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: u32,
    sha256: String,
    document: Lease,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Debug, PartialEq, Eq)]
pub enum Undo {
    AlreadyAbsent,
    DeleteExact,
    Conflict,
}
pub fn undo_with_progress(
    expected: &Route,
    current: Option<&Route>,
    already_restored: bool,
) -> Undo {
    if already_restored && current.is_some() {
        Undo::Conflict
    } else {
        undo_route(expected, current)
    }
}
pub fn undo_route(expected: &Route, current: Option<&Route>) -> Undo {
    match current {
        None => Undo::AlreadyAbsent,
        Some(r) if r == expected => Undo::DeleteExact,
        _ => Undo::Conflict,
    }
}
/// Before the first observed post-state, accept only the pinned core's narrow initialization footprint.
/// This is not authorization to modify a physical interface or an existing adapter.
pub fn partial_footprint(lease: &Lease, interface: &Interface, routes: &[Route]) -> bool {
    if interface.guid != lease.guid
        || interface.alias != lease.alias
        || !matches!(interface.mtu, 1500 | 65535)
    {
        return false;
    }
    if !interface
        .dns
        .iter()
        .all(|a| a == &"198.18.0.2".parse::<IpAddr>().expect("literal"))
    {
        return false;
    }
    if !interface.unicast.iter().all(|(a, p)| match a {
        IpAddr::V4(v) => *v == Ipv4Addr::new(198, 18, 0, 1) && *p == 30,
        IpAddr::V6(v) => v.is_unicast_link_local(),
    }) {
        return false;
    }
    routes.iter().all(|r| {
        if r.luid != interface.luid {
            return false;
        }
        if lease.added_routes.contains(r) {
            return true;
        }
        if r.protocol != 2 || !r.next_hop.is_unspecified() {
            return false;
        }
        match r.destination {
            IpAddr::V4(a) => [
                (Ipv4Addr::new(198, 18, 0, 0), 30),
                (Ipv4Addr::new(198, 18, 0, 1), 32),
                (Ipv4Addr::new(198, 18, 0, 3), 32),
                (Ipv4Addr::new(224, 0, 0, 0), 4),
                (Ipv4Addr::BROADCAST, 32),
            ]
            .contains(&(a, r.prefix)),
            IpAddr::V6(a) => {
                (a.is_unicast_link_local() && matches!(r.prefix, 64 | 128))
                    || (a.is_multicast() && r.prefix == 8)
            }
        }
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub phase: RunPhase,
    pub detail: String,
    pub generation: Option<u64>,
    pub retry_count: u8,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    Stopped,
    Starting,
    Quarantined,
    /// Exact v3 narrow permits read back on top of the full M2 baseline. Policy only: no
    /// enforcement, leak or tunnel-health proof, and never "protected".
    NarrowOpen,
    RecoveryRequired,
    Failed,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            phase: RunPhase::Stopped,
            detail: "TUN未运行；数据通路尚不可用".into(),
            generation: None,
            retry_count: 0,
        }
    }
}
#[derive(Default)]
pub struct Retry {
    attempts: u8,
}
impl Retry {
    pub fn next_delay(&mut self, current: u64, requested: u64) -> Option<std::time::Duration> {
        if current != requested || self.attempts >= 3 {
            return None;
        }
        let secs = 1u64 << self.attempts;
        self.attempts += 1;
        Some(std::time::Duration::from_secs(secs))
    }
    pub fn attempts(&self) -> u8 {
        self.attempts
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restore_preserves_later_edits() {
        let r = Route::default_half(42, false);
        let mut edited = r.clone();
        edited.metric += 1;
        assert_eq!(undo_route(&r, None), Undo::AlreadyAbsent);
        assert_eq!(undo_route(&r, Some(&r)), Undo::DeleteExact);
        assert_eq!(undo_route(&r, Some(&edited)), Undo::Conflict);
    }
    #[test]
    fn corruption_and_scope_expansion_rejected() {
        let n = "012345678901234567890123456789ab".to_owned();
        let mut l = Lease::new(n.clone(), n, 4, 0, vec![], vec![]);
        let b = l.encode().unwrap();
        assert!(Lease::decode(&b).is_ok());
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v["document"]["generation"] = 5.into();
        assert!(Lease::decode(&serde_json::to_vec(&v).unwrap()).is_err());
        l.owned_luid = Some(4);
        let mut r = Route::default_half(4, false);
        r.prefix = 0;
        l.added_routes.push(r);
        assert!(l.encode().is_err());
    }
    #[test]
    fn retry_is_bounded_and_generation_scoped() {
        let mut r = Retry::default();
        for s in [1, 2, 4] {
            assert_eq!(r.next_delay(5, 5).unwrap().as_secs(), s);
        }
        assert!(r.next_delay(5, 5).is_none());
        let mut r = Retry::default();
        assert!(r.next_delay(6, 5).is_none());
    }
}

#[cfg(test)]
mod lifecycle_regressions {
    use super::*;
    fn lease() -> Lease {
        Lease::new("1".repeat(32), "2".repeat(32), 9, 0, vec![], vec![])
    }
    fn interface(l: &Lease) -> Interface {
        Interface {
            guid: l.guid.clone(),
            luid: 77,
            alias: l.alias.clone(),
            dns: vec!["198.18.0.2".parse().unwrap()],
            unicast: vec![("198.18.0.1".parse().unwrap(), 30)],
            ipv6_enabled: true,
            up: true,
            mtu: 1500,
        }
    }
    #[test]
    fn checksum_detects_snapshot_change() {
        let l = lease();
        let bytes = l.encode().unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        envelope["document"]["generation"] = 10.into();
        assert!(Lease::decode(&serde_json::to_vec(&envelope).unwrap()).is_err());
    }
    #[test]
    fn journal_cannot_target_an_observed_physical_luid() {
        let mut l = lease();
        let mut physical = interface(&l);
        physical.guid = "3".repeat(32);
        physical.alias = "Ethernet".into();
        l.physical_before.push(physical);
        l.owned_luid = Some(77);
        l.added_routes.push(Route::default_half(77, false));
        assert!(l.validate().is_err());
    }
    #[test]
    fn unknown_poststate_cannot_include_foreign_interface_route() {
        let l = lease();
        let i = interface(&l);
        let mut route = Route::default_half(88, false);
        route.protocol = 2;
        route.destination = "224.0.0.0".parse().unwrap();
        route.prefix = 4;
        route.next_hop = "0.0.0.0".parse().unwrap();
        assert!(!partial_footprint(&l, &i, &[route]));
    }
    #[test]
    fn already_undone_route_recreated_later_is_conflict() {
        let r = Route::default_half(77, false);
        assert_eq!(undo_with_progress(&r, Some(&r), true), Undo::Conflict);
        assert_eq!(undo_with_progress(&r, None, true), Undo::AlreadyAbsent);
    }
    #[test]
    fn route_change_is_never_overwritten() {
        let r = Route::default_half(77, false);
        let mut later = r.clone();
        later.metric = 8;
        assert_eq!(undo_route(&r, Some(&later)), Undo::Conflict);
        assert_eq!(undo_route(&r, None), Undo::AlreadyAbsent);
    }
    #[test]
    fn caller_cannot_change_job_namespace() {
        let mut l = lease();
        l.job = r"Global\ForeignJob".into();
        assert!(l.encode().is_err());
    }
    #[test]
    fn quarantined_requires_all_owned_evidence() {
        let mut l = lease();
        l.stage = Stage::Quarantined;
        assert!(l.validate().is_err());
    }
    #[test]
    fn tunnel_template_keeps_all_auto_routing_off() {
        use crate::{Cipher, Profile, Secret};
        let p = Profile {
            name: "离线".into(),
            server: "203.0.113.9".parse().unwrap(),
            port: 443,
            method: Cipher::Aes128Gcm,
            password: Secret("not-a-real-credential".into()),
        };
        let config =
            crate::engine::config_for_tunnel(&p, &format!("LG-{}", "1".repeat(32)), "Ethernet")
                .unwrap();
        let v: serde_json::Value = serde_json::from_slice(config.bytes()).unwrap();
        assert_eq!(v["tun"]["enable"], true);
        assert_eq!(v["tun"]["auto-route"], false);
        assert_eq!(v["tun"]["strict-route"], false);
        assert_eq!(v["interface-name"], "Ethernet");
        assert_eq!(v["external-controller"], "");
    }
}

#[cfg(test)]
mod initialization_regression {
    use super::*;
    #[test]
    fn known_driver_initial_mtu_can_be_recovered_before_core_configuration() {
        let l = Lease::new("1".repeat(32), "2".repeat(32), 0, 0, vec![], vec![]);
        let mut i = Interface {
            guid: l.guid.clone(),
            alias: l.alias.clone(),
            luid: 88,
            dns: vec![],
            unicast: vec![],
            ipv6_enabled: true,
            up: false,
            mtu: 65535,
        };
        assert!(partial_footprint(&l, &i, &[]));
        i.mtu = 9000;
        assert!(!partial_footprint(&l, &i, &[]));
    }
}
