//! v3 narrow-permit plan: ALE identity gate ∩ packet-layer exception, layered on the M2 baseline.
//!
//! Pure and side-effect free. Nothing here installs a filter or proves enforcement; it only
//! defines the exact 14 objects, the order in which they may appear, and how a native readback is
//! compared against them. A permit is never considered present from configuration or journal alone.
use crate::guard::{self, JournalStage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

pub const POLICY_VERSION: u32 = 3;
/// providerData marker of every v3 filter. Parent provider/sublayer stay the M2 objects: WFP only
/// arbitrates PERMIT against BLOCK by weight inside ONE sublayer, so a permit elsewhere is useless
/// against the M2 BLOCK and a permit with hard/clear rights is forbidden by design.
pub const MARKER: &[u8] = b"LineGuard.Permit.v3";
pub const KEY_BASE: u128 = 0xa9b29c632a1a49c9ae644e4700040000;
/// ALE default BLOCK uses the same weight as the M2 packet baseline.
pub const BLOCK_WEIGHT: u64 = guard::FILTER_WEIGHT;
/// Soft PERMIT, strictly above this product's own BLOCK in the same sublayer only.
pub const PERMIT_WEIGHT: u64 = 0x2000;
const _: () = assert!(PERMIT_WEIGHT > BLOCK_WEIGHT);
pub const GATE_COUNT: usize = 10;
pub const PACKET_COUNT: usize = 4;
pub const RULE_COUNT: usize = GATE_COUNT + PACKET_COUNT;
pub const MAX_APP_ID: usize = 4096;
pub const MAX_JOURNAL: usize = 64 * 1024;
pub const GATE_INTENT: &str = "INSTALL-ALE-GATE-KEEP-BLOCK";
pub const OPEN_INTENT: &str = "OPEN-NARROW-DATA-PATH";
/// Access right of the single ACE in the ALE_USER_ID descriptor (FWP_ACTRL_MATCH_FILTER).
pub const MATCH_FILTER_RIGHT: u32 = 0x0000_0001;

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    AleConnectV4,
    AleRecvAcceptV4,
    AleConnectV6,
    AleRecvAcceptV6,
    OutPacketV4,
    InPacketV4,
}
pub const LAYERS: [Layer; 6] = [
    Layer::AleConnectV4,
    Layer::AleRecvAcceptV4,
    Layer::AleConnectV6,
    Layer::AleRecvAcceptV6,
    Layer::OutPacketV4,
    Layer::InPacketV4,
];
impl Layer {
    pub fn is_packet(self) -> bool {
        matches!(self, Layer::OutPacketV4 | Layer::InPacketV4)
    }
    /// Conditions the official per-layer table allows. Packet layers have NO app/user/proto/port.
    pub fn allows(self, field: Field) -> bool {
        match self {
            Layer::OutPacketV4 | Layer::InPacketV4 => {
                matches!(field, Field::LocalInterface | Field::RemoteAddressV4)
            }
            Layer::AleConnectV4 | Layer::AleRecvAcceptV4 => true,
            Layer::AleConnectV6 | Layer::AleRecvAcceptV6 => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Block,
    Permit,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    /// ALE default-deny plus identity permits. Harmless alone: the M2 packet BLOCK still holds.
    Gate,
    /// The only objects that create a data path. Added last, revoked first.
    Packet,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    LocalInterface,
    RemoteAddressV4,
    Protocol,
    RemotePort,
    AppId,
    UserId,
}
/// Every condition uses FWP_MATCH_EQUAL. Integers are host order, as WFP expects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Value {
    Luid(u64),
    Ipv4(Ipv4Addr),
    Protocol(u8),
    Port(u16),
    /// Exact bytes FwpmGetAppIdFromFileName0 returned (NT device path, UTF-16LE + NUL).
    AppId(Vec<u8>),
    /// Security descriptor with exactly one ACCESS_ALLOWED ACE of MATCH_FILTER_RIGHT for this SID.
    ServiceSid(String),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: Field,
    pub value: Value,
}
impl Condition {
    fn new(field: Field, value: Value) -> Self {
        Self { field, value }
    }
    fn well_typed(&self) -> bool {
        matches!(
            (self.field, &self.value),
            (Field::LocalInterface, Value::Luid(_))
                | (Field::RemoteAddressV4, Value::Ipv4(_))
                | (Field::Protocol, Value::Protocol(_))
                | (Field::RemotePort, Value::Port(_))
                | (Field::AppId, Value::AppId(_))
                | (Field::UserId, Value::ServiceSid(_))
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub key: u128,
    pub layer: Layer,
    pub action: Action,
    pub weight: u64,
    pub part: Part,
    pub conditions: Vec<Condition>,
}
pub fn is_permit_key(key: u128) -> bool {
    (KEY_BASE + 1..=KEY_BASE + RULE_COUNT as u128).contains(&key)
}
pub fn part_of(key: u128) -> Option<Part> {
    is_permit_key(key).then(|| {
        if key - KEY_BASE <= GATE_COUNT as u128 {
            Part::Gate
        } else {
            Part::Packet
        }
    })
}

/// Live, never user-typed inputs: LUIDs are read from the OS, the app id is derived from the
/// fixed controlled core path, the SID is the per-service SID SCM put in the token.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Params {
    pub tun_luid: u64,
    pub physical_luid: u64,
    pub endpoint: Ipv4Addr,
    pub port: u16,
    pub app_id: Vec<u8>,
    pub service_sid: String,
}
impl Params {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.tun_luid == 0 || self.physical_luid == 0 || self.tun_luid == self.physical_luid {
            return Err("TUN与物理接口LUID必须为不同的非零真实值");
        }
        let ip = self.endpoint;
        if ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.is_link_local()
            || ip.is_documentation()
            || ip.octets()[0] == 0
            || ip.octets()[0] >= 240
            // Never let the node exception collide with the TUN's own 198.18.0.0/15 range.
            || (ip.octets()[0] == 198 && ip.octets()[1] & 0xfe == 18)
        {
            return Err("节点必须是单一可路由IPv4单播地址");
        }
        if self.port == 0 {
            return Err("节点端口不能为0");
        }
        let id = &self.app_id;
        if id.len() < 4
            || id.len() > MAX_APP_ID
            || !id.len().is_multiple_of(2)
            || !id.ends_with(&[0, 0])
            || id[..id.len() - 2].chunks(2).any(|c| c == [0, 0])
        {
            return Err("核心App ID必须是系统派生的UTF-16LE路径");
        }
        if !valid_service_sid(&self.service_sid) {
            return Err("必须是专用服务SID（S-1-5-80-…）");
        }
        Ok(())
    }
}
/// `NT SERVICE\<name>` SIDs are S-1-5-80 followed by exactly five 32-bit sub-authorities.
pub fn valid_service_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let parts: Vec<_> = rest.split('-').collect();
    parts.len() == 5
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 10
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u32>().is_ok()
        })
}

/// The exact 14 v3 objects: 10 gate filters first (keys 1..=10), 4 packet permits last (11..=14).
pub fn plan(p: &Params) -> Result<Vec<Rule>, &'static str> {
    p.validate()?;
    let tun = || Condition::new(Field::LocalInterface, Value::Luid(p.tun_luid));
    let physical = || Condition::new(Field::LocalInterface, Value::Luid(p.physical_luid));
    let node = || Condition::new(Field::RemoteAddressV4, Value::Ipv4(p.endpoint));
    let core = |protocol: u8| {
        vec![
            Condition::new(Field::AppId, Value::AppId(p.app_id.clone())),
            Condition::new(Field::UserId, Value::ServiceSid(p.service_sid.clone())),
            physical(),
            node(),
            Condition::new(Field::Protocol, Value::Protocol(protocol)),
            Condition::new(Field::RemotePort, Value::Port(p.port)),
        ]
    };
    let gate = Part::Gate;
    let packet = Part::Packet;
    let specs: [(Layer, Action, Part, Vec<Condition>); RULE_COUNT] = [
        (Layer::AleConnectV4, Action::Block, gate, vec![]),
        (Layer::AleRecvAcceptV4, Action::Block, gate, vec![]),
        (Layer::AleConnectV6, Action::Block, gate, vec![]),
        (Layer::AleRecvAcceptV6, Action::Block, gate, vec![]),
        (Layer::AleConnectV4, Action::Permit, gate, vec![tun()]),
        (Layer::AleRecvAcceptV4, Action::Permit, gate, vec![tun()]),
        (Layer::AleConnectV4, Action::Permit, gate, core(TCP)),
        (Layer::AleConnectV4, Action::Permit, gate, core(UDP)),
        (Layer::AleRecvAcceptV4, Action::Permit, gate, core(TCP)),
        (Layer::AleRecvAcceptV4, Action::Permit, gate, core(UDP)),
        (Layer::OutPacketV4, Action::Permit, packet, vec![tun()]),
        (Layer::InPacketV4, Action::Permit, packet, vec![tun()]),
        (
            Layer::OutPacketV4,
            Action::Permit,
            packet,
            vec![physical(), node()],
        ),
        (
            Layer::InPacketV4,
            Action::Permit,
            packet,
            vec![physical(), node()],
        ),
    ];
    let rules: Vec<Rule> = specs
        .into_iter()
        .enumerate()
        .map(|(i, (layer, action, part, conditions))| Rule {
            key: KEY_BASE + i as u128 + 1,
            layer,
            action,
            weight: match action {
                Action::Block => BLOCK_WEIGHT,
                Action::Permit => PERMIT_WEIGHT,
            },
            part,
            conditions,
        })
        .collect();
    for rule in &rules {
        // Defence in depth: a plan that a layer cannot express is rejected, never degraded.
        if rule.action == Action::Permit && rule.conditions.is_empty()
            || rule
                .conditions
                .iter()
                .any(|c| !c.well_typed() || !rule.layer.allows(c.field))
        {
            return Err("内部计划违反层条件矩阵");
        }
    }
    Ok(rules)
}

/// One filter as the native side decoded it. `conditions` is None when any condition could not
/// be decoded into the closed vocabulary above (unknown field, match type or value type).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    pub key: u128,
    pub filter_id: u64,
    pub layer: Option<Layer>,
    pub action: Option<Action>,
    pub weight: Option<u64>,
    /// Exactly FWPM_FILTER_FLAG_PERSISTENT: no boot, disabled, hard-permit or clear-right flags.
    pub persistent_only: bool,
    /// Provider/sublayer are the M2 objects and providerData is the v3 marker.
    pub owned: bool,
    pub conditions: Option<Vec<Condition>>,
}
impl Observed {
    fn matches(&self, rule: &Rule) -> bool {
        let same_conditions = self.conditions.as_ref().is_some_and(|seen| {
            let mut seen = seen.clone();
            let mut want = rule.conditions.clone();
            seen.sort_by_key(|c| c.field);
            want.sort_by_key(|c| c.field);
            seen == want
        });
        self.key == rule.key
            && self.owned
            && self.persistent_only
            && self.filter_id != 0
            && self.layer == Some(rule.layer)
            && self.action == Some(rule.action)
            && self.weight == Some(rule.weight)
            && same_conditions
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// No v3 object; the M2 baseline alone decides.
    Absent,
    /// All 10 gate objects exact, no packet permit. Still no data path.
    Gate,
    /// All 14 exact. A narrow data path is permitted by policy; enforcement is NOT verified.
    Open,
    /// Anything else, including any v3 object without trusted expected parameters.
    Drift,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub policy_version: u32,
    pub state: State,
    pub gate_exact: usize,
    pub packet_exact: usize,
    pub present: usize,
    pub enforcement_verified: bool,
    pub detail: String,
}
/// `expected` comes from the validated permit journal; `observed` from a live WFP readback.
/// Unknown keys under the product provider are the caller's `extra` and always mean Drift.
pub fn assess(expected: Option<&Params>, observed: &[Observed], extra: bool) -> Evidence {
    let plan = expected.and_then(|p| plan(p).ok());
    let exact = |part: Part| {
        plan.as_ref().map_or(0, |rules| {
            rules
                .iter()
                .filter(|r| r.part == part)
                .filter(|r| observed.iter().filter(|o| o.key == r.key).count() == 1)
                .filter(|r| observed.iter().any(|o| o.matches(r)))
                .count()
        })
    };
    let gate_exact = exact(Part::Gate);
    let packet_exact = exact(Part::Packet);
    let packet_present = observed
        .iter()
        .filter(|o| part_of(o.key) == Some(Part::Packet))
        .count();
    let state = if observed.is_empty() && !extra {
        State::Absent
    } else if extra || plan.is_none() || observed.iter().any(|o| !is_permit_key(o.key)) {
        State::Drift
    } else if gate_exact == GATE_COUNT && packet_present == 0 && observed.len() == GATE_COUNT {
        State::Gate
    } else if gate_exact == GATE_COUNT
        && packet_exact == PACKET_COUNT
        && observed.len() == RULE_COUNT
    {
        State::Open
    } else {
        State::Drift
    };
    let detail = match state {
        State::Absent => "无v3许可对象；仅M2基线决定",
        State::Gate => "ALE身份门10条回读完整；无包层许可，数据面仍被M2阻断",
        State::Open => {
            "14条v3对象回读完整：仅TUN与单一节点的窄数据通路在策略上被允许；执行效果/旁路未验收"
        }
        State::Drift => "v3许可对象缺失、多余、字段漂移或缺少可信预期参数；须先撤销许可",
    }
    .into();
    Evidence {
        policy_version: POLICY_VERSION,
        state,
        gate_exact,
        packet_exact,
        present: observed.len(),
        enforcement_verified: false,
        detail,
    }
}

/// Preconditions are evaluated against fresh readbacks inside the write transaction.
pub fn may_install_gate(m2: guard::State, current: State) -> Result<(), &'static str> {
    if m2 != guard::State::Configured {
        return Err("要求完整M2阻断基线；不会自动封网或替代基线");
    }
    if current != State::Absent {
        return Err("已有v3对象；先撤销再安装，不覆盖未知状态");
    }
    Ok(())
}
/// The packet permits are the final enabling step and require every other barrier to be proved.
pub fn may_open(
    m2: guard::State,
    emergency_present: bool,
    current: State,
    tun_observed: bool,
) -> Result<(), &'static str> {
    if m2 != guard::State::Configured {
        return Err("M2基线回读不完整；拒绝放行");
    }
    if emergency_present {
        return Err("独立应急阻断存在；只能由管理员显式解除，放行不会绕过它");
    }
    if current != State::Gate {
        return Err("ALE身份门未精确就绪；包层许可只能最后启用");
    }
    if !tun_observed {
        return Err("独占TUN后态未回读确认");
    }
    Ok(())
}
/// Revocation deletes every v3 key in ONE transaction; packet keys are listed first so a
/// partially applied (non-transactional) fallback could never leave packet permits behind gates.
pub fn revoke_order(observed: &[Observed]) -> Result<Vec<u128>, &'static str> {
    if observed.iter().any(|o| !is_permit_key(o.key) || !o.owned) {
        return Err("存在非本产品v3对象；不扩大删除范围");
    }
    let mut keys: Vec<u128> = observed.iter().map(|o| o.key).collect();
    keys.sort_by_key(|k| (part_of(*k) != Some(Part::Packet), *k));
    keys.dedup();
    Ok(keys)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalAction {
    Gate,
    Open,
    Revoke,
}
/// Write-ahead record. It supplies expected values for readback comparison; it is never evidence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema: u32,
    pub action: JournalAction,
    pub stage: JournalStage,
    pub timestamp_ms: u64,
    pub params: Option<Params>,
    pub error: Option<String>,
}
impl Journal {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != POLICY_VERSION {
            return Err("许可journal版本不支持");
        }
        match (&self.params, self.action) {
            (Some(p), _) => p.validate()?,
            (None, JournalAction::Revoke) => {}
            (None, _) => return Err("安装/放行journal缺少参数"),
        }
        if self.error.as_ref().is_some_and(|e| e.len() > 1024) {
            return Err("journal错误信息过长");
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let payload = serde_json::to_vec(self).map_err(|_| "journal编码失败")?;
        let encoded = serde_json::to_vec(&Envelope {
            schema: POLICY_VERSION,
            sha256: hex(&Sha256::digest(&payload)),
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
        if e.schema != POLICY_VERSION {
            return Err("journal版本不支持");
        }
        let data = serde_json::to_vec(&e.document).map_err(|_| "journal格式无效")?;
        if hex(&Sha256::digest(&data)) != e.sha256 {
            return Err("journal校验和不符");
        }
        e.document.validate()?;
        Ok(e.document)
    }
    /// Expected values for readback comparison. The stage is deliberately ignored: whether an
    /// object exists is decided only by the live readback, never by what the journal claims.
    pub fn expected(&self) -> Option<&Params> {
        self.params.as_ref()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: u32,
    sha256: String,
    document: Journal,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Params {
        let mut app_id: Vec<u8> = r"\device\harddiskvolume3\programdata\lineguard\mihomo.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        app_id.extend([0, 0]);
        Params {
            tun_luid: 0x0006_8000_0000_0011,
            physical_luid: 0x0006_0000_0000_0002,
            endpoint: Ipv4Addr::new(203, 0, 114, 7),
            port: 8388,
            app_id,
            service_sid: "S-1-5-80-1-2-3-4-5".into(),
        }
    }
    fn observe(rules: &[Rule]) -> Vec<Observed> {
        rules
            .iter()
            .enumerate()
            .map(|(i, r)| Observed {
                key: r.key,
                filter_id: 100 + i as u64,
                layer: Some(r.layer),
                action: Some(r.action),
                weight: Some(r.weight),
                persistent_only: true,
                owned: true,
                conditions: Some(r.conditions.iter().rev().cloned().collect()),
            })
            .collect()
    }

    #[test]
    fn plan_is_fourteen_ordered_objects_matching_matrix() {
        let rules = plan(&params()).unwrap();
        assert_eq!(rules.len(), RULE_COUNT);
        assert!(rules[..GATE_COUNT].iter().all(|r| r.part == Part::Gate));
        assert!(rules[GATE_COUNT..].iter().all(|r| r.part == Part::Packet));
        for (i, r) in rules.iter().enumerate() {
            assert_eq!(r.key, KEY_BASE + i as u128 + 1);
            assert_eq!(part_of(r.key), Some(r.part));
            assert!(!guard::rules().iter().any(|m2| m2.key == r.key));
        }
        // No permit anywhere on IPv6 and no unconditional permit.
        assert!(rules.iter().all(|r| r.action == Action::Block
            || (!matches!(r.layer, Layer::AleConnectV6 | Layer::AleRecvAcceptV6)
                && !r.conditions.is_empty())));
        assert_eq!(
            rules.iter().filter(|r| r.action == Action::Block).count(),
            4
        );
        assert!(
            rules
                .iter()
                .all(|r| (r.action == Action::Block) == (r.weight == BLOCK_WEIGHT))
        );
    }

    #[test]
    fn packet_layer_never_carries_identity_and_physical_permit_needs_node() {
        let rules = plan(&params()).unwrap();
        for r in rules.iter().filter(|r| r.layer.is_packet()) {
            assert!(
                r.conditions
                    .iter()
                    .all(|c| matches!(c.field, Field::LocalInterface | Field::RemoteAddressV4))
            );
            let physical = r.conditions.contains(&Condition::new(
                Field::LocalInterface,
                Value::Luid(params().physical_luid),
            ));
            if physical {
                assert!(
                    r.conditions
                        .iter()
                        .any(|c| c.field == Field::RemoteAddressV4)
                );
            }
        }
        // Every ALE permit on the physical interface carries full core identity + 5-tuple subset.
        for r in rules
            .iter()
            .filter(|r| !r.layer.is_packet() && r.action == Action::Permit)
        {
            let fields: Vec<_> = r.conditions.iter().map(|c| c.field).collect();
            if fields.len() > 1 {
                for f in [
                    Field::AppId,
                    Field::UserId,
                    Field::LocalInterface,
                    Field::RemoteAddressV4,
                    Field::Protocol,
                    Field::RemotePort,
                ] {
                    assert!(fields.contains(&f));
                }
            } else {
                assert_eq!(
                    r.conditions,
                    vec![Condition::new(
                        Field::LocalInterface,
                        Value::Luid(params().tun_luid)
                    )]
                );
            }
        }
    }

    #[test]
    fn invalid_params_rejected() {
        let mut p = params();
        p.physical_luid = p.tun_luid;
        assert!(plan(&p).is_err());
        for ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 19, 3, 3),
            Ipv4Addr::new(250, 1, 1, 1),
        ] {
            let mut p = params();
            p.endpoint = ip;
            assert!(p.validate().is_err(), "{ip}");
        }
        let mut p = params();
        p.port = 0;
        assert!(p.validate().is_err());
        let mut p = params();
        p.app_id.truncate(p.app_id.len() - 2);
        assert!(p.validate().is_err());
        let mut p = params();
        p.app_id = vec![b'a', 0, 0, 0, b'b', 0, 0, 0];
        assert!(p.validate().is_err());
        for sid in [
            "S-1-5-18",
            "S-1-5-80-1-2-3-4",
            "S-1-5-80-1-2-3-4-5-6",
            "S-1-5-80-1-2-3-4-x",
            "S-1-5-80-1-2-3-4-4294967296",
            "S-1-5-80-01-2-3-4-5",
        ] {
            assert!(!valid_service_sid(sid), "{sid}");
        }
        assert!(valid_service_sid("S-1-5-80-0-4294967295-3-4-5"));
    }

    #[test]
    fn readback_states() {
        let p = params();
        let rules = plan(&p).unwrap();
        assert_eq!(assess(Some(&p), &[], false).state, State::Absent);
        let gate = observe(&rules[..GATE_COUNT]);
        assert_eq!(assess(Some(&p), &gate, false).state, State::Gate);
        let all = observe(&rules);
        let e = assess(Some(&p), &all, false);
        assert_eq!(e.state, State::Open);
        assert!(!e.enforcement_verified);
        // No trusted expectations → never Gate/Open even with a perfect-looking readback.
        assert_eq!(assess(None, &all, false).state, State::Drift);
        assert_eq!(assess(Some(&p), &all, true).state, State::Drift);
        // Packet permits without the full gate are drift, not a partial success.
        assert_eq!(
            assess(Some(&p), &observe(&rules[GATE_COUNT..]), false).state,
            State::Drift
        );
    }

    #[test]
    fn any_field_drift_is_detected() {
        let p = params();
        let rules = plan(&p).unwrap();
        let base = observe(&rules);
        type Mutation = Box<dyn Fn(&mut Observed)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|o| o.owned = false),
            Box::new(|o| o.persistent_only = false),
            Box::new(|o| o.filter_id = 0),
            Box::new(|o| o.weight = Some(PERMIT_WEIGHT + 1)),
            Box::new(|o| o.action = Some(Action::Block)),
            Box::new(|o| o.layer = Some(Layer::InPacketV4)),
            Box::new(|o| o.conditions = None),
            Box::new(|o| {
                o.conditions.as_mut().unwrap().pop();
            }),
            Box::new(|o| {
                for c in o.conditions.as_mut().unwrap() {
                    if let Value::Luid(l) = &mut c.value {
                        *l += 1;
                    }
                }
            }),
        ];
        for (n, m) in mutations.iter().enumerate() {
            // Mutate the physical-node packet permit (has two conditions) and an identity permit.
            for target in [12usize, 6] {
                let mut seen = base.clone();
                m(&mut seen[target]);
                let state = assess(Some(&p), &seen, false).state;
                if seen[target] != base[target] {
                    assert_eq!(state, State::Drift, "mutation {n} on {target}");
                }
            }
        }
        let mut dup = base.clone();
        dup.push(base[3].clone());
        assert_eq!(assess(Some(&p), &dup, false).state, State::Drift);
        let mut extra_cond = base.clone();
        extra_cond[10]
            .conditions
            .as_mut()
            .unwrap()
            .push(Condition::new(Field::RemotePort, Value::Port(1)));
        assert_eq!(assess(Some(&p), &extra_cond, false).state, State::Drift);
    }

    #[test]
    fn enabling_order_is_enforced() {
        use guard::State as M2;
        assert!(may_install_gate(M2::Configured, State::Absent).is_ok());
        assert!(may_install_gate(M2::Drift, State::Absent).is_err());
        assert!(may_install_gate(M2::Configured, State::Drift).is_err());
        assert!(may_open(M2::Configured, false, State::Gate, true).is_ok());
        assert!(may_open(M2::Configured, true, State::Gate, true).is_err());
        assert!(may_open(M2::Configured, false, State::Absent, true).is_err());
        assert!(may_open(M2::Configured, false, State::Open, true).is_err());
        assert!(may_open(M2::Configured, false, State::Gate, false).is_err());
        assert!(may_open(M2::Absent, false, State::Gate, true).is_err());
    }

    #[test]
    fn revoke_lists_packet_permits_first_and_refuses_foreign() {
        let rules = plan(&params()).unwrap();
        let seen = observe(&rules);
        let order = revoke_order(&seen).unwrap();
        assert_eq!(order.len(), RULE_COUNT);
        assert!(
            order[..PACKET_COUNT]
                .iter()
                .all(|k| part_of(*k) == Some(Part::Packet))
        );
        let mut foreign = seen.clone();
        foreign[0].owned = false;
        assert!(revoke_order(&foreign).is_err());
        let mut alien = seen;
        alien[0].key = guard::rules()[0].key;
        assert!(revoke_order(&alien).is_err());
    }

    #[test]
    fn journal_roundtrip_checksum_and_expectations() {
        let j = Journal {
            schema: POLICY_VERSION,
            action: JournalAction::Gate,
            stage: JournalStage::Prepared,
            timestamp_ms: 1,
            params: Some(params()),
            error: None,
        };
        let bytes = j.encode().unwrap();
        assert_eq!(Journal::decode(&bytes).unwrap(), j);
        let j_copy = j.clone();
        assert!(j.expected().is_some());
        let mut tampered = String::from_utf8(bytes).unwrap();
        tampered = tampered.replacen("8388", "8389", 1);
        assert!(Journal::decode(tampered.as_bytes()).is_err());
        let missing = Journal {
            params: None,
            ..j.clone()
        };
        assert!(missing.encode().is_err());
        let revoke = Journal {
            action: JournalAction::Revoke,
            params: None,
            ..j
        };
        assert!(revoke.encode().is_ok());
        assert!(revoke.expected().is_none());
        // A revoke keeps the previous parameters so an aborted revoke can still be compared.
        assert!(
            Journal {
                action: JournalAction::Revoke,
                ..j_copy
            }
            .expected()
            .is_some()
        );
    }
}
