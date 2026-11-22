//! Versioned all-IP laboratory block plan. Never a VPN/protection certification.
use serde::{Deserialize, Serialize};

pub const POLICY_VERSION: u32 = 2;
pub const RESCUE_MARKER: &str = "LineGuard.Rescue.GuardPolicy.v2.NetworkJournal.v1.PermitRevoke.v3";
pub const PROVIDER: u128 = 0xa9b29c632a1a49c9ae644e4700020001;
pub const SUBLAYER: u128 = 0xa9b29c632a1a49c9ae644e4700020002;
pub const MARKER: &[u8] = b"LineGuard.Guard.v2";
pub const SUBLAYER_WEIGHT: u16 = 0x7000;
pub const FILTER_WEIGHT: u64 = 0x1000;
pub const RULE_COUNT: usize = 12;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    InV4,
    InV6,
    OutV4,
    OutV6,
    ForwardV4,
    ForwardV6,
}
pub const LAYERS: [Layer; 6] = [
    Layer::InV4,
    Layer::InV6,
    Layer::OutV4,
    Layer::OutV6,
    Layer::ForwardV4,
    Layer::ForwardV6,
];
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Lifetime {
    Persistent,
    Boot,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub key: u128,
    pub layer: Layer,
    pub lifetime: Lifetime,
}
pub fn rules() -> [Rule; RULE_COUNT] {
    std::array::from_fn(|i| Rule {
        key: 0xa9b29c632a1a49c9ae644e4700030000 + i as u128 + 1,
        layer: LAYERS[i % 6],
        lifetime: if i < 6 {
            Lifetime::Persistent
        } else {
            Lifetime::Boot
        },
    })
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Unknown,
    Absent,
    Drift,
    Configured,
    Emergency,
    /// M2 baseline plus exact v3 narrow permits: no longer block-all, never "protected".
    Narrowed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub policy_version: u32,
    pub state: State,
    pub observed_unix_ms: u64,
    pub persistent_rules: usize,
    pub boot_rules: usize,
    pub expected_rules: usize,
    pub service_auto_system: bool,
    pub enforcement_verified: bool,
    pub detail: String,
}
impl Evidence {
    pub fn unknown() -> Self {
        Self {
            policy_version: POLICY_VERSION,
            state: State::Unknown,
            observed_unix_ms: 0,
            persistent_rules: 0,
            boot_rules: 0,
            expected_rules: RULE_COUNT,
            service_auto_system: false,
            enforcement_verified: false,
            detail: "未取得当前WFP证据；不能确定是否存在阻断".into(),
        }
    }
    pub fn assess(
        parents_present: bool,
        parents_valid: bool,
        service_ok: bool,
        observed: &[(u128, bool)],
        extra: bool,
        now: u64,
    ) -> Self {
        let plan = rules();
        let valid = |spec: &Rule| {
            observed
                .iter()
                .filter(|(key, exact)| *key == spec.key && *exact)
                .count()
                == 1
        };
        let persistent_rules = plan
            .iter()
            .filter(|r| r.lifetime == Lifetime::Persistent && valid(r))
            .count();
        let boot_rules = plan
            .iter()
            .filter(|r| r.lifetime == Lifetime::Boot && valid(r))
            .count();
        let state = if !parents_present && observed.is_empty() && !extra {
            State::Absent
        } else if parents_valid
            && service_ok
            && !extra
            && observed.len() == RULE_COUNT
            && persistent_rules + boot_rules == RULE_COUNT
        {
            State::Configured
        } else {
            State::Drift
        };
        let detail = match state {
            State::Absent => "未发现本产品阻断规则；没有防护",
            State::Configured => {
                "12条策略存储/字段回读完整；boot仅为注册证据，阻断效果与冷启动未验收"
            }
            State::Drift => "规则缺失、字段/归属漂移或服务配置不符；阻断可能仍部分生效，请独立检查",
            State::Unknown | State::Emergency | State::Narrowed => unreachable!(),
        }
        .into();
        Self {
            policy_version: POLICY_VERSION,
            state,
            observed_unix_ms: now,
            persistent_rules,
            boot_rules,
            expected_rules: RULE_COUNT,
            service_auto_system: service_ok,
            enforcement_verified: false,
            detail,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalStage {
    Prepared,
    Committed,
    Aborted,
    Uncertain,
}
pub fn failed_mutation(commit_attempted: bool, abort_succeeded: bool) -> JournalStage {
    if !commit_attempted && abort_succeeded {
        JournalStage::Aborted
    } else {
        JournalStage::Uncertain
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_has_distinct_lifetime_pairs() {
        let plan = rules();
        for (i, r) in plan.iter().enumerate() {
            assert!(!plan[..i].iter().any(|other| other.key == r.key));
            assert_eq!(r.layer, plan[(i + 6) % 12].layer);
            assert_ne!(r.lifetime, plan[(i + 6) % 12].lifetime);
        }
    }
    #[test]
    fn no_rules_or_incomplete_rules_never_configured() {
        assert_eq!(
            Evidence::assess(false, false, false, &[], false, 1).state,
            State::Absent
        );
        let partial: Vec<_> = rules()[..6].iter().map(|r| (r.key, true)).collect();
        assert_eq!(
            Evidence::assess(true, true, true, &partial, false, 1).state,
            State::Drift
        );
    }
    #[test]
    fn readback_not_config_or_journal_produces_evidence() {
        let full: Vec<_> = rules().iter().map(|r| (r.key, true)).collect();
        let e = Evidence::assess(true, true, true, &full, false, 1);
        assert_eq!(e.state, State::Configured);
        assert!(!e.enforcement_verified);
        assert_eq!(
            Evidence::assess(true, true, false, &full, false, 1).state,
            State::Drift
        );
        assert_eq!(
            Evidence::assess(true, true, true, &full, true, 1).state,
            State::Drift
        );
    }
    #[test]
    fn unknown_commit_or_failed_abort_is_not_rollback_success() {
        assert_eq!(failed_mutation(false, true), JournalStage::Aborted);
        assert_eq!(failed_mutation(false, false), JournalStage::Uncertain);
        assert_eq!(failed_mutation(true, true), JournalStage::Uncertain);
    }
}
