//! v3 narrow permits (ALE identity gate ∩ packet exception) under the fixed M2 parents.
//!
//! Admin-only, explicit intent, never reachable from Connect or the ordinary UI. The gate is a
//! separate committed transaction; the packet permits are a final, separate transaction. Revocation
//! removes every v3 object in one transaction. Nothing here reports enforcement or protection.
use super::{
    security::{Descriptor, require_elevated_admin, sid_string},
    storage::Store,
    wfp::{self, Engine, Enumeration, Memory, check, conflict, gid, key, now, weight},
};
use lineguard_core::{
    guard::{self, JournalStage},
    permit::{
        self as model, Action, Condition, Field, JournalAction, Layer, Observed, Params, Part,
        Value,
    },
};
use std::{io, net::Ipv4Addr, ptr};
use windows_sys::{
    Win32::{
        Foundation::FWP_E_FILTER_NOT_FOUND,
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::{
            ACCESS_ALLOWED_ACE, ACL, GetAce, GetSecurityDescriptorDacl,
            GetSecurityDescriptorLength, IsValidSecurityDescriptor,
        },
    },
    core::GUID,
};

const MAX_SD: u32 = 4096;

fn layer_guid(layer: Layer) -> GUID {
    match layer {
        Layer::AleConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::AleRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::AleConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::AleRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        Layer::OutPacketV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        Layer::InPacketV4 => FWPM_LAYER_INBOUND_IPPACKET_V4,
    }
}
fn layer_of(guid: &GUID) -> Option<Layer> {
    model::LAYERS
        .into_iter()
        .find(|l| key(&layer_guid(*l)) == key(guid))
}
fn field_guid(field: Field) -> GUID {
    match field {
        Field::LocalInterface => FWPM_CONDITION_IP_LOCAL_INTERFACE,
        Field::RemoteAddressV4 => FWPM_CONDITION_IP_REMOTE_ADDRESS,
        Field::Protocol => FWPM_CONDITION_IP_PROTOCOL,
        Field::RemotePort => FWPM_CONDITION_IP_REMOTE_PORT,
        Field::AppId => FWPM_CONDITION_ALE_APP_ID,
        Field::UserId => FWPM_CONDITION_ALE_USER_ID,
    }
}
fn field_of(guid: &GUID) -> Option<Field> {
    [
        Field::LocalInterface,
        Field::RemoteAddressV4,
        Field::Protocol,
        Field::RemotePort,
        Field::AppId,
        Field::UserId,
    ]
    .into_iter()
    .find(|f| key(&field_guid(*f)) == key(guid))
}
fn marker(blob: &FWP_BYTE_BLOB) -> bool {
    blob.size as usize == model::MARKER.len()
        && !blob.data.is_null()
        && unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) } == model::MARKER
}
fn blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: model::MARKER.len() as u32,
        data: model::MARKER.as_ptr().cast_mut(),
    }
}
/// Owner/group are required for the kernel AccessCheck; the DACL grants only MATCH_FILTER.
fn user_descriptor(sid: &str) -> io::Result<Descriptor> {
    if !model::valid_service_sid(sid) {
        return Err(conflict());
    }
    Descriptor::new(&format!("O:SYG:SYD:(A;;CC;;;{sid})"))
}
/// Decode an ALE_USER_ID descriptor back to the one service SID, or None if it is anything else.
fn decode_user(blob: &FWP_BYTE_BLOB) -> Option<String> {
    if blob.data.is_null() || blob.size == 0 || blob.size > MAX_SD {
        return None;
    }
    let sd = blob.data.cast();
    if unsafe { IsValidSecurityDescriptor(sd) } == 0
        || unsafe { GetSecurityDescriptorLength(sd) } > blob.size
    {
        return None;
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) } == 0
        || present == 0
        || dacl.is_null()
        || unsafe { (*dacl).AceCount } != 1
    {
        return None;
    }
    let mut ace = ptr::null_mut();
    if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
        return None;
    }
    let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if ace.Header.AceType != 0 || ace.Header.AceFlags != 0 || ace.Mask != model::MATCH_FILTER_RIGHT
    {
        return None;
    }
    let sid = sid_string((&ace.SidStart as *const u32).cast_mut().cast()).ok()?;
    model::valid_service_sid(&sid).then_some(sid)
}
fn bytes(blob: *const FWP_BYTE_BLOB, limit: usize) -> Option<Vec<u8>> {
    let blob = unsafe { blob.as_ref() }?;
    if blob.data.is_null() || blob.size as usize > limit {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }.to_vec())
}
fn decode_condition(c: &FWPM_FILTER_CONDITION0) -> Option<Condition> {
    if c.matchType != FWP_MATCH_EQUAL {
        return None;
    }
    let field = field_of(&c.fieldKey)?;
    let v = &c.conditionValue;
    let value = unsafe {
        match (field, v.r#type) {
            (Field::LocalInterface, FWP_UINT64) => Value::Luid(*v.Anonymous.uint64.as_ref()?),
            (Field::RemoteAddressV4, FWP_UINT32) => Value::Ipv4(Ipv4Addr::from(v.Anonymous.uint32)),
            (Field::Protocol, FWP_UINT8) => Value::Protocol(v.Anonymous.uint8),
            (Field::RemotePort, FWP_UINT16) => Value::Port(v.Anonymous.uint16),
            (Field::AppId, FWP_BYTE_BLOB_TYPE) => {
                Value::AppId(bytes(v.Anonymous.byteBlob, model::MAX_APP_ID)?)
            }
            (Field::UserId, FWP_SECURITY_DESCRIPTOR_TYPE) => {
                Value::ServiceSid(decode_user(v.Anonymous.sd.as_ref()?)?)
            }
            _ => return None,
        }
    };
    Some(Condition { field, value })
}
fn decode(filter: &FWPM_FILTER0) -> Observed {
    let owned = !filter.providerKey.is_null()
        && key(unsafe { &*filter.providerKey }) == guard::PROVIDER
        && key(&filter.subLayerKey) == guard::SUBLAYER
        && marker(&filter.providerData);
    // Callouts, contexts and hard/clear rights are never part of the plan.
    let action = (unsafe { filter.Anonymous.rawContext } == 0)
        .then_some(filter.action.r#type)
        .and_then(|a| match a {
            FWP_ACTION_BLOCK => Some(Action::Block),
            FWP_ACTION_PERMIT => Some(Action::Permit),
            _ => None,
        });
    let conditions = if filter.numFilterConditions == 0 {
        Some(Vec::new())
    } else if filter.filterCondition.is_null() || filter.numFilterConditions > 16 {
        None
    } else {
        unsafe {
            std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
        }
        .iter()
        .map(decode_condition)
        .collect()
    };
    Observed {
        key: key(&filter.filterKey),
        filter_id: filter.filterId,
        layer: layer_of(&filter.layerKey),
        action,
        weight: weight(&filter.weight),
        persistent_only: filter.flags == FWPM_FILTER_FLAG_PERSISTENT,
        owned,
        conditions,
    }
}

/// Fixed keys plus provider enumeration of the four ALE layers (packet layers are already
/// enumerated by the M2 observer, which flags unknown keys there as extras).
fn observe(engine: &Engine) -> io::Result<(Vec<Observed>, bool)> {
    let mut seen = Vec::new();
    for index in 1..=model::RULE_COUNT as u128 {
        let mut filter = Memory(ptr::null_mut::<FWPM_FILTER0>());
        let code =
            unsafe { FwpmFilterGetByKey0(engine.0, &gid(model::KEY_BASE + index), &mut filter.0) };
        if code == 0 {
            seen.push(decode(unsafe { &*filter.0 }));
        } else if code != FWP_E_FILTER_NOT_FOUND as u32 {
            check(code)?;
        }
    }
    let mut extra = false;
    for layer in [
        Layer::AleConnectV4,
        Layer::AleRecvAcceptV4,
        Layer::AleConnectV6,
        Layer::AleRecvAcceptV6,
    ] {
        let mut provider = gid(guard::PROVIDER);
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider,
            layerKey: layer_guid(layer),
            enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            actionMask: u32::MAX,
            ..Default::default()
        };
        let mut handle = ptr::null_mut();
        check(unsafe { FwpmFilterCreateEnumHandle0(engine.0, &template, &mut handle) })?;
        let enumeration = Enumeration { engine, handle };
        let mut entries = Memory(ptr::null_mut::<*mut FWPM_FILTER0>());
        let mut count = 0;
        check(unsafe {
            FwpmFilterEnum0(engine.0, enumeration.handle, 65, &mut entries.0, &mut count)
        })?;
        if count > 64 {
            return Err(conflict());
        }
        if count != 0 {
            for entry in unsafe { std::slice::from_raw_parts(entries.0, count as usize) } {
                let observed = decode(unsafe { &**entry });
                match seen.iter().find(|o| o.key == observed.key) {
                    Some(previous) if previous != &observed => return Err(conflict()),
                    Some(_) => {}
                    None => extra = true,
                }
            }
        }
    }
    Ok((seen, extra))
}
pub(super) fn any_present(engine: &Engine) -> io::Result<bool> {
    let (seen, extra) = observe(engine)?;
    Ok(!seen.is_empty() || extra)
}
fn expected() -> Option<Params> {
    Store::guard_journal_readonly()
        .and_then(|s| s.load_permit())
        .ok()
        .flatten()
        .and_then(|j| j.expected().cloned())
}

/// Live readback; journal parameters are only the comparison target.
pub fn inspect() -> io::Result<model::Evidence> {
    let engine = Engine::open()?;
    let mut tx = engine.transaction(true)?;
    let (seen, extra) = observe(&engine)?;
    tx.commit()?;
    Ok(model::assess(expected().as_ref(), &seen, extra))
}
/// Fold v3 evidence into the M2 view without ever upgrading it to protection.
pub(super) fn compose(base: guard::Evidence, permit: &model::Evidence) -> guard::Evidence {
    let mut out = base;
    match permit.state {
        model::State::Absent => {}
        model::State::Gate => {
            out.detail = format!("{}；另有{}", out.detail, permit.detail);
        }
        model::State::Open if out.state == guard::State::Configured => {
            out.state = guard::State::Narrowed;
            out.detail = permit.detail.clone();
        }
        model::State::Open | model::State::Drift => {
            out.state = guard::State::Drift;
            out.detail = format!("{}；{}", permit.detail, out.detail);
        }
    }
    out
}

/// Derives live inputs: the app id from the fixed controlled core path, the service SID from SCM.
pub fn params_for(
    tun_luid: u64,
    physical_luid: u64,
    endpoint: Ipv4Addr,
    port: u16,
) -> io::Result<Params> {
    let core = Store::core_assets(false)?.directory().join("mihomo.exe");
    let path = super::security::wide(&core.to_string_lossy());
    let mut app = Memory(ptr::null_mut::<FWP_BYTE_BLOB>());
    check(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app.0) })?;
    let app_id = bytes(app.0, model::MAX_APP_ID).ok_or_else(conflict)?;
    let params = Params {
        tun_luid,
        physical_luid,
        endpoint,
        port,
        app_id,
        service_sid: super::security::service_sid_string()?,
    };
    params.validate().map_err(io::Error::other)?;
    Ok(params)
}

/// Owns every buffer a native filter points into until FwpmFilterAdd0 returns.
// Boxes are deliberate: conditions hold raw pointers, and a Vec may move its elements on growth.
#[allow(clippy::vec_box)]
#[derive(Default)]
struct Built {
    conditions: Vec<FWPM_FILTER_CONDITION0>,
    luids: Vec<Box<u64>>,
    blobs: Vec<Box<FWP_BYTE_BLOB>>,
    data: Vec<Vec<u8>>,
    descriptors: Vec<Descriptor>,
}
impl Built {
    fn new(conditions: &[Condition]) -> io::Result<Self> {
        let mut out = Self::default();
        for c in conditions {
            let mut value = FWP_CONDITION_VALUE0::default();
            match &c.value {
                Value::Luid(luid) => {
                    let mut boxed = Box::new(*luid);
                    value.r#type = FWP_UINT64;
                    value.Anonymous.uint64 = &mut *boxed;
                    out.luids.push(boxed);
                }
                Value::Ipv4(ip) => {
                    value.r#type = FWP_UINT32;
                    value.Anonymous.uint32 = u32::from(*ip); // host byte order
                }
                Value::Protocol(p) => {
                    value.r#type = FWP_UINT8;
                    value.Anonymous.uint8 = *p;
                }
                Value::Port(p) => {
                    value.r#type = FWP_UINT16;
                    value.Anonymous.uint16 = *p;
                }
                Value::AppId(id) => {
                    let mut data = id.clone();
                    let mut boxed = Box::new(FWP_BYTE_BLOB {
                        size: data.len() as u32,
                        data: data.as_mut_ptr(),
                    });
                    value.r#type = FWP_BYTE_BLOB_TYPE;
                    value.Anonymous.byteBlob = &mut *boxed;
                    out.data.push(data);
                    out.blobs.push(boxed);
                }
                Value::ServiceSid(sid) => {
                    let sd = user_descriptor(sid)?;
                    let size = unsafe { GetSecurityDescriptorLength(sd.raw()) };
                    if size == 0 || size > MAX_SD {
                        return Err(conflict());
                    }
                    let mut boxed = Box::new(FWP_BYTE_BLOB {
                        size,
                        data: sd.raw().cast(),
                    });
                    value.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
                    value.Anonymous.sd = &mut *boxed;
                    out.descriptors.push(sd);
                    out.blobs.push(boxed);
                }
            }
            out.conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: field_guid(c.field),
                matchType: FWP_MATCH_EQUAL,
                conditionValue: value,
            });
        }
        Ok(out)
    }
}
fn add(engine: &Engine, rules: &[model::Rule]) -> io::Result<()> {
    let descriptor = Descriptor::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)")?;
    let mut provider = gid(guard::PROVIDER);
    let mut label = super::security::wide("LineGuard v3 narrow permit - EXPERIMENTAL UNVERIFIED");
    let display = FWPM_DISPLAY_DATA0 {
        name: label.as_mut_ptr(),
        description: ptr::null_mut(),
    };
    for rule in rules {
        let layer_key = layer_guid(rule.layer);
        let mut platform = Memory(ptr::null_mut::<FWPM_LAYER0>());
        check(unsafe { FwpmLayerGetByKey0(engine.0, &layer_key, &mut platform.0) })?;
        if unsafe { (*platform.0).flags } & FWPM_LAYER_FLAG_KERNEL == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "目标不是内核过滤层，拒绝降级",
            ));
        }
        let mut built = Built::new(&rule.conditions)?;
        let mut value = rule.weight;
        let filter = FWPM_FILTER0 {
            filterKey: gid(rule.key),
            displayData: display,
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            providerKey: &mut provider,
            providerData: blob(),
            layerKey: layer_key,
            subLayerKey: gid(guard::SUBLAYER),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 { uint64: &mut value },
            },
            numFilterConditions: built.conditions.len() as u32,
            filterCondition: if built.conditions.is_empty() {
                ptr::null_mut()
            } else {
                built.conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: match rule.action {
                    Action::Block => FWP_ACTION_BLOCK,
                    Action::Permit => FWP_ACTION_PERMIT,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        check(unsafe { FwpmFilterAdd0(engine.0, &filter, descriptor.raw(), ptr::null_mut()) })?;
        drop(built);
    }
    Ok(())
}

fn journal(action: JournalAction, stage: JournalStage, params: Option<Params>) -> model::Journal {
    model::Journal {
        schema: model::POLICY_VERSION,
        action,
        stage,
        timestamp_ms: now(),
        params,
        error: None,
    }
}
/// Shared write path: preconditions, write-ahead journal, mutation, in-transaction readback,
/// commit, then a fresh post-commit readback. Any failure aborts and is journaled honestly.
fn apply(
    action: JournalAction,
    params: Option<Params>,
    precondition: impl FnOnce(&Engine, model::State) -> io::Result<()>,
    mutation: impl FnOnce(&Engine, &[Observed]) -> io::Result<()>,
    target: model::State,
) -> io::Result<model::Evidence> {
    require_elevated_admin()?;
    let store = Store::guard_journal()?; // admin-only ACL and exclusive writer lock
    let previous = store.load_permit().ok().flatten();
    let expected = params
        .clone()
        .or_else(|| previous.as_ref().and_then(|j| j.expected().cloned()));
    let engine = Engine::open()?;
    let mut tx = engine.transaction(false)?;
    let (seen, extra) = observe(&engine)?;
    let current = model::assess(expected.as_ref(), &seen, extra);
    precondition(&engine, current.state)?;
    let mut record = journal(action, JournalStage::Prepared, expected.clone());
    store.save_permit(&record)?; // failure leaves WFP untouched
    let mut commit_attempted = false;
    let result = (|| {
        mutation(&engine, &seen)?;
        let (after, extra) = observe(&engine)?;
        if model::assess(expected.as_ref(), &after, extra).state != target {
            return Err(io::Error::other("事务内v3回读与目标不符，拒绝提交"));
        }
        commit_attempted = true;
        tx.commit()
    })();
    if let Err(error) = result {
        let aborted = tx.abort();
        record.stage = guard::failed_mutation(commit_attempted, aborted);
        record.error = Some(error.to_string().chars().take(512).collect());
        let saved = store.save_permit(&record).is_ok();
        return Err(io::Error::other(format!(
            "{error}；事务结果={:?}，journal记录={saved}。不确定时请inspect/独立rescue；未宣称放行或撤销成功",
            record.stage
        )));
    }
    record.stage = JournalStage::Committed;
    if store.save_permit(&record).is_err() {
        return Err(io::Error::other(
            "v3事务已提交但journal写回失败；请inspect或rescue recover撤销许可",
        ));
    }
    let engine = Engine::open()?;
    let mut tx = engine.transaction(true)?;
    let (after, extra) = observe(&engine)?;
    tx.commit()?;
    let evidence = model::assess(expected.as_ref(), &after, extra);
    if evidence.state != target {
        return Err(io::Error::other(
            "提交后实时回读与目标不符；结果未知，请inspect/rescue",
        ));
    }
    Ok(evidence)
}

/// Gate: ALE default-deny plus exact identity permits. The M2 packet BLOCK still stops all data.
pub fn install_gate(params: &Params, confirmation: &str) -> io::Result<model::Evidence> {
    if confirmation != model::GATE_INTENT {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "需要明确的ALE身份门安装意图",
        ));
    }
    let rules = model::plan(params).map_err(io::Error::other)?;
    super::wfp::require_rescue()?;
    apply(
        JournalAction::Gate,
        Some(params.clone()),
        |engine, current| {
            model::may_install_gate(wfp::m2_evidence(engine)?.state, current)
                .map_err(io::Error::other)
        },
        |engine, _| {
            add(
                engine,
                &rules
                    .iter()
                    .filter(|r| r.part == Part::Gate)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        },
        model::State::Gate,
    )
}

/// Final enabling step: only the four packet permits, only on an exact gate and full M2 baseline,
/// with no independent emergency barrier present. `tun_observed` must come from a fresh native
/// readback of this product's exclusive TUN by the caller.
pub fn open(
    params: &Params,
    confirmation: &str,
    tun_observed: bool,
) -> io::Result<model::Evidence> {
    if confirmation != model::OPEN_INTENT {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "需要明确的窄数据通路启用意图",
        ));
    }
    let rules = model::plan(params).map_err(io::Error::other)?;
    super::wfp::require_rescue()?;
    apply(
        JournalAction::Open,
        Some(params.clone()),
        |engine, current| {
            model::may_open(
                wfp::m2_evidence(engine)?.state,
                wfp::emergency_observe(engine)?.present(),
                current,
                tun_observed,
            )
            .map_err(io::Error::other)
        },
        |engine, _| {
            add(
                engine,
                &rules
                    .iter()
                    .filter(|r| r.part == Part::Packet)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        },
        model::State::Open,
    )
}

/// Removes every owned v3 object in one transaction. The M2 baseline is never touched, so the
/// result is the full block again. Absent → no-op. Foreign key owners → refuse, no wider delete.
pub fn revoke_all() -> io::Result<model::Evidence> {
    require_elevated_admin()?;
    {
        let engine = Engine::open()?;
        let mut tx = engine.transaction(true)?;
        let (seen, extra) = observe(&engine)?;
        tx.commit()?;
        if seen.is_empty() && !extra {
            return Ok(model::assess(None, &[], false));
        }
    }
    apply(
        JournalAction::Revoke,
        None,
        |_, _| Ok(()),
        |engine, seen| {
            for k in model::revoke_order(seen).map_err(io::Error::other)? {
                check(unsafe { FwpmFilterDeleteByKey0(engine.0, &gid(k)) })?;
            }
            Ok(())
        },
        model::State::Absent,
    )
}
