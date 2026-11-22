//! Only fixed LineGuard v2 objects may be mutated. Never called automatically.
use super::{
    security::{Descriptor, require_elevated_admin, wide},
    storage::Store,
};
use lineguard_core::guard::{self, Evidence, JournalStage, Layer, Lifetime};
use serde::Serialize;
use std::{
    ffi::OsStr,
    io, ptr,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_service::{
    service::{ServiceAccess, ServiceStartType},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::{
    Win32::{
        Foundation::{
            FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
        },
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
    core::GUID,
};

pub(super) const SERVICE: &str = "LineGuardPreview";
const _: () = assert!(FWPM_FILTER_FLAG_PERSISTENT == 1 && FWPM_FILTER_FLAG_BOOTTIME == 2);
pub(super) fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("WFP错误0x{code:08x}")))
    }
}
pub(super) fn conflict() -> io::Error {
    io::Error::other("产品GUID/版本或依赖冲突；未扩大修改范围，请独立inspect")
}
pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
pub(super) fn key(g: &GUID) -> u128 {
    ((g.data1 as u128) << 96)
        | ((g.data2 as u128) << 80)
        | ((g.data3 as u128) << 64)
        | u64::from_be_bytes(g.data4) as u128
}
pub(super) fn gid(value: u128) -> GUID {
    GUID::from_u128(value)
}
fn layer(layer: Layer) -> GUID {
    match layer {
        Layer::InV4 => FWPM_LAYER_INBOUND_IPPACKET_V4,
        Layer::InV6 => FWPM_LAYER_INBOUND_IPPACKET_V6,
        Layer::OutV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        Layer::OutV6 => FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        Layer::ForwardV4 => FWPM_LAYER_IPFORWARD_V4,
        Layer::ForwardV6 => FWPM_LAYER_IPFORWARD_V6,
    }
}
fn marker(blob: &FWP_BYTE_BLOB) -> bool {
    blob.size as usize == guard::MARKER.len()
        && !blob.data.is_null()
        && unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) } == guard::MARKER
}
fn blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: guard::MARKER.len() as u32,
        data: guard::MARKER.as_ptr().cast_mut(),
    }
}
pub(super) fn wide_matches(text: *const u16, expected: &str) -> bool {
    if text.is_null() {
        return false;
    }
    let expected = wide(expected);
    expected.len() < 256
        && expected
            .iter()
            .enumerate()
            .all(|(i, ch)| unsafe { *text.add(i) == *ch })
}
pub(super) struct Memory<T>(pub(super) *mut T);
impl<T> Drop for Memory<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FwpmFreeMemory0((&mut self.0 as *mut *mut T).cast());
            }
        }
    }
}
pub(super) struct Engine(pub(super) HANDLE);
impl Engine {
    pub(super) fn open() -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        let session = FWPM_SESSION0 {
            txnWaitTimeoutInMSec: 1000,
            ..Default::default()
        };
        check(unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut raw,
            )
        })?;
        Ok(Self(raw))
    }
    pub(super) fn transaction(&self, read_only: bool) -> io::Result<Transaction<'_>> {
        check(unsafe {
            FwpmTransactionBegin0(self.0, if read_only { FWPM_TXN_READ_ONLY } else { 0 })
        })?;
        Ok(Transaction {
            engine: self,
            active: true,
        })
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
pub(super) struct Transaction<'a> {
    engine: &'a Engine,
    active: bool,
}
impl Transaction<'_> {
    pub(super) fn commit(&mut self) -> io::Result<()> {
        check(unsafe { FwpmTransactionCommit0(self.engine.0) })?;
        self.active = false;
        Ok(())
    }
    pub(super) fn abort(&mut self) -> bool {
        let code = unsafe { FwpmTransactionAbort0(self.engine.0) };
        self.active = false;
        code == 0
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                FwpmTransactionAbort0(self.engine.0);
            }
        }
    }
}
pub(super) struct Enumeration<'a> {
    pub(super) engine: &'a Engine,
    pub(super) handle: HANDLE,
}
impl Drop for Enumeration<'_> {
    fn drop(&mut self) {
        unsafe {
            FwpmFilterDestroyEnumHandle0(self.engine.0, self.handle);
        }
    }
}

#[derive(Clone, Serialize)]
struct FilterSnapshot {
    key: String,
    id: u64,
    layer: String,
    flags: u32,
    action: u32,
    conditions: u32,
    weight: Option<u64>,
    effective_weight: Option<u64>,
    owned: bool,
    exact: bool,
}
pub(super) fn weight(value: &FWP_VALUE0) -> Option<u64> {
    if value.r#type == FWP_UINT64 && !unsafe { value.Anonymous.uint64 }.is_null() {
        Some(unsafe { *value.Anonymous.uint64 })
    } else {
        None
    }
}
impl FilterSnapshot {
    fn from_native(filter: &FWPM_FILTER0) -> Self {
        let owned = !filter.providerKey.is_null()
            && key(unsafe { &*filter.providerKey }) == guard::PROVIDER
            && key(&filter.subLayerKey) == guard::SUBLAYER
            && marker(&filter.providerData);
        let expected = guard::rules()
            .into_iter()
            .find(|r| r.key == key(&filter.filterKey));
        let exact = expected.is_some_and(|spec| {
            let expected_flags = if spec.lifetime == Lifetime::Persistent {
                FWPM_FILTER_FLAG_PERSISTENT
            } else {
                FWPM_FILTER_FLAG_BOOTTIME
            };
            // Boot objects may be disabled at runtime; that does not prove or disprove cold-boot execution.
            let flags = if spec.lifetime == Lifetime::Boot {
                filter.flags & !FWPM_FILTER_FLAG_DISABLED
            } else {
                filter.flags
            };
            owned
                && flags == expected_flags
                && key(&filter.layerKey) == key(&layer(spec.layer))
                && filter.numFilterConditions == 0
                && filter.action.r#type == FWP_ACTION_BLOCK
                && weight(&filter.weight) == Some(guard::FILTER_WEIGHT)
                && (spec.lifetime == Lifetime::Boot || filter.filterId != 0)
                && unsafe { filter.Anonymous.rawContext } == 0
        });
        Self {
            key: format!("{:032x}", key(&filter.filterKey)),
            id: filter.filterId,
            layer: format!("{:032x}", key(&filter.layerKey)),
            flags: filter.flags,
            action: filter.action.r#type,
            conditions: filter.numFilterConditions,
            weight: weight(&filter.weight),
            effective_weight: weight(&filter.effectiveWeight),
            owned,
            exact,
        }
    }
}
#[derive(Serialize)]
struct Observation {
    provider_present: bool,
    provider_owned: bool,
    provider_enabled: bool,
    sublayer_present: bool,
    sublayer_owned: bool,
    sublayer_exact: bool,
    service_ok: bool,
    filters: Vec<FilterSnapshot>,
    extra: bool,
}
impl Observation {
    fn evidence(&self) -> Evidence {
        let values: Vec<_> = self
            .filters
            .iter()
            .map(|f| (u128::from_str_radix(&f.key, 16).unwrap_or(0), f.exact))
            .collect();
        Evidence::assess(
            self.provider_present || self.sublayer_present,
            self.provider_owned && self.provider_enabled && self.sublayer_exact,
            self.service_ok,
            &values,
            self.extra,
            now(),
        )
    }
    fn can_mutate(&self) -> bool {
        (!self.provider_present || self.provider_owned)
            && (!self.sublayer_present || self.sublayer_owned)
            && !self.extra
            && self.filters.iter().all(|f| f.owned)
    }
}
fn service_ok() -> bool {
    let check = || {
        let manager =
            ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT).ok()?;
        let service = manager
            .open_service(SERVICE, ServiceAccess::QUERY_CONFIG)
            .ok()?;
        let config = service.query_config().ok()?;
        let account = config.account_name?.to_string_lossy().to_ascii_lowercase();
        let expected = std::env::current_exe()
            .ok()?
            .with_file_name("lineguard-service.exe");
        let configured = config.executable_path.to_string_lossy();
        let configured = configured
            .strip_prefix('"')
            .and_then(|p| p.strip_suffix('"'))
            .unwrap_or(&configured);
        Some(
            configured.eq_ignore_ascii_case(&expected.to_string_lossy())
                && config.start_type == ServiceStartType::AutoStart
                && (account == "localsystem" || account == "nt authority\\system"),
        )
    };
    check().unwrap_or(false)
}
fn observe(engine: &Engine) -> io::Result<Observation> {
    let mut state = Observation {
        provider_present: false,
        provider_owned: false,
        provider_enabled: false,
        sublayer_present: false,
        sublayer_owned: false,
        sublayer_exact: false,
        service_ok: false,
        filters: Vec::new(),
        extra: false,
    };
    let mut provider = Memory(ptr::null_mut::<FWPM_PROVIDER0>());
    let code = unsafe { FwpmProviderGetByKey0(engine.0, &gid(guard::PROVIDER), &mut provider.0) };
    if code == 0 {
        let p = unsafe { &*provider.0 };
        state.provider_present = true;
        state.provider_owned = marker(&p.providerData)
            && wide_matches(p.serviceName, SERVICE)
            && p.flags & !FWPM_PROVIDER_FLAG_DISABLED == FWPM_PROVIDER_FLAG_PERSISTENT;
        state.provider_enabled = p.flags & FWPM_PROVIDER_FLAG_DISABLED == 0;
        state.service_ok = service_ok();
    } else if code != FWP_E_PROVIDER_NOT_FOUND as u32 {
        check(code)?;
    }
    let mut sublayer = Memory(ptr::null_mut::<FWPM_SUBLAYER0>());
    let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &gid(guard::SUBLAYER), &mut sublayer.0) };
    if code == 0 {
        let sub = unsafe { &*sublayer.0 };
        state.sublayer_present = true;
        state.sublayer_owned = marker(&sub.providerData)
            && !sub.providerKey.is_null()
            && key(unsafe { &*sub.providerKey }) == guard::PROVIDER;
        state.sublayer_exact = state.sublayer_owned
            && sub.flags == FWPM_SUBLAYER_FLAG_PERSISTENT
            && sub.weight == guard::SUBLAYER_WEIGHT;
    } else if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
        check(code)?;
    }
    for spec in guard::rules() {
        let mut filter = Memory(ptr::null_mut::<FWPM_FILTER0>());
        let code = unsafe { FwpmFilterGetByKey0(engine.0, &gid(spec.key), &mut filter.0) };
        if code == 0 {
            state
                .filters
                .push(FilterSnapshot::from_native(unsafe { &*filter.0 }));
        } else if code != FWP_E_FILTER_NOT_FOUND as u32 {
            check(code)?;
        }
    }
    if state.provider_present {
        for layer_kind in guard::LAYERS {
            let mut provider_key = gid(guard::PROVIDER);
            let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                providerKey: &mut provider_key,
                layerKey: layer(layer_kind),
                enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
                flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME
                    | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
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
                    let observed = FilterSnapshot::from_native(unsafe { &**entry });
                    // v3 objects share the M2 parents by design and are assessed by `permit`;
                    // they are neither M2 rules nor unknown extras.
                    if lineguard_core::permit::is_permit_key(key(unsafe { &(**entry).filterKey })) {
                        continue;
                    }
                    if let Some(previous) = state.filters.iter().find(|f| f.key == observed.key) {
                        if previous.id != observed.id || previous.exact != observed.exact {
                            return Err(conflict());
                        }
                    } else {
                        if !guard::rules()
                            .iter()
                            .any(|r| format!("{:032x}", r.key) == observed.key)
                        {
                            state.extra = true;
                        }
                        state.filters.push(observed);
                    }
                }
            }
        }
    }
    Ok(state)
}
/// M2 evidence inside the caller's transaction (no nested session that could wait on it).
pub(super) fn m2_evidence(engine: &Engine) -> io::Result<Evidence> {
    Ok(observe(engine)?.evidence())
}
pub(super) fn inspect_m2() -> io::Result<Evidence> {
    let engine = Engine::open()?;
    let mut tx = engine.transaction(true)?;
    let state = observe(&engine)?;
    tx.commit()?;
    Ok(state.evidence())
}
pub fn detailed_inspect() -> io::Result<String> {
    let engine = Engine::open()?;
    let mut tx = engine.transaction(true)?;
    let objects = observe(&engine)?;
    let evidence = objects.evidence();
    tx.commit()?;
    #[derive(Serialize)]
    struct Report {
        evidence: Evidence,
        objects: Observation,
    }
    serde_json::to_string_pretty(&Report { evidence, objects }).map_err(io::Error::other)
}
fn remove_owned(engine: &Engine, before: &Observation) -> io::Result<()> {
    if !before.can_mutate() {
        return Err(conflict());
    }
    for filter in &before.filters {
        let id = u128::from_str_radix(&filter.key, 16).map_err(io::Error::other)?;
        if !guard::rules().iter().any(|spec| spec.key == id) {
            return Err(conflict());
        }
        check(unsafe { FwpmFilterDeleteByKey0(engine.0, &gid(id)) })?;
    }
    if before.sublayer_present {
        check(unsafe { FwpmSubLayerDeleteByKey0(engine.0, &gid(guard::SUBLAYER)) })?;
    }
    if before.provider_present {
        check(unsafe { FwpmProviderDeleteByKey0(engine.0, &gid(guard::PROVIDER)) })?;
    }
    Ok(())
}
fn install(engine: &Engine) -> io::Result<()> {
    let descriptor = Descriptor::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)")?;
    let mut provider_key = gid(guard::PROVIDER);
    let mut service = wide(SERVICE);
    let mut label = wide("LineGuard M2 - EXPERIMENTAL BLOCK ALL IP");
    let display = FWPM_DISPLAY_DATA0 {
        name: label.as_mut_ptr(),
        description: ptr::null_mut(),
    };
    let provider = FWPM_PROVIDER0 {
        providerKey: provider_key,
        displayData: display,
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: blob(),
        serviceName: service.as_mut_ptr(),
    };
    check(unsafe { FwpmProviderAdd0(engine.0, &provider, descriptor.raw()) })?;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: gid(guard::SUBLAYER),
        displayData: display,
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        providerData: blob(),
        weight: guard::SUBLAYER_WEIGHT,
    };
    check(unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, descriptor.raw()) })?;
    for spec in guard::rules() {
        let layer_key = layer(spec.layer);
        let mut platform_layer = Memory(ptr::null_mut::<FWPM_LAYER0>());
        check(unsafe { FwpmLayerGetByKey0(engine.0, &layer_key, &mut platform_layer.0) })?;
        if unsafe { (*platform_layer.0).flags } & FWPM_LAYER_FLAG_KERNEL == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "目标不是内核过滤层，拒绝降级安装",
            ));
        }
        let mut weight = guard::FILTER_WEIGHT;
        let filter = FWPM_FILTER0 {
            filterKey: gid(spec.key),
            displayData: display,
            flags: if spec.lifetime == Lifetime::Persistent {
                FWPM_FILTER_FLAG_PERSISTENT
            } else {
                FWPM_FILTER_FLAG_BOOTTIME
            },
            providerKey: &mut provider_key,
            providerData: blob(),
            layerKey: layer_key,
            subLayerKey: gid(guard::SUBLAYER),
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight,
                },
            },
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                ..Default::default()
            },
            ..Default::default()
        };
        check(unsafe { FwpmFilterAdd0(engine.0, &filter, descriptor.raw(), ptr::null_mut()) })?;
    }
    Ok(())
}
#[derive(Serialize)]
struct Journal {
    schema: u32,
    action: &'static str,
    stage: JournalStage,
    timestamp_ms: u64,
    before: Observation,
    transaction_objects: Option<Observation>,
    after: Option<Evidence>,
    error: Option<String>,
}

pub fn mutate(installing: bool, confirmation: &str, experimental_vm: bool) -> io::Result<Evidence> {
    require_elevated_admin()?;
    if (installing && (confirmation != "BLOCK-ALL-IP" || !experimental_vm))
        || (!installing && confirmation != "ALLOW-DIRECT")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "需要真实管理员权限和精确危险操作确认",
        ));
    }
    if installing {
        if !service_ok() {
            return Err(io::Error::other(
                "拒绝安装：必须预先具备LocalSystem/AutoStart的LineGuardPreview服务；程序不会替你安装或修改服务",
            ));
        }
        require_rescue()?;
    }
    let store = Store::guard_journal()?; // admin-only ACL and exclusive cross-process writer lock
    let engine = Engine::open()?;
    let mut tx = engine.transaction(false)?;
    let before = observe(&engine)?;
    if !before.can_mutate() {
        return Err(conflict());
    }
    if super::permit::any_present(&engine)? {
        return Err(io::Error::other(
            "存在v3许可对象；先由rescue recover撤销许可，M2基线不与许可混改",
        ));
    }
    let evidence = before.evidence();
    if (installing && evidence.state == guard::State::Configured)
        || (!installing && evidence.state == guard::State::Absent)
    {
        tx.abort();
        return Ok(evidence);
    }
    let mut record = Journal {
        schema: guard::POLICY_VERSION,
        action: if installing { "install" } else { "remove" },
        stage: JournalStage::Prepared,
        timestamp_ms: now(),
        before,
        transaction_objects: None,
        after: None,
        error: None,
    };
    store.save_journal(&record)?; // failure here leaves the original WFP transaction untouched
    let mut commit_attempted = false;
    let operation = (|| {
        remove_owned(&engine, &record.before)?;
        if installing {
            install(&engine)?;
        }
        let applied = observe(&engine)?;
        let after = applied.evidence();
        if (installing && after.state != guard::State::Configured)
            || (!installing && after.state != guard::State::Absent)
        {
            return Err(io::Error::other("事务内回读不完整（含boot规则），拒绝提交"));
        }
        record.transaction_objects = Some(applied);
        record.after = Some(after);
        commit_attempted = true;
        tx.commit()
    })();
    if let Err(error) = operation {
        let aborted = tx.abort();
        record.stage = guard::failed_mutation(commit_attempted, aborted);
        record.error = Some(error.to_string());
        let journal_ok = store.save_journal(&record).is_ok();
        return Err(io::Error::other(format!(
            "{error}；事务结果={:?}，journal记录={}。若不确定请inspect/独立rescue；未宣称解除或阻断成功",
            record.stage, journal_ok
        )));
    }
    record.stage = JournalStage::Committed;
    record.after = inspect_m2().ok();
    if store.save_journal(&record).is_err() {
        return Err(io::Error::other(
            "WFP已提交但journal最终写回失败；阻断可能生效，请inspect或独立rescue，不要重复盲目安装",
        ));
    }
    record.after.ok_or_else(|| {
        io::Error::other("WFP已提交，但提交后实时回读失败；结果未知，请独立inspect/rescue")
    })
}

// Independent recovery barrier: deliberately no SCM service binding and no boot claim.
const EM_PROVIDER: u128 = 0xa9b29c632a1a49c9ae644e4700050001;
const EM_SUBLAYER: u128 = 0xa9b29c632a1a49c9ae644e4700050002;
const EM_FILTER: u128 = 0xa9b29c632a1a49c9ae644e4700051000;
const EM_MARKER: &[u8] = b"LineGuard.Emergency.v3";
fn em_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: EM_MARKER.len() as u32,
        data: EM_MARKER.as_ptr().cast_mut(),
    }
}
fn em_marker(blob: &FWP_BYTE_BLOB) -> bool {
    blob.size as usize == EM_MARKER.len()
        && !blob.data.is_null()
        && unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) } == EM_MARKER
}
#[derive(Serialize)]
pub(super) struct Emergency {
    provider: bool,
    sublayer: bool,
    ids: Vec<(usize, u64)>,
}
impl Emergency {
    fn complete(&self) -> bool {
        self.provider && self.sublayer && self.ids.len() == 6
    }
    pub(super) fn present(&self) -> bool {
        self.provider || self.sublayer || !self.ids.is_empty()
    }
}
pub(super) fn emergency_observe(engine: &Engine) -> io::Result<Emergency> {
    let mut out = Emergency {
        provider: false,
        sublayer: false,
        ids: Vec::new(),
    };
    let mut p = Memory(ptr::null_mut::<FWPM_PROVIDER0>());
    let code = unsafe { FwpmProviderGetByKey0(engine.0, &gid(EM_PROVIDER), &mut p.0) };
    if code == 0 {
        let p = unsafe { &*p.0 };
        if !em_marker(&p.providerData)
            || p.flags != FWPM_PROVIDER_FLAG_PERSISTENT
            || !p.serviceName.is_null()
        {
            return Err(conflict());
        }
        out.provider = true;
    } else if code != FWP_E_PROVIDER_NOT_FOUND as u32 {
        check(code)?;
    }
    let mut s = Memory(ptr::null_mut::<FWPM_SUBLAYER0>());
    let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &gid(EM_SUBLAYER), &mut s.0) };
    if code == 0 {
        let s = unsafe { &*s.0 };
        if !em_marker(&s.providerData)
            || s.flags != FWPM_SUBLAYER_FLAG_PERSISTENT
            || s.providerKey.is_null()
            || key(unsafe { &*s.providerKey }) != EM_PROVIDER
            || s.weight != 0xfffe
        {
            return Err(conflict());
        }
        out.sublayer = true;
    } else if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
        check(code)?;
    }
    for (index, l) in guard::LAYERS.into_iter().enumerate() {
        let mut f = Memory(ptr::null_mut::<FWPM_FILTER0>());
        let code =
            unsafe { FwpmFilterGetByKey0(engine.0, &gid(EM_FILTER + index as u128 + 1), &mut f.0) };
        if code == 0 {
            let f = unsafe { &*f.0 };
            if !em_marker(&f.providerData)
                || f.providerKey.is_null()
                || key(unsafe { &*f.providerKey }) != EM_PROVIDER
                || key(&f.subLayerKey) != EM_SUBLAYER
                || key(&f.layerKey) != key(&layer(l))
                || f.flags != FWPM_FILTER_FLAG_PERSISTENT
                || f.action.r#type != FWP_ACTION_BLOCK
                || f.numFilterConditions != 0
                || weight(&f.weight) != Some(u64::MAX)
                || f.filterId == 0
                || unsafe { f.Anonymous.rawContext } != 0
            {
                return Err(conflict());
            }
            out.ids.push((index, f.filterId));
        } else if code != FWP_E_FILTER_NOT_FOUND as u32 {
            check(code)?;
        }
    }
    Ok(out)
}
pub fn ensure_closed() -> io::Result<Evidence> {
    require_elevated_admin()?;
    // Always use the separate unbound recovery provider. This never deletes a permit or baseline.
    let store = Store::guard_journal()?;
    let engine = Engine::open()?;
    let mut tx = engine.transaction(false)?;
    let before = emergency_observe(&engine)?;
    if !before.complete() {
        store
            .save_emergency(&serde_json::json!({"schema":1,"stage":"prepared","before":before}))?;
        let sd = Descriptor::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)")?;
        let mut provider = gid(EM_PROVIDER);
        let mut name = wide("LineGuard independent recovery BLOCK - UNVERIFIED");
        let display = FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        };
        if !before.provider {
            check(unsafe {
                FwpmProviderAdd0(
                    engine.0,
                    &FWPM_PROVIDER0 {
                        providerKey: provider,
                        displayData: display,
                        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                        providerData: em_blob(),
                        serviceName: ptr::null_mut(),
                    },
                    sd.raw(),
                )
            })?;
        }
        if !before.sublayer {
            check(unsafe {
                FwpmSubLayerAdd0(
                    engine.0,
                    &FWPM_SUBLAYER0 {
                        subLayerKey: gid(EM_SUBLAYER),
                        displayData: display,
                        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                        providerKey: &mut provider,
                        providerData: em_blob(),
                        weight: 0xfffe,
                    },
                    sd.raw(),
                )
            })?;
        }
        for (index, l) in guard::LAYERS.into_iter().enumerate() {
            if before.ids.iter().any(|(i, _)| *i == index) {
                continue;
            }
            let mut value = u64::MAX;
            let f = FWPM_FILTER0 {
                filterKey: gid(EM_FILTER + index as u128 + 1),
                displayData: display,
                flags: FWPM_FILTER_FLAG_PERSISTENT,
                providerKey: &mut provider,
                providerData: em_blob(),
                layerKey: layer(l),
                subLayerKey: gid(EM_SUBLAYER),
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_VALUE0_0 { uint64: &mut value },
                },
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_BLOCK,
                    ..Default::default()
                },
                ..Default::default()
            };
            check(unsafe { FwpmFilterAdd0(engine.0, &f, sd.raw(), ptr::null_mut()) })?;
        }
    }
    if !emergency_observe(&engine)?.complete() {
        return Err(conflict());
    }
    tx.commit()?;
    let after = emergency_observe(&engine)?;
    store
        .save_emergency(&serde_json::json!({"schema":1,"stage":"committed","objects":after}))
        .map_err(|_| {
            io::Error::other("独立阻断可能已提交但journal写入失败；未停止核心或恢复网络")
        })?;
    if !after.complete() {
        return Err(conflict());
    }
    Ok(emergency_evidence(&after))
}
fn emergency_evidence(e: &Emergency) -> Evidence {
    Evidence {
        policy_version: 3,
        state: if e.complete() {
            guard::State::Emergency
        } else {
            guard::State::Drift
        },
        observed_unix_ms: now(),
        persistent_rules: e.ids.len(),
        boot_rules: 0,
        expected_rules: 6,
        service_auto_system: false,
        enforcement_verified: false,
        detail: "独立救援持久阻断字段回读完整性；不依赖SCM，无boot或执行效果验证".into(),
    }
}
pub fn inspect() -> io::Result<Evidence> {
    let base = inspect_m2()?;
    let engine = Engine::open()?;
    let mut tx = engine.transaction(true)?;
    let em = emergency_observe(&engine)?;
    tx.commit()?;
    if em.present() {
        return Ok(emergency_evidence(&em));
    }
    Ok(super::permit::compose(base, &super::permit::inspect()?))
}
pub fn remove_emergency(confirmation: &str) -> io::Result<()> {
    require_elevated_admin()?;
    if confirmation != "ALLOW-DIRECT" {
        return Err(conflict());
    }
    let store = Store::guard_journal()?;
    let engine = Engine::open()?;
    let mut tx = engine.transaction(false)?;
    let before = emergency_observe(&engine)?;
    store.save_emergency(
        &serde_json::json!({"schema":1,"stage":"remove_prepared","before":before}),
    )?;
    for (index, _) in &before.ids {
        check(unsafe { FwpmFilterDeleteByKey0(engine.0, &gid(EM_FILTER + *index as u128 + 1)) })?;
    }
    if before.sublayer {
        check(unsafe { FwpmSubLayerDeleteByKey0(engine.0, &gid(EM_SUBLAYER)) })?;
    }
    if before.provider {
        check(unsafe { FwpmProviderDeleteByKey0(engine.0, &gid(EM_PROVIDER)) })?;
    }
    if emergency_observe(&engine)?.present() {
        return Err(conflict());
    }
    tx.commit()?;
    store.save_emergency(&serde_json::json!({"schema":1,"stage":"removed"}))?;
    Ok(())
}

pub(super) fn require_rescue() -> io::Result<()> {
    let rescue = std::env::current_exe()?.with_file_name("lineguard-rescue.exe");
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(rescue)?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let pe_offset = bytes
        .get(0x3c..0x40)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .map(|n| n as usize);
    let is_pe_x64 = bytes.starts_with(b"MZ")
        && pe_offset.and_then(|offset| bytes.get(offset..offset.saturating_add(6)))
            == Some(&b"PE\0\0\x64\x86"[..]);
    if bytes.len() > 8 * 1024 * 1024
        || !is_pe_x64
        || !bytes
            .windows(guard::RESCUE_MARKER.len())
            .any(|part| part == guard::RESCUE_MARKER.as_bytes())
    {
        return Err(io::Error::other(
            "先准备同目录M3 x64独立rescue（含网络恢复和阻断移除能力标记），拒绝只凭同名文件先封网",
        ));
    }
    Ok(())
}
