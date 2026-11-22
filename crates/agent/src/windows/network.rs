//! Native snapshots and exact owned-object recovery. No physical-adapter setters.
use super::{
    security::{self, wide},
    storage::Store,
    wfp,
};
use lineguard_core::network::{self as model, Interface, Lease, OwnedPost, Route, Stage, Undo};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::{
    Win32::{
        Devices::DeviceAndDriverInstallation::*,
        Foundation::{
            DEVPROPKEY, ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS, INVALID_HANDLE_VALUE,
        },
        NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
        Networking::WinSock::*,
        Security::Cryptography::*,
        System::{Com::CoCreateGuid, Registry::*},
    },
    core::GUID,
};
pub(super) fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
pub(super) fn conflict() -> io::Error {
    io::Error::other("网络后态/归属变化：保留阻断，拒绝覆盖用户或第三方改动")
}
pub(super) fn guid_text(g: &GUID) -> String {
    format!(
        "{:08x}{:04x}{:04x}{}",
        g.data1,
        g.data2,
        g.data3,
        g.data4
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
pub(super) fn guid(value: &str) -> io::Result<GUID> {
    Ok(GUID::from_u128(
        u128::from_str_radix(value, 16).map_err(|_| conflict())?,
    ))
}
fn utf16(value: &[u16]) -> String {
    String::from_utf16_lossy(&value[..value.iter().position(|c| *c == 0).unwrap_or(value.len())])
}
unsafe fn text_at(value: *const u16, max: usize) -> io::Result<String> {
    if value.is_null() {
        return Ok(String::new());
    }
    let mut n = 0;
    while n < max && unsafe { *value.add(n) } != 0 {
        n += 1;
    }
    if n == max {
        return Err(conflict());
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(value, n)
    }))
}
struct Mib<T>(*mut T);
impl<T> Drop for Mib<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0.cast()) }
        }
    }
}
pub(super) fn socket(ip: IpAddr) -> SOCKADDR_INET {
    let mut out = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(a) => {
            let mut v = SOCKADDR_IN::default();
            v.sin_family = AF_INET;
            v.sin_addr.S_un.S_addr = u32::from_ne_bytes(a.octets());
            out.Ipv4 = v;
        }
        IpAddr::V6(a) => {
            let mut v = SOCKADDR_IN6::default();
            v.sin6_family = AF_INET6;
            v.sin6_addr.u.Byte = a.octets();
            out.Ipv6 = v;
        }
    }
    out
}
pub(super) fn address(sa: &SOCKADDR_INET) -> io::Result<IpAddr> {
    match unsafe { sa.si_family } {
        AF_INET => Ok(IpAddr::V4(Ipv4Addr::from(
            unsafe { sa.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
        ))),
        AF_INET6 => Ok(IpAddr::V6(Ipv6Addr::from(unsafe {
            sa.Ipv6.sin6_addr.u.Byte
        }))),
        _ => Err(conflict()),
    }
}
fn socket_pointer(sa: SOCKET_ADDRESS) -> io::Result<IpAddr> {
    if sa.lpSockaddr.is_null() {
        return Err(conflict());
    }
    match unsafe { (*sa.lpSockaddr).sa_family } {
        AF_INET if sa.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 => {
            address(&SOCKADDR_INET {
                Ipv4: unsafe { *sa.lpSockaddr.cast::<SOCKADDR_IN>() },
            })
        }
        AF_INET6 if sa.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 => {
            address(&SOCKADDR_INET {
                Ipv6: unsafe { *sa.lpSockaddr.cast::<SOCKADDR_IN6>() },
            })
        }
        _ => Err(conflict()),
    }
}
pub(super) fn interfaces() -> io::Result<Vec<Interface>> {
    let mut bytes = 32 * 1024u32;
    for _ in 0..3 {
        if bytes > 1024 * 1024 {
            return Err(io::Error::other("接口快照超出边界"));
        }
        let mut buf = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                ptr::null(),
                first,
                &mut bytes,
            )
        };
        if code == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        check(code)?;
        let mut current = first;
        let mut result = Vec::new();
        while !current.is_null() {
            if result.len() >= 128 {
                return Err(conflict());
            }
            let a = unsafe { &*current };
            let mut id = GUID::from_u128(0);
            check(unsafe { ConvertInterfaceLuidToGuid(&a.Luid, &mut id) })?;
            let mut dns = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                if dns.len() >= 32 {
                    return Err(conflict());
                }
                let row = unsafe { &*d };
                dns.push(socket_pointer(row.Address)?);
                d = row.Next;
            }
            let mut unicast = Vec::new();
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                if unicast.len() >= 64 {
                    return Err(conflict());
                }
                let row = unsafe { &*u };
                unicast.push((socket_pointer(row.Address)?, row.OnLinkPrefixLength));
                u = row.Next;
            }
            dns.sort();
            dns.dedup();
            unicast.sort();
            unicast.dedup();
            result.push(Interface {
                guid: guid_text(&id),
                luid: unsafe { a.Luid.Value },
                alias: unsafe { text_at(a.FriendlyName, 1024) }?,
                dns,
                unicast,
                ipv6_enabled: unsafe { a.Anonymous2.Flags } & IP_ADAPTER_IPV6_ENABLED != 0,
                up: a.OperStatus == 1,
                mtu: a.Mtu,
            });
            current = a.Next;
        }
        result.sort_by(|a, b| a.guid.cmp(&b.guid));
        return Ok(result);
    }
    Err(io::Error::other("接口变化过快，拒绝不稳定快照"))
}
pub(super) fn routes() -> io::Result<Vec<Route>> {
    let mut table = Mib(ptr::null_mut::<MIB_IPFORWARD_TABLE2>());
    check(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table.0) })?;
    let t = unsafe { &*table.0 };
    if t.NumEntries > 4096 {
        return Err(conflict());
    }
    let mut result = Vec::new();
    for r in unsafe { std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize) } {
        result.push(Route {
            destination: address(&r.DestinationPrefix.Prefix)?,
            prefix: r.DestinationPrefix.PrefixLength,
            luid: unsafe { r.InterfaceLuid.Value },
            next_hop: address(&r.NextHop)?,
            metric: r.Metric,
            protocol: r.Protocol,
            site_prefix: r.SitePrefixLength,
            valid_lifetime: r.ValidLifetime,
            preferred_lifetime: r.PreferredLifetime,
            loopback: r.Loopback,
            autoconfigure: r.AutoconfigureAddress,
            publish: r.Publish,
            immortal: r.Immortal,
        });
    }
    result.sort_by_key(|r| format!("{}:{}:{}:{}", r.luid, r.destination, r.prefix, r.next_hop));
    Ok(result)
}
fn native_route(r: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: r.luid };
    row.DestinationPrefix.Prefix = socket(r.destination);
    row.DestinationPrefix.PrefixLength = r.prefix;
    row.NextHop = socket(r.next_hop);
    row.Metric = r.metric;
    row.Protocol = r.protocol;
    row.SitePrefixLength = r.site_prefix;
    row.ValidLifetime = r.valid_lifetime;
    row.PreferredLifetime = r.preferred_lifetime;
    row.Loopback = r.loopback;
    row.AutoconfigureAddress = r.autoconfigure;
    row.Publish = r.publish;
    row.Immortal = r.immortal;
    row
}
pub(super) fn physical_for(ip: Ipv4Addr) -> io::Result<Interface> {
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    check(unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &socket(IpAddr::V4(ip)),
            0,
            &mut route,
            &mut source,
        )
    })?;
    let mut row = MIB_IF_ROW2::default();
    row.InterfaceLuid = route.InterfaceLuid;
    check(unsafe { GetIfEntry2(&mut row) })?;
    if !matches!(row.Type, 6 | 71)
        || row.OperStatus != 1
        || row.InterfaceAndOperStatusFlags._bitfield & 1 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "只支持实际以太网/Wi-Fi物理出口的独占实验环境",
        ));
    }
    interfaces()?
        .into_iter()
        .find(|i| i.luid == unsafe { route.InterfaceLuid.Value })
        .ok_or_else(conflict)
}
struct Devices(HDEVINFO);
impl Drop for Devices {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
#[derive(Clone)]
pub(super) struct Device {
    pub instance: String,
    pub name: String,
    pub guid: Option<String>,
}
fn property(set: HDEVINFO, row: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> io::Result<String> {
    let mut buf = [0u16; 512];
    let mut kind = 0;
    let mut needed = 0;
    if unsafe {
        SetupDiGetDevicePropertyW(
            set,
            row,
            key,
            &mut kind,
            buf.as_mut_ptr().cast(),
            size_of_val(&buf) as u32,
            &mut needed,
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if kind != 0x12 || needed > size_of_val(&buf) as u32 {
        return Err(conflict());
    }
    Ok(utf16(&buf))
}
fn device_guid(set: HDEVINFO, row: &SP_DEVINFO_DATA) -> io::Result<Option<String>> {
    let key =
        unsafe { SetupDiOpenDevRegKey(set, row, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE) };
    if key == INVALID_HANDLE_VALUE {
        return Ok(None);
    }
    let key = Key(key);
    let mut value = [0u16; 64];
    let mut bytes = size_of_val(&value) as u32;
    let code = unsafe {
        RegGetValueW(
            key.0,
            ptr::null(),
            wide("NetCfgInstanceId").as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if code == 2 {
        return Ok(None);
    }
    check(code)?;
    let id = utf16(&value)
        .replace(['{', '}', '-'], "")
        .to_ascii_lowercase();
    guid(&id)?;
    Ok(Some(id))
}
fn enumerate(
    mut visit: impl FnMut(HDEVINFO, &SP_DEVINFO_DATA, &Device) -> io::Result<()>,
) -> io::Result<()> {
    let set = unsafe { SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, ptr::null(), ptr::null_mut(), 0) };
    if set == INVALID_HANDLE_VALUE as isize {
        return Err(io::Error::last_os_error());
    }
    let set = Devices(set);
    for index in 0..1024 {
        let mut row = SP_DEVINFO_DATA::default();
        row.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
        if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut row) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                return Ok(());
            }
            return Err(e);
        }
        let mut hardware = [0u16; 1024];
        let mut needed = 0;
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set.0,
                &row,
                SPDRP_HARDWAREID,
                ptr::null_mut(),
                hardware.as_mut_ptr().cast(),
                size_of_val(&hardware) as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            if matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(13) | Some(2)
            ) {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if needed > size_of_val(&hardware) as u32 {
            return Err(conflict());
        }
        let wintun = hardware
            .split(|c| *c == 0)
            .filter(|v| !v.is_empty())
            .any(|v| {
                let s = String::from_utf16_lossy(v);
                s.eq_ignore_ascii_case("Wintun") || s.eq_ignore_ascii_case(r"SWD\Wintun")
            });
        if !wintun {
            continue;
        }
        let mut instance = [0u16; 512];
        if unsafe {
            SetupDiGetDeviceInstanceIdW(
                set.0,
                &row,
                instance.as_mut_ptr(),
                instance.len() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let key = DEVPROPKEY {
            fmtid: GUID::from_u128(0x3361c968_2f2e_4660_b47e_699cdc4c32b9),
            pid: 3,
        };
        let name = property(set.0, &row, &key)?;
        let d = Device {
            instance: utf16(&instance),
            name,
            guid: device_guid(set.0, &row)?,
        };
        visit(set.0, &row, &d)?;
    }
    Err(io::Error::other("设备枚举超出边界"))
}
pub(super) fn wintun_devices() -> io::Result<Vec<Device>> {
    let mut all = Vec::new();
    enumerate(|_, _, d| {
        all.push(d.clone());
        Ok(())
    })?;
    Ok(all)
}
pub(super) fn expected_guid(alias: &str) -> io::Result<String> {
    let mut algorithm = ptr::null_mut();
    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_MD5_ALGORITHM, ptr::null(), 0)
    };
    if status < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "无法计算上游兼容接口GUID（系统MD5策略）",
        ));
    }
    struct Algorithm(BCRYPT_ALG_HANDLE);
    impl Drop for Algorithm {
        fn drop(&mut self) {
            unsafe {
                BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }
    let algorithm = Algorithm(algorithm);
    let data = format!("wintun{alias}");
    let mut bytes = [0u8; 16];
    if unsafe {
        BCryptHash(
            algorithm.0,
            ptr::null(),
            0,
            data.as_ptr(),
            data.len() as u32,
            bytes.as_mut_ptr(),
            16,
        )
    } < 0
    {
        return Err(conflict());
    }
    Ok(guid_text(&GUID {
        data1: u32::from_le_bytes(bytes[..4].try_into().map_err(|_| conflict())?),
        data2: u16::from_le_bytes(bytes[4..6].try_into().map_err(|_| conflict())?),
        data3: u16::from_le_bytes(bytes[6..8].try_into().map_err(|_| conflict())?),
        data4: bytes[8..].try_into().map_err(|_| conflict())?,
    }))
}
pub(super) fn prepare(generation: u64, index: usize) -> io::Result<Lease> {
    if !wintun_devices()?.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "独占实验模式拒绝任何现有/幽灵Wintun设备；不复用或清理其他VPN网卡",
        ));
    }
    let mut nonce = GUID::from_u128(0);
    if unsafe { CoCreateGuid(&mut nonce) } < 0 {
        return Err(conflict());
    }
    let nonce = guid_text(&nonce);
    let id = expected_guid(&format!("LG-{nonce}"))?;
    let physical = interfaces()?;
    if physical
        .iter()
        .any(|i| i.guid == id || i.alias.eq_ignore_ascii_case(&format!("LG-{nonce}")))
    {
        return Err(conflict());
    }
    let routes = routes()?;
    if routes.len() > 512 {
        return Err(conflict());
    }
    Ok(Lease::new(nonce, id, generation, index, physical, routes))
}
pub(super) fn owned(lease: &Lease) -> io::Result<Option<(Device, Option<OwnedPost>)>> {
    if expected_guid(&lease.alias)? != lease.guid {
        return Err(conflict());
    }
    let devices = wintun_devices()?;
    let mut result = None;
    for d in devices {
        if d.name == lease.alias || d.guid.as_deref() == Some(&lease.guid) {
            if result.is_some()
                || d.name != lease.alias
                || d.guid.as_ref().is_some_and(|g| g != &lease.guid)
                || lease
                    .instance_id
                    .as_ref()
                    .is_some_and(|id| id != &d.instance)
            {
                return Err(conflict());
            }
            let interface = interfaces()?.into_iter().find(|i| i.guid == lease.guid);
            let post = if let Some(i) = interface {
                if i.alias != lease.alias || lease.owned_luid.is_some_and(|l| l != i.luid) {
                    return Err(conflict());
                }
                let routes = routes()?.into_iter().filter(|r| r.luid == i.luid).collect();
                Some(OwnedPost {
                    interface: i,
                    routes,
                })
            } else {
                None
            };
            result = Some((d, post));
        } else {
            return Err(io::Error::other(
                "出现外来Wintun设备；停止独占实验，不做全局孤儿清理",
            ));
        }
    }
    Ok(result)
}
pub(super) fn add_routes(store: &Store, lease: &mut Lease) -> io::Result<()> {
    let (_, post) = owned(lease)?.ok_or_else(conflict)?;
    let post = post.ok_or_else(conflict)?;
    lease.owned_luid = Some(post.interface.luid);
    lease.stage = Stage::RoutesApplying;
    for second in [false, true] {
        let route = Route::default_half(post.interface.luid, second);
        if routes()?.iter().any(|r| r.same_key(&route)) {
            return Err(conflict());
        }
        lease.added_routes.push(route.clone());
        store.save_network(lease)?; // write ahead of Create
        check(unsafe { CreateIpForwardEntry2(&native_route(&route)) })?;
        let current = routes()?.into_iter().find(|r| r.same_key(&route));
        if current.as_ref() != Some(&route) {
            return Err(conflict());
        }
    }
    let (_, post) = owned(lease)?.ok_or_else(conflict)?;
    lease.expected_after = post;
    lease.stage = Stage::Quarantined;
    store.save_network(lease)
}
fn acceptable(lease: &Lease, post: &OwnedPost) -> bool {
    match &lease.expected_after {
        Some(expected) => {
            if expected.interface != post.interface {
                return false;
            }
            let without_added = |rows: &[Route]| {
                rows.iter()
                    .filter(|r| !lease.added_routes.iter().any(|a| a.same_key(r)))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            without_added(&expected.routes) == without_added(&post.routes)
                && lease.added_routes.iter().all(|r| {
                    model::undo_route(r, post.routes.iter().find(|x| x.same_key(r)))
                        != Undo::Conflict
                })
        }
        None => model::partial_footprint(lease, &post.interface, &post.routes),
    }
}
pub(super) fn precheck_restore(lease: &Lease) -> io::Result<()> {
    if let Some((_, Some(post))) = owned(lease)? {
        if !acceptable(lease, &post) {
            return Err(conflict());
        }
    }
    let now = routes()?;
    for (index, r) in lease.added_routes.iter().enumerate() {
        if model::undo_with_progress(
            r,
            now.iter().find(|x| x.same_key(r)),
            index < lease.restored_routes,
        ) == Undo::Conflict
        {
            return Err(conflict());
        }
    }
    Ok(())
}
pub(super) fn restore(store: &Store, lease: &mut Lease) -> io::Result<()> {
    precheck_restore(lease)?;
    lease.stage = Stage::Restoring;
    store.save_network(lease)?;
    for index in lease.restored_routes..lease.added_routes.len() {
        let expected = &lease.added_routes[index];
        let now = routes()?;
        match model::undo_route(expected, now.iter().find(|r| r.same_key(expected))) {
            Undo::Conflict => return Err(conflict()),
            Undo::AlreadyAbsent => {}
            Undo::DeleteExact => check(unsafe { DeleteIpForwardEntry2(&native_route(expected)) })?,
        }
        lease.restored_routes = index + 1;
        store.save_network(lease)?;
    }
    // The core may already have lost its SwDevice handle and Windows may have removed the TUN.
    if let Some((device, post)) = owned(lease)? {
        if let Some(post) = post {
            if !acceptable(lease, &post) {
                return Err(conflict());
            }
        }
        enumerate(|set, row, d| {
            if d.instance != device.instance {
                return Ok(());
            }
            if d.name != lease.alias || d.guid.as_ref().is_some_and(|g| g != &lease.guid) {
                return Err(conflict());
            }
            let mut remove = SP_REMOVEDEVICE_PARAMS::default();
            remove.ClassInstallHeader.cbSize = size_of::<SP_CLASSINSTALL_HEADER>() as u32;
            remove.ClassInstallHeader.InstallFunction = DIF_REMOVE;
            remove.Scope = DI_REMOVEDEVICE_GLOBAL;
            if unsafe {
                SetupDiSetClassInstallParamsW(
                    set,
                    row,
                    &remove.ClassInstallHeader,
                    size_of_val(&remove) as u32,
                )
            } == 0
                || unsafe { SetupDiCallClassInstaller(DIF_REMOVE, set, row) } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
        if owned(lease)?.is_some() {
            return Err(io::Error::other(
                "适配器移除尚未完成/需重启，保留journal与阻断",
            ));
        }
    }
    lease.stage = Stage::Restored;
    lease.last_error = None;
    store.save_network(lease)
}

pub fn recover(confirmation: &str, allow_direct: bool) -> io::Result<String> {
    security::require_elevated_admin()?;
    if confirmation != model::RECOVER_INTENT {
        return Err(io::Error::other("缺少明确恢复意图"));
    }
    // Exclusive writer lock is shared with the daemon and ordinary guard removal.
    // Confirm the independent barrier before stopping the daemon or reading an untrusted journal.
    wfp::ensure_closed()?;
    // With the unconditional independent barrier in place, removing v3 permits cannot open
    // anything; do it before touching the core or routes so no permit outlives this recovery.
    super::permit::revoke_all()?;
    let store = match Store::network_journal(true) {
        Ok(store) => store,
        Err(e) if matches!(e.raw_os_error(), Some(32 | 33)) => {
            super::engine::stop_service_owner()?;
            Store::network_journal(true)?
        }
        Err(e) => return Err(e),
    };
    if let Some(mut lease) = store.load_network()? {
        if lease.stage != Stage::Restored {
            let result = (|| {
                precheck_restore(&lease)?;
                super::engine::stop_recorded_job(&lease)?;
                restore(&store, &mut lease)
            })();
            if let Err(e) = result {
                lease.stage = Stage::Conflict;
                lease.last_error = Some("独立恢复未完成；可能有后续修改，阻断保持".into());
                store.save_network(&lease)?;
                return Err(e);
            }
        }
    }
    if allow_direct {
        // Both namespaces are ours; keep the standalone barrier until M2 removal is confirmed.
        super::wfp::mutate(false, "ALLOW-DIRECT", false)?;
        wfp::remove_emergency("ALLOW-DIRECT")?;
        if wfp::inspect()?.state != lineguard_core::guard::State::Absent {
            return Err(conflict());
        }
        Ok("已按所有权及后态检查恢复本产品网络；显式移除两套产品阻断。未重置系统/第三方配置；未验证联网效果".into())
    } else {
        Ok(
            "本产品网络恢复完成；独立持久阻断仍保留。未撤销其他产品规则，未恢复用户后来改动的配置"
                .into(),
        )
    }
}

pub(crate) fn removal_lock() -> io::Result<Store> {
    let store = Store::network_journal(true)?;
    if store
        .load_network()?
        .is_some_and(|l| l.stage != Stage::Restored)
    {
        return Err(io::Error::other(
            "存在未恢复网络journal；先执行独立rescue recover",
        ));
    }
    Ok(store)
}
