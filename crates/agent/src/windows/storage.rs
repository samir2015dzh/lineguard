use super::security::{Descriptor, Identity, sid_string, wide};
use crate::Endpoint;
use lineguard_core::{Config, MAX_IMPORT};
use std::{
    ffi::c_void,
    fs,
    io::{self, Read, Write},
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, LocalFree},
    Security::{
        Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW},
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_WRITE, GetFileAttributesW,
        INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        OPEN_ALWAYS,
    },
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath},
};
const MAX_ENCRYPTED: u64 = (MAX_IMPORT + 8192) as u64;
fn path_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn folder(console: bool) -> io::Result<PathBuf> {
    let mut text = ptr::null_mut();
    let id = if console {
        &FOLDERID_LocalAppData
    } else {
        &FOLDERID_ProgramData
    };
    // KF_FLAG_DONT_VERIFY: retrieve the configured name without touching a remote redirect.
    if unsafe { SHGetKnownFolderPath(id, 0x4000, ptr::null_mut(), &mut text) } < 0 {
        return Err(io::Error::other("无法读取系统目录"));
    }
    let mut len = 0;
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    let path = PathBuf::from(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, len)
    }));
    unsafe {
        CoTaskMemFree(text.cast());
    }
    let mut components = path.components();
    if !matches!(components.next(),Some(std::path::Component::Prefix(p)) if matches!(p.kind(),std::path::Prefix::Disk(_)))
        || !matches!(components.next(), Some(std::path::Component::RootDir))
    {
        return Err(io::Error::other("数据根目录必须是普通本地盘路径"));
    }
    let root: PathBuf = path.components().take(2).collect();
    let kind = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(path_wide(&root).as_ptr())
    };
    if !matches!(kind, 2 | 3 | 5 | 6) {
        return Err(io::Error::other("拒绝网络/未知类型数据盘"));
    }
    Ok(path.join(if console {
        "LineGuardPreviewConsole"
    } else {
        "LineGuardPreview"
    }))
}
fn reject_reparse(path: &Path) -> io::Result<bool> {
    let attrs = unsafe { GetFileAttributesW(path_wide(path).as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            return Ok(false);
        }
        return Err(error);
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("拒绝重解析路径"));
    }
    Ok(true)
}
fn ensure_owner(path: &Path, endpoint: Endpoint, identity: &Identity) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            path_wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let sid = sid_string(owner);
    unsafe {
        LocalFree(descriptor);
    }
    let sid = sid?;
    if (endpoint.console && sid == identity.user)
        || (!endpoint.console && (sid == "S-1-5-18" || sid == "S-1-5-32-544"))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "数据目录所有者不可信",
        ))
    }
}
fn harden(path: &Path, descriptor: &Descriptor) -> io::Result<()> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.raw(), &mut present, &mut acl, &mut defaulted)
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err(io::Error::other("ACL 无效"));
    }
    let code = unsafe {
        SetNamedSecurityInfoW(
            path_wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        )
    };
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
/// Offline import deliberately refuses network/device prefixes and reparse ancestors.
fn local_import_path(source: &Path) -> io::Result<PathBuf> {
    use std::path::{Component, Prefix};
    let absolute = if source.is_absolute() {
        source.to_path_buf()
    } else {
        std::env::current_dir()?.join(source)
    };
    let mut components = absolute.components();
    if !matches!(components.next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        return Err(io::Error::other(
            "仅接受本地普通盘路径，拒绝UNC/设备/特殊前缀",
        ));
    }
    let mut current = PathBuf::new();
    for c in absolute.components().take(2) {
        current.push(c.as_os_str());
    }
    let drive = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(path_wide(&current).as_ptr())
    };
    if !matches!(drive, 2 | 3 | 5 | 6) {
        return Err(io::Error::other("拒绝网络或未知类型的导入盘"));
    }
    for component in components {
        let Component::Normal(name) = component else {
            return Err(io::Error::other("拒绝父路径和特殊路径组件"));
        };
        current.push(name);
        if !reject_reparse(&current)? {
            return Err(io::ErrorKind::NotFound.into());
        }
    }
    Ok(absolute)
}

pub struct Store {
    directory: PathBuf,
    descriptor: Descriptor,
    endpoint: Endpoint,
    _writer: Option<super::security::Handle>,
}
impl Store {
    pub fn open_readonly(endpoint: Endpoint, identity: &Identity) -> io::Result<Self> {
        Self::prepare(endpoint, identity, false)
    }
    pub fn open(endpoint: Endpoint, identity: &Identity) -> io::Result<Self> {
        Self::prepare(endpoint, identity, true)
    }
    fn prepare(endpoint: Endpoint, identity: &Identity, create: bool) -> io::Result<Self> {
        Self::prepare_at(endpoint, identity, create, folder(endpoint.console)?)
    }
    pub fn guard_journal() -> io::Result<Self> {
        let identity = Identity::current()?;
        Self::prepare_at(
            Endpoint { console: false },
            &identity,
            true,
            folder(false)?.with_file_name("LineGuardGuardPreview"),
        )
    }
    pub fn network_journal(create: bool) -> io::Result<Self> {
        Self::prepare_at(
            Endpoint { console: false },
            &Identity::current()?,
            create,
            folder(false)?.with_file_name("LineGuardNetworkPreview"),
        )
    }
    pub fn save_network(&self, lease: &lineguard_core::network::Lease) -> io::Result<()> {
        let bytes = lease.encode().map_err(io::Error::other)?;
        self.atomic_write("network-journal.json", &bytes)
    }
    pub fn load_network(&self) -> io::Result<Option<lineguard_core::network::Lease>> {
        use std::os::windows::fs::OpenOptionsExt;
        let path = self.directory.join("network-journal.json");
        if !self.directory.exists() || !reject_reparse(&path)? {
            return Ok(None);
        }
        ensure_owner(&path, self.endpoint, &Identity::current()?)?;
        let mut bytes = Vec::new();
        fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(path)?
            .take((lineguard_core::network::MAX_JOURNAL + 1) as u64)
            .read_to_end(&mut bytes)?;
        lineguard_core::network::Lease::decode(&bytes)
            .map(Some)
            .map_err(io::Error::other)
    }
    pub fn core_inbox() -> io::Result<Self> {
        let identity = Identity::current()?;
        Self::prepare_at(
            Endpoint { console: false },
            &identity,
            true,
            folder(false)?.with_file_name("LineGuardCoreInboxPreview"),
        )
    }
    pub fn core_assets(create: bool) -> io::Result<Self> {
        let identity = Identity::current()?;
        Self::prepare_at(
            Endpoint { console: false },
            &identity,
            create,
            folder(false)?.with_file_name("LineGuardCorePreview"),
        )
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn verified_core(
        &self,
        pin: &lineguard_core::engine::CorePin,
    ) -> io::Result<(fs::File, PathBuf)> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let path = self.directory.join("mihomo.exe");
        if !reject_reparse(&path)? {
            return Err(io::ErrorKind::NotFound.into());
        }
        ensure_owner(&path, self.endpoint, &Identity::current()?)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() != pin.executable_size
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::other("拒绝非普通核心文件"));
        }
        lineguard_core::engine::verify_reader(&mut file, pin)?;
        // Keep this deny-write/delete handle alive until the child has exited.
        Ok((file, path))
    }
    pub fn import_core(
        &self,
        source: &Path,
        pin: &lineguard_core::engine::CorePin,
    ) -> io::Result<()> {
        use std::{
            io::{Seek, SeekFrom},
            os::windows::fs::{MetadataExt, OpenOptionsExt},
        };
        let source = local_import_path(source)?;
        let mut input = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&source)?;
        let metadata = input.metadata()?;
        if metadata.len() != pin.executable_size {
            return Err(io::Error::other("核心大小不符；未读取内容"));
        }
        if !metadata.is_file()
            || metadata.len() != pin.executable_size
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::other("仅接受普通核心文件"));
        }
        lineguard_core::engine::verify_reader(&mut input, pin)?;
        input.seek(SeekFrom::Start(0))?;
        let target = self.directory.join("mihomo.exe");
        reject_reparse(&target)?;
        let temp = self
            .directory
            .join(format!("core.{}.tmp", std::process::id()));
        let attributes = self.descriptor.attributes();
        let handle = super::security::Handle::new(unsafe {
            CreateFileW(
                path_wide(&temp).as_ptr(),
                windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        })?;
        let result = (|| {
            let mut output = unsafe { fs::File::from_raw_handle(handle.0) };
            std::mem::forget(handle);
            let copied = io::copy(&mut input.take(pin.executable_size + 1), &mut output)?;
            if copied != pin.executable_size {
                return Err(io::Error::other("核心复制不完整"));
            }
            output.sync_all()?;
            output.seek(SeekFrom::Start(0))?;
            lineguard_core::engine::verify_reader(&mut output, pin)?;
            drop(output);
            if unsafe {
                MoveFileExW(
                    path_wide(&temp).as_ptr(),
                    path_wide(&target).as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
    fn prepare_at(
        endpoint: Endpoint,
        identity: &Identity,
        create: bool,
        directory: PathBuf,
    ) -> io::Result<Self> {
        let sddl = if endpoint.console {
            format!(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{})",
                identity.user
            )
        } else {
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".into()
        };
        let descriptor = Descriptor::new(&sddl)?;
        if create {
            let attributes = descriptor.attributes();
            if unsafe { CreateDirectoryW(path_wide(&directory).as_ptr(), &attributes) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                    return Err(error);
                }
            }
        }
        if reject_reparse(&directory)? {
            let attrs = unsafe { GetFileAttributesW(path_wide(&directory).as_ptr()) };
            if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(io::Error::other("非数据目录"));
            }
            ensure_owner(&directory, endpoint, identity)?;
            if create {
                harden(&directory, &descriptor)?;
            }
        }
        let writer = if create {
            let lock = directory.join("writer.lock");
            reject_reparse(&lock)?;
            let attributes = descriptor.attributes();
            Some(super::security::Handle::new(unsafe {
                CreateFileW(
                    path_wide(&lock).as_ptr(),
                    FILE_GENERIC_WRITE,
                    0,
                    &attributes,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                )
            })?)
        } else {
            None
        };
        Ok(Self {
            directory,
            descriptor,
            endpoint,
            _writer: writer,
        })
    }
    pub fn load(&self) -> io::Result<Option<(Config, u64)>> {
        let file = self.directory.join("config.dpapi");
        // Absent parent is legitimate on a fresh readonly inspection.
        if !self.directory.exists() {
            return Ok(None);
        }
        if !reject_reparse(&file)? {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        fs::File::open(file)?
            .take(MAX_ENCRYPTED + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_ENCRYPTED {
            return Err(io::Error::other("密文过大"));
        }
        let mut clear = crypt(&bytes, false, self.endpoint.console)?;
        let result = (|| {
            if clear.len() < 8 || clear.len() > MAX_IMPORT + 8 {
                return Err(io::Error::other("存储格式无效"));
            }
            let generation = u64::from_le_bytes(clear[..8].try_into().map_err(io::Error::other)?);
            let config = Config::parse(&clear[8..]).map_err(io::Error::other)?;
            Ok(Some((config, generation)))
        })();
        lineguard_core::wipe(&mut clear);
        result
    }
    pub fn save(&self, config: &Config, generation: u64) -> io::Result<()> {
        config.validate().map_err(io::Error::other)?;
        let mut clear = generation.to_le_bytes().to_vec();
        serde_json::to_writer(&mut clear, config)
            .map_err(|_| io::Error::other("无法序列化配置"))?;
        if clear.len() > MAX_IMPORT + 8 {
            lineguard_core::wipe(&mut clear);
            return Err(io::Error::other("配置过大"));
        }
        let encrypted = crypt(&clear, true, self.endpoint.console);
        lineguard_core::wipe(&mut clear);
        let encrypted = encrypted?;
        self.atomic_write("config.dpapi", &encrypted)
    }
    pub fn save_emergency(&self, document: &impl serde::Serialize) -> io::Result<()> {
        self.save_json("emergency-journal.json", document)
    }
    pub fn save_journal(&self, document: &impl serde::Serialize) -> io::Result<()> {
        self.save_json("guard-journal.json", document)
    }
    pub fn save_core_receipt(&self, document: &impl serde::Serialize) -> io::Result<()> {
        self.save_json("core-receipt.json", document)
    }
    pub fn core_license_confirmed(
        &self,
        pin: &lineguard_core::engine::CorePin,
    ) -> io::Result<bool> {
        use std::os::windows::fs::OpenOptionsExt;
        let receipt = self.directory.join("core-receipt.json");
        if !reject_reparse(&receipt)? {
            return Ok(false);
        }
        ensure_owner(&receipt, self.endpoint, &Identity::current()?)?;
        let mut data = Vec::new();
        fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(receipt)?
            .take(8193)
            .read_to_end(&mut data)?;
        if data.len() > 8192 {
            return Err(io::Error::other("许可收据过大"));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&data).map_err(|_| io::Error::other("许可收据无效"))?;
        Ok(v["schema"] == 1
            && v["core_version"] == pin.version
            && v["sha256"] == pin.executable_sha256
            && v["licenses_explicitly_confirmed"] == true
            && v["executed"] == false
            && v["tunnel_enabled"] == false)
    }
    fn save_json(&self, name: &'static str, document: &impl serde::Serialize) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(document).map_err(io::Error::other)?;
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::other("记录过大"));
        }
        self.atomic_write(name, &bytes)
    }
    fn atomic_write(&self, name: &'static str, bytes: &[u8]) -> io::Result<()> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let temporary = self
            .directory
            .join(format!("{name}.{}.{stamp}.tmp", std::process::id()));
        let target = self.directory.join(name);
        let attributes = self.descriptor.attributes();
        let raw = unsafe {
            CreateFileW(
                path_wide(&temporary).as_ptr(),
                FILE_GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        let handle = super::security::Handle::new(raw)?;
        let mut file = unsafe { fs::File::from_raw_handle(handle.0) };
        std::mem::forget(handle);
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if unsafe {
                MoveFileExW(
                    path_wide(&temporary).as_ptr(),
                    path_wide(&target).as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}
fn crypt(input: &[u8], protect: bool, console: bool) -> io::Result<Vec<u8>> {
    let data = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr().cast_mut(),
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    let flags = CRYPTPROTECT_UI_FORBIDDEN
        | if protect && !console {
            CRYPTPROTECT_LOCAL_MACHINE
        } else {
            0
        };
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &data,
                wide("LineGuard configuration v1").as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                flags,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &data,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                flags,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        if !protect {
            lineguard_core::wipe(std::slice::from_raw_parts_mut(
                output.pbData,
                output.cbData as usize,
            ));
        }
        LocalFree(output.pbData.cast::<c_void>());
        Ok(result)
    }
}
