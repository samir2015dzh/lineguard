use crate::Endpoint;
use std::{ffi::c_void, io, ptr};
const SE_GROUP_LOGON_ID: u32 = 0xC0000000;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
        TokenGroups, TokenSessionId, TokenUser,
    },
    System::{
        RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken},
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
};

pub struct Handle(pub HANDLE);
impl Handle {
    pub fn new(raw: HANDLE) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
pub fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "本地身份或会话校验失败")
}

pub struct Descriptor(*mut c_void);
impl Descriptor {
    pub fn new(sddl: &str) -> io::Result<Self> {
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
    pub fn raw(&self) -> *mut c_void {
        self.0
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub fn sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut len = 0;
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Ok(result)
    }
}
fn token_info(token: HANDLE, class: i32) -> io::Result<Vec<usize>> {
    let mut len = 0;
    unsafe {
        GetTokenInformation(token, class, ptr::null_mut(), 0, &mut len);
    }
    if len == 0 || len > 64 * 1024 {
        return Err(denied());
    }
    let mut data = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
    if unsafe { GetTokenInformation(token, class, data.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(data)
}
#[derive(Clone)]
pub struct Identity {
    pub user: String,
    pub logon: String,
    pub session: u32,
}
impl Identity {
    pub fn from_token(token: HANDLE) -> io::Result<Self> {
        let user = token_info(token, TokenUser)?;
        let user = sid_string(unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid })?;
        let session = token_info(token, TokenSessionId)?;
        let session = unsafe { *session.as_ptr().cast::<u32>() };
        let groups = token_info(token, TokenGroups)?;
        let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
        let entries = unsafe {
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        let logon = entries
            .iter()
            .find(|g| g.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
            .map(|g| sid_string(g.Sid))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            user,
            logon,
            session,
        })
    }
    pub fn current() -> io::Result<Self> {
        let token = process_token(unsafe { GetCurrentProcess() })?;
        Self::from_token(token.0)
    }
    pub fn for_endpoint(endpoint: Endpoint) -> io::Result<Self> {
        let current = Self::current()?;
        if endpoint.console {
            if current.user == "S-1-5-18" || current.logon.is_empty() {
                return Err(denied());
            }
            return Ok(current);
        }
        if current.user != "S-1-5-18" {
            return Err(denied());
        }
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err(denied());
        }
        let mut raw = ptr::null_mut();
        if unsafe { WTSQueryUserToken(session, &mut raw) } == 0 {
            return Err(denied());
        }
        let token = Handle::new(raw)?;
        let identity = Self::from_token(token.0)?;
        if identity.logon.is_empty() {
            return Err(denied());
        }
        Ok(identity)
    }
    pub fn matches(&self, other: &Self) -> bool {
        self.user == other.user && self.logon == other.logon && self.session == other.session
    }
}
pub fn process_token(process: HANDLE) -> io::Result<Handle> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(denied());
    }
    Handle::new(raw)
}

pub fn verify_server(pid: u32, endpoint: Endpoint) -> io::Result<()> {
    let process = Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    let token = process_token(process.0)?;
    let server = Identity::from_token(token.0)?;
    let current = Identity::current()?;
    if endpoint.console {
        if !current.matches(&server) {
            return Err(denied());
        }
    } else if server.user != "S-1-5-18" || server.session != 0 {
        return Err(denied());
    }
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut len) } == 0 {
        return Err(denied());
    }
    let actual = std::path::PathBuf::from(String::from_utf16_lossy(&buffer[..len as usize]));
    let expected = std::env::current_exe()?.with_file_name("lineguard-service.exe");
    // All preview executables must be siblings. Production install directory must be admin-owned.
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(denied());
    }
    Ok(())
}

pub fn require_elevated_admin() -> io::Result<()> {
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, TokenElevation, WinBuiltinAdministratorsSid,
    };
    let token = process_token(unsafe { GetCurrentProcess() })?;
    let elevation = token_info(token.0, TokenElevation)?;
    if unsafe { *elevation.as_ptr().cast::<u32>() } == 0 {
        return Err(denied());
    }
    let mut sid = [0usize; 16];
    let mut size = std::mem::size_of_val(&sid) as u32;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(denied());
    }
    let mut member = 0;
    if unsafe { CheckTokenMembership(ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member) } == 0
        || member == 0
    {
        return Err(denied());
    }
    Ok(())
}

/// Read from the authenticated token, never a field supplied in an IPC request.
pub fn token_is_elevated_admin(token: HANDLE) -> io::Result<bool> {
    let elevation = token_info(token, windows_sys::Win32::Security::TokenElevation)?;
    if unsafe { *elevation.as_ptr().cast::<u32>() } == 0 {
        return Ok(false);
    }
    let groups = token_info(token, TokenGroups)?;
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    for group in entries {
        if group.Attributes & 0x4 != 0
            && group.Attributes & 0x10 == 0
            && sid_string(group.Sid)? == "S-1-5-32-544"
        {
            return Ok(true);
        }
    }
    Ok(false)
}
/// The SYSTEM check alone is insufficient for the future outer-flow WFP identity.
pub fn require_service_sid() -> io::Result<()> {
    let token = process_token(unsafe { GetCurrentProcess() })?;
    require_service_token(token.0)
}
/// Binary SID of `NT SERVICE\LineGuardPreview` (pointer-aligned buffer).
fn service_sid() -> io::Result<Vec<usize>> {
    use windows_sys::Win32::Security::LookupAccountNameW;
    let account = wide(r"NT SERVICE\LineGuardPreview");
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut usage = 0;
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut sid_size,
            ptr::null_mut(),
            &mut domain_size,
            &mut usage,
        );
    }
    if sid_size == 0 || sid_size > 1024 || domain_size > 1024 {
        return Err(denied());
    }
    let mut sid = vec![0usize; (sid_size as usize).div_ceil(size_of::<usize>())];
    let mut domain = vec![0u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut usage,
        )
    } == 0
    {
        return Err(denied());
    }
    Ok(sid)
}
/// String form used as the v3 ALE_USER_ID expectation; validated as a per-service SID.
pub fn service_sid_string() -> io::Result<String> {
    let mut sid = service_sid()?;
    let text = sid_string(sid.as_mut_ptr().cast())?;
    if !lineguard_core::permit::valid_service_sid(&text) {
        return Err(denied());
    }
    Ok(text)
}
pub fn require_service_token(token: HANDLE) -> io::Result<()> {
    use windows_sys::Win32::Security::EqualSid;
    let identity = Identity::from_token(token)?;
    if identity.user != "S-1-5-18" || identity.session != 0 {
        return Err(denied());
    }
    let sid = service_sid()?;
    let groups = token_info(token, TokenGroups)?;
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    for group in
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) }
    {
        if group.Attributes & 0x4 != 0
            && group.Attributes & 0x10 == 0
            && unsafe { EqualSid(group.Sid, sid.as_ptr().cast_mut().cast()) } != 0
        {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "服务令牌缺少启用的专用服务SID；须在隔离VM预配置服务SID并重新启动服务，未自动修改SCM",
    ))
}
