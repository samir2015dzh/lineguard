use super::security::{self, Descriptor, Handle, Identity, denied, wide};
use crate::Endpoint;
use lineguard_core::{FaultCode, MAX_FRAME, Reply, Request, Response, VERSION};
use std::{
    io, ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
        ERROR_PIPE_LISTENING, HANDLE,
    },
    Security::{RevertToSelf, TOKEN_QUERY},
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT, WriteFile,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
            ImpersonateNamedPipeClient, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            SetNamedPipeHandleState, WaitNamedPipeW,
        },
        Threading::{GetCurrentThread, OpenThreadToken},
    },
};
const DEADLINE: Duration = Duration::from_secs(4);
fn name(endpoint: Endpoint) -> io::Result<Vec<u16>> {
    Ok(wide(&if endpoint.console {
        let user = Identity::current()?;
        format!(
            r"\\.\pipe\LineGuard.Preview.Console.{}.{}",
            user.user, user.session
        )
    } else {
        r"\\.\pipe\LineGuard.Preview.Service".into()
    }))
}
fn last_code() -> u32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}
fn retry(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "管道请求超时"));
    }
    thread::sleep(Duration::from_millis(10));
    Ok(())
}
fn read_exact(handle: HANDLE, output: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        let mut count = 0;
        let ok = unsafe {
            ReadFile(
                handle,
                output[offset..].as_mut_ptr(),
                (output.len() - offset) as u32,
                &mut count,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            match last_code() {
                ERROR_NO_DATA => {
                    retry(deadline)?;
                    continue;
                }
                code => return Err(io::Error::from_raw_os_error(code as i32)),
            }
        }
        if count == 0 {
            retry(deadline)?;
        } else {
            offset += count as usize;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "读取超时"));
        }
    }
    Ok(())
}
fn write_all(handle: HANDLE, input: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < input.len() {
        let mut count = 0;
        let ok = unsafe {
            WriteFile(
                handle,
                input[offset..].as_ptr(),
                (input.len() - offset) as u32,
                &mut count,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            retry(deadline)?;
        } else {
            offset += count as usize;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "写入超时"));
        }
    }
    Ok(())
}
fn receive(handle: HANDLE, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    read_exact(handle, &mut length, deadline)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::other("协议帧大小无效"));
    }
    let mut data = vec![0u8; length];
    if let Err(error) = read_exact(handle, &mut data, deadline) {
        lineguard_core::wipe(&mut data);
        return Err(error);
    }
    Ok(data)
}
fn send(handle: HANDLE, data: &[u8], deadline: Instant) -> io::Result<()> {
    if data.is_empty() || data.len() > MAX_FRAME {
        return Err(io::Error::other("协议帧过大"));
    }
    write_all(handle, &(data.len() as u32).to_le_bytes(), deadline)?;
    write_all(handle, data, deadline)
}

pub fn call(endpoint: Endpoint, request: Request) -> io::Result<Response> {
    let pipe = name(endpoint)?;
    let deadline = Instant::now() + DEADLINE;
    let handle = loop {
        let raw = unsafe {
            CreateFileW(
                pipe.as_ptr(),
                FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        match Handle::new(raw) {
            Ok(handle) => break handle,
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                unsafe {
                    WaitNamedPipeW(pipe.as_ptr(), 100);
                }
                retry(deadline)?;
            }
            Err(error) => return Err(error),
        }
    };
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(handle.0, &mut pid) } == 0 {
        return Err(denied());
    }
    security::verify_server(pid, endpoint)?;
    let mode = PIPE_NOWAIT;
    if unsafe { SetNamedPipeHandleState(handle.0, &mode, ptr::null(), ptr::null()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let id = request.id;
    let mut data = serde_json::to_vec(&request).map_err(|_| io::Error::other("编码失败"))?;
    let written = send(handle.0, &data, deadline);
    lineguard_core::wipe(&mut data);
    written?;
    let data = receive(handle.0, deadline)?;
    let response: Response =
        serde_json::from_slice(&data).map_err(|_| io::Error::other("无效响应"))?;
    if response.version != VERSION || response.id != id {
        return Err(io::Error::other("响应版本或编号不符"));
    }
    write_all(handle.0, &[0x06], deadline)?;
    Ok(response)
}
struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        unsafe {
            if RevertToSelf() == 0 {
                std::process::abort();
            }
        }
    }
}
pub struct Authority {
    pub elevated_admin: bool,
}
fn authenticate(handle: HANDLE, expected: &Identity) -> io::Result<Authority> {
    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        return Err(denied());
    }
    let _revert = Revert;
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        return Err(denied());
    }
    let token = Handle::new(raw)?;
    let actual = Identity::from_token(token.0)?;
    if expected.matches(&actual) {
        Ok(Authority {
            elevated_admin: security::token_is_elevated_admin(token.0)?,
        })
    } else {
        Err(denied())
    }
}
pub fn serve(
    endpoint: Endpoint,
    identity: Identity,
    stop: Arc<AtomicBool>,
    ready: impl FnOnce(),
    mut handle_request: impl FnMut(Option<(Request, Authority)>) -> Option<Response>,
) -> io::Result<()> {
    // Client rights intentionally exclude FILE_CREATE_PIPE_INSTANCE (same bit as FILE_APPEND_DATA).
    let descriptor = Descriptor::new(&format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019B;;;{})",
        identity.logon
    ))?;
    let attributes = descriptor.attributes();
    let handle = Handle::new(unsafe {
        CreateNamedPipeW(
            name(endpoint)?.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            (MAX_FRAME + 4) as u32,
            (MAX_FRAME + 4) as u32,
            0,
            &attributes,
        )
    })?;
    ready();
    while !stop.load(Ordering::Relaxed) {
        handle_request(None);
        let connected = unsafe { ConnectNamedPipe(handle.0, ptr::null_mut()) };
        if connected == 0 {
            match last_code() {
                ERROR_PIPE_CONNECTED => {}
                ERROR_PIPE_LISTENING => {
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
                ERROR_NO_DATA => {
                    unsafe {
                        DisconnectNamedPipe(handle.0);
                    }
                    continue;
                }
                code => return Err(io::Error::from_raw_os_error(code as i32)),
            }
        }
        let deadline = Instant::now() + DEADLINE;
        let transaction = (|| {
            // Read before impersonation: Windows authenticates the writer of the last message.
            let mut data = receive(handle.0, deadline)?;
            let authorized = authenticate(handle.0, &identity);
            let request = if authorized.is_ok() {
                lineguard_core::request(&data).ok()
            } else {
                None
            };
            lineguard_core::wipe(&mut data);
            let authority = authorized?;
            if !endpoint.console {
                // M1 binds to one physical-console logon; session changes fail closed until restart.
                let active = Identity::for_endpoint(endpoint)?;
                if !identity.matches(&active) {
                    return Err(denied());
                }
            }
            let response = if let Some(request) = request {
                handle_request(Some((request, authority)))
                    .ok_or_else(|| io::Error::other("缺少IPC响应"))?
            } else {
                Response {
                    version: VERSION,
                    id: 0,
                    result: Reply::Failure {
                        code: FaultCode::Protocol,
                        message: "请求格式无效".into(),
                    },
                }
            };
            let data = serde_json::to_vec(&response).map_err(|_| io::Error::other("编码失败"))?;
            send(handle.0, &data, deadline)?;
            // Avoid FlushFileBuffers: an untrusted reader could block the only state owner indefinitely.
            // Wait for peer close/ack so DisconnectNamedPipe cannot discard an unread reply.
            let mut ack = [0u8; 1];
            match read_exact(handle.0, &mut ack, deadline) {
                Ok(()) if ack == [0x06] => Ok(()),
                Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(()),
                _ => Err(io::Error::other("响应确认失败")),
            }
        })();
        let _ = transaction; // No request payload or secret is ever logged.
        unsafe {
            DisconnectNamedPipe(handle.0);
        }
    }
    Ok(())
}
