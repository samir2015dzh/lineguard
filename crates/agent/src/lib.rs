use lineguard_core::{Request, Response};
use std::{
    io,
    sync::{Arc, atomic::AtomicBool},
};

#[cfg(windows)]
pub mod windows;

#[derive(Clone, Copy)]
pub struct Endpoint {
    pub console: bool,
}

#[cfg(windows)]
pub fn call(endpoint: Endpoint, request: Request) -> io::Result<Response> {
    windows::ipc::call(endpoint, request)
}
#[cfg(not(windows))]
pub fn call(_: Endpoint, _: Request) -> io::Result<Response> {
    Err(unsupported())
}

#[cfg(windows)]
pub fn serve(endpoint: Endpoint, stop: Arc<AtomicBool>) -> io::Result<()> {
    windows::serve(endpoint, stop, || {})
}
#[cfg(not(windows))]
pub fn serve(_: Endpoint, _: Arc<AtomicBool>) -> io::Result<()> {
    Err(unsupported())
}

pub fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "仅支持 Windows；没有模拟 DPAPI、服务或网络操作",
    )
}

/// Read-only encrypted storage and WFP inspection, independent of the daemon.
#[cfg(windows)]
pub fn inspect(endpoint: Endpoint) -> io::Result<String> {
    windows::inspect(endpoint)
}
#[cfg(not(windows))]
pub fn inspect(_: Endpoint) -> io::Result<String> {
    Err(unsupported())
}

#[cfg(windows)]
pub fn serve_with_ready(
    endpoint: Endpoint,
    stop: Arc<AtomicBool>,
    ready: impl FnOnce(),
) -> io::Result<()> {
    windows::serve(endpoint, stop, ready)
}

/// Read live WFP evidence; never infers state from a journal.
#[cfg(windows)]
pub fn inspect_guard() -> io::Result<lineguard_core::guard::Evidence> {
    windows::wfp::inspect()
}
#[cfg(not(windows))]
pub fn inspect_guard() -> io::Result<lineguard_core::guard::Evidence> {
    Err(unsupported())
}
/// Native API enforces elevated Administrators membership and exact intent.
#[cfg(windows)]
pub fn mutate_guard(
    install: bool,
    confirmation: &str,
    experimental_vm: bool,
) -> io::Result<lineguard_core::guard::Evidence> {
    let _network = if !install {
        Some(windows::network::removal_lock()?)
    } else {
        None
    };
    windows::wfp::mutate(install, confirmation, experimental_vm)
}
#[cfg(not(windows))]
pub fn mutate_guard(_: bool, _: &str, _: bool) -> io::Result<lineguard_core::guard::Evidence> {
    Err(unsupported())
}

#[cfg(windows)]
pub fn inspect_guard_details() -> io::Result<String> {
    windows::wfp::detailed_inspect()
}
#[cfg(not(windows))]
pub fn inspect_guard_details() -> io::Result<String> {
    Err(unsupported())
}

/// Only imports the exact pinned public core; no execution or network changes.
#[cfg(windows)]
pub fn import_core(
    source: &std::path::Path,
    confirmation: &str,
) -> io::Result<lineguard_core::engine::Info> {
    windows::engine::import(source, confirmation)
}
#[cfg(not(windows))]
pub fn import_core(_: &std::path::Path, _: &str) -> io::Result<lineguard_core::engine::Info> {
    Err(unsupported())
}

/// Creates only an admin-owned local staging folder; no executable is opened or run.
#[cfg(windows)]
pub fn prepare_core_import() -> io::Result<std::path::PathBuf> {
    windows::engine::prepare_import()
}
#[cfg(not(windows))]
pub fn prepare_core_import() -> io::Result<std::path::PathBuf> {
    Err(unsupported())
}

#[cfg(windows)]
pub fn recover_network(confirmation: &str, allow_direct: bool) -> io::Result<String> {
    windows::network::recover(confirmation, allow_direct)
}
#[cfg(not(windows))]
pub fn recover_network(_: &str, _: bool) -> io::Result<String> {
    Err(unsupported())
}
