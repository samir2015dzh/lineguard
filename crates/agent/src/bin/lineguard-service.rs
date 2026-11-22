use lineguard_agent::{Endpoint, serve};
use std::sync::{Arc, atomic::AtomicBool};
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--console") {
        eprintln!(
            "LineGuard M2 console：只观察已有WFP，不自动安装或撤销；关闭终端不会解除持久实验阻断。"
        );
        if serve(Endpoint { console: true }, Arc::new(AtomicBool::new(false))).is_err() {
            eprintln!("启动失败：权限、管道或存储不可用（不输出敏感路径）");
            std::process::exit(1);
        }
    } else {
        platform_main();
    }
}
#[cfg(not(windows))]
fn platform_main() {
    eprintln!("仅支持 Windows SCM/console；未执行任何安装。");
    std::process::exit(1);
}
#[cfg(windows)]
fn platform_main() {
    use windows_service::{define_windows_service, service_dispatcher};
    define_windows_service!(entry, service_main);
    if service_dispatcher::start("LineGuardPreview", entry).is_err() {
        eprintln!("请由 SCM 启动；离线开发使用 --console。此程序不会自动安装服务。");
        std::process::exit(1);
    }
}
#[cfg(windows)]
fn service_main(_: Vec<std::ffi::OsString>) {
    use std::sync::atomic::Ordering;
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = stop.clone();
    let Ok(status) =
        service_control_handler::register("LineGuardPreview", move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_stop.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
    else {
        return;
    };
    let report = |state, code| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(5),
            process_id: None,
        });
    };
    report(ServiceState::StartPending, 0);
    let result = lineguard_agent::serve_with_ready(Endpoint { console: false }, stop, || {
        report(ServiceState::Running, 0)
    });
    report(ServiceState::Stopped, if result.is_ok() { 0 } else { 1 });
}
