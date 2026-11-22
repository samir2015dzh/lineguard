pub mod engine;
pub mod ipc;
pub mod network;
pub mod permit;
mod security;
mod storage;
pub mod wfp;
use crate::Endpoint;
use lineguard_core::{Config, Controller, Mode};
use std::{
    io,
    sync::{Arc, atomic::AtomicBool},
};

/// Tag a startup failure with its stage, keeping kind and OS code; never paths or identities.
fn stage<T>(name: &str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("stage={name} kind={:?} os={:?}", e.kind(), e.raw_os_error()),
        )
    })
}
pub fn serve(endpoint: Endpoint, stop: Arc<AtomicBool>, ready: impl FnOnce()) -> io::Result<()> {
    let identity = stage("identity", security::Identity::for_endpoint(endpoint))?;
    let store = stage("store", storage::Store::open(endpoint, &identity))?;
    let loaded = store.load();
    let (config, generation, saved, error) = match loaded {
        Ok(Some((config, generation))) => (config, generation, true, false),
        Ok(None) => (Config::default(), 0, false, false),
        Err(_) => (Config::default(), 0, false, true),
    };
    let mode = if endpoint.console {
        Mode::Console
    } else {
        Mode::Service
    };
    let mut controller = Controller::new(config, generation, saved, error, mode);
    let mut lifecycle = engine::Lifecycle::new();
    controller.observe_network(lifecycle.status());
    let result = ipc::serve(endpoint, identity, stop, ready, |event| {
        if lifecycle.tick(controller.generation()) {
            controller.observe_network(lifecycle.status());
        }
        let Some((request, authority)) = event else {
            return None;
        };
        // Protocol/authentication checks precede every effect, not merely Controller dispatch.
        if request.version == lineguard_core::VERSION {
            match &request.command {
                lineguard_core::Command::StartExclusiveTun {
                    expected_generation,
                    index,
                    confirmation,
                } => {
                    let result = if endpoint.console || !authority.elevated_admin {
                        lineguard_core::Reply::Failure{code:lineguard_core::FaultCode::PermissionDenied,message:"独占TUN仅接受经令牌核验的同会话管理员请求；普通UI无启动或关保护权限".into()}
                    } else {
                        let result = controller
                            .profile(*expected_generation, *index)
                            .map_err(io::Error::other)
                            .and_then(|profile| {
                                lifecycle.start(profile, *expected_generation, *index, confirmation)
                            });
                        controller.observe_network(lifecycle.status());
                        controller.observe_guard(
                            wfp::inspect()
                                .unwrap_or_else(|_| lineguard_core::guard::Evidence::unknown()),
                        );
                        match result {
                            Ok(()) => lineguard_core::Reply::Status {
                                snapshot: controller.snapshot(),
                            },
                            Err(e) => lineguard_core::Reply::Failure {
                                code: lineguard_core::FaultCode::Engine,
                                message: e.to_string(),
                            },
                        }
                    };
                    return Some(lineguard_core::Response {
                        version: lineguard_core::VERSION,
                        id: request.id,
                        result,
                    });
                }
                lineguard_core::Command::OpenNarrowPath {
                    expected_generation,
                    confirmation,
                } => {
                    let result = if endpoint.console || !authority.elevated_admin {
                        lineguard_core::Reply::Failure {
                            code: lineguard_core::FaultCode::PermissionDenied,
                            message:
                                "窄数据通路仅接受经令牌核验的同会话管理员请求；普通UI无放行权限"
                                    .into(),
                        }
                    } else if *expected_generation != controller.generation() {
                        lineguard_core::Reply::Failure {
                            code: lineguard_core::FaultCode::Conflict,
                            message: "配置代次已变化；拒绝放行".into(),
                        }
                    } else {
                        let result = lifecycle.open_narrow(*expected_generation, confirmation);
                        controller.observe_network(lifecycle.status());
                        controller.observe_guard(
                            wfp::inspect()
                                .unwrap_or_else(|_| lineguard_core::guard::Evidence::unknown()),
                        );
                        match result {
                            Ok(()) => lineguard_core::Reply::Status {
                                snapshot: controller.snapshot(),
                            },
                            Err(e) => lineguard_core::Reply::Failure {
                                code: lineguard_core::FaultCode::Engine,
                                message: e.to_string(),
                            },
                        }
                    };
                    return Some(lineguard_core::Response {
                        version: lineguard_core::VERSION,
                        id: request.id,
                        result,
                    });
                }
                lineguard_core::Command::CoreInfo => controller.observe_core(engine::info()),
                lineguard_core::Command::CoreCheck {
                    expected_generation,
                    index,
                    confirmation,
                } => {
                    let result = if endpoint.console || !authority.elevated_admin {
                        lineguard_core::Reply::Failure { code:lineguard_core::FaultCode::PermissionDenied,
                            message:"核心检查只接受同一会话经令牌核验的管理员，通过SYSTEM服务明确发起；普通界面无此权限".into() }
                    } else {
                        match controller.profile(*expected_generation, *index) {
                            Err(error) => lineguard_core::Reply::Failure {
                                code: lineguard_core::FaultCode::Conflict,
                                message: error.to_string(),
                            },
                            Ok(profile) => match engine::check_config(profile, confirmation) {
                                Ok(report) => {
                                    controller.observe_guard(report.guard_after.clone());
                                    lineguard_core::Reply::CoreChecked { report }
                                }
                                Err(error) => lineguard_core::Reply::Failure {
                                    code: lineguard_core::FaultCode::Engine,
                                    message: error.to_string(),
                                },
                            },
                        }
                    };
                    return Some(lineguard_core::Response {
                        version: lineguard_core::VERSION,
                        id: request.id,
                        result,
                    });
                }
                _ => {}
            }
        }
        if matches!(
            &request.command,
            lineguard_core::Command::Status | lineguard_core::Command::Diagnostics
        ) {
            controller.observe_guard(
                wfp::inspect().unwrap_or_else(|_| lineguard_core::guard::Evidence::unknown()),
            );
        }
        Some(controller.handle(request, |config, generation| {
            store.save(config, generation).map_err(|_| ())
        }))
    });
    stage("pipe", result)
}
pub fn inspect(endpoint: Endpoint) -> io::Result<String> {
    let config_report = (|| {
        let identity = security::Identity::current()?;
        let store = storage::Store::open_readonly(endpoint, &identity)?;
        let result = match store.load()? {
            Some((config, generation)) => format!(
                "配置可解密读取；线路数={}，代次={generation}",
                config.profiles.len()
            ),
            None => "没有已保存配置".into(),
        };
        Ok::<_, io::Error>(result)
    })()
    .unwrap_or_else(|_| "配置不可读或密文损坏（服务数据可能需要管理员）；未改动文件".into());
    let evidence = wfp::inspect().unwrap_or_else(|_| lineguard_core::guard::Evidence::unknown());
    let network = match storage::Store::network_journal(false).and_then(|s| s.load_network()) {
        Ok(Some(lease)) => format!(
            "网络journal阶段={:?}；自有路由进度={}/{}（不是实时隧道健康证明）",
            lease.stage,
            lease.restored_routes,
            lease.added_routes.len()
        ),
        Ok(None) => "无网络journal".into(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => "尚无网络journal目录".into(),
        Err(_) => "网络journal不可读/损坏；禁止猜测性恢复".into(),
    };
    Ok(format!(
        "{config_report}\n{network}\nWFP实时回读：{}\n运行期规则={}，boot注册={}，预期总数={}\n本次inspect没有修改规则、文件、DNS、IPv6或服务\n解除实验阻断需管理员：lineguard-rescue remove --confirm ALLOW-DIRECT",
        evidence.detail, evidence.persistent_rules, evidence.boot_rules, evidence.expected_rules
    ))
}
