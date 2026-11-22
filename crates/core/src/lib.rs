//! Pure, side-effect-free preview domain. There is deliberately no Protected state.
pub mod engine;
pub mod guard;
pub mod network;
pub mod permit;
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};
use thiserror::Error;
use zeroize::Zeroize;

pub fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

pub const VERSION: u32 = 5;
pub const CONFIG_VERSION: u32 = 1;
pub const MAX_FRAME: usize = 128 * 1024;
pub const MAX_IMPORT: usize = 64 * 1024;
pub const MAX_PROFILES: usize = 16;

#[derive(Debug, Error)]
pub enum Error {
    #[error("输入格式无效（请使用版本 1 的离线 JSON 配置）")]
    Format,
    #[error("输入超过允许大小")]
    TooLarge,
    #[error("配置无效：{0}")]
    Invalid(&'static str),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Unknown,
    Unprotected,
    Blocked,
    Degraded,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub server: IpAddr,
    pub port: u16,
    pub method: Cipher,
    pub password: Secret,
}

// Never derive Debug for secrets: diagnostics and validation must not echo input.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[已隐藏]")
    }
}
impl Secret {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Cipher {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20Poly1305,
}

impl Cipher {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20Poly1305 => "chacha20-ietf-poly1305",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub profiles: Vec<Profile>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema: CONFIG_VERSION,
            profiles: Vec::new(),
        }
    }
}
impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_IMPORT {
            return Err(Error::TooLarge);
        }
        let config: Self = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema != CONFIG_VERSION {
            return Err(Error::Invalid("不支持的配置版本"));
        }
        if self.profiles.len() > MAX_PROFILES {
            return Err(Error::Invalid("最多保存 16 条线路"));
        }
        for (index, profile) in self.profiles.iter().enumerate() {
            if profile.name.trim().is_empty()
                || profile.name.len() > 96
                || profile.name.chars().any(char::is_control)
            {
                return Err(Error::Invalid("线路名称为空、过长或含控制字符"));
            }
            if self.profiles[..index]
                .iter()
                .any(|other| other.name == profile.name)
            {
                return Err(Error::Invalid("线路名称重复"));
            }
            if profile.server.is_unspecified()
                || profile.server.is_loopback()
                || profile.server.is_multicast()
            {
                return Err(Error::Invalid("端点不可为未指定、回环或组播地址"));
            }
            if profile.port == 0 || profile.password.is_empty() || profile.password.len() > 1024 {
                return Err(Error::Invalid("端口或密码长度不合法"));
            }
        }
        Ok(())
    }
    pub fn summaries(&self) -> Vec<ProfileSummary> {
        self.profiles
            .iter()
            .map(|p| ProfileSummary {
                name: p.name.clone(),
                server: p.server,
                port: p.port,
                method: p.method,
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSummary {
    pub name: String,
    pub server: IpAddr,
    pub port: u16,
    pub method: Cipher,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub id: u64,
    pub command: Command,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status,
    Import {
        expected_generation: u64,
        config: Config,
    },
    Connect,
    CoreInfo,
    StartExclusiveTun {
        expected_generation: u64,
        index: usize,
        confirmation: String,
    },
    CoreCheck {
        expected_generation: u64,
        index: usize,
        confirmation: String,
    },
    /// Admin-only: on an already quarantined exclusive TUN, install the v3 gate then the packet
    /// permits as the final step. Not Connect; never reachable from the ordinary UI.
    OpenNarrowPath {
        expected_generation: u64,
        confirmation: String,
    },
    Diagnostics,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub network: network::Status,
    pub core: engine::Info,
    pub guard: guard::Evidence,
    pub generation: u64,
    pub phase: Phase,
    pub profiles: Vec<ProfileSummary>,
    pub saved: bool,
    pub storage_error: bool,
    pub mode: Mode,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Service,
    Console,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub id: u64,
    pub result: Reply,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Status { snapshot: Snapshot },
    Imported { snapshot: Snapshot },
    Diagnostics { report: Diagnostic },
    CoreInfo { info: engine::Info },
    CoreChecked { report: engine::CheckReport },
    Failure { code: FaultCode, message: String },
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FaultCode {
    Unsupported,
    InvalidInput,
    Conflict,
    Storage,
    Protocol,
    PermissionDenied,
    Engine,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub guard: guard::Evidence,
    pub product: String,
    pub version: String,
    pub mode: Mode,
    pub generation: u64,
    pub profile_count: usize,
    pub storage_error: bool,
    pub protection: String,
}

pub struct Controller {
    network: network::Status,
    core: engine::Info,
    guard: guard::Evidence,
    config: Config,
    generation: u64,
    saved: bool,
    storage_error: bool,
    mode: Mode,
}
impl Controller {
    pub fn new(
        config: Config,
        generation: u64,
        saved: bool,
        storage_error: bool,
        mode: Mode,
    ) -> Self {
        Self {
            network: network::Status::default(),
            core: engine::Info::default(),
            guard: guard::Evidence::unknown(),
            config,
            generation,
            saved,
            storage_error,
            mode,
        }
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn observe_network(&mut self, status: network::Status) {
        self.network = status;
    }
    pub fn observe_core(&mut self, info: engine::Info) {
        self.core = info;
    }
    pub fn profile(&self, generation: u64, index: usize) -> Result<&Profile, Error> {
        if self.storage_error || generation != self.generation {
            return Err(Error::Invalid("配置代次改变或存储异常，请刷新"));
        }
        self.config
            .profiles
            .get(index)
            .ok_or(Error::Invalid("未找到线路"))
    }
    pub fn observe_guard(&mut self, evidence: guard::Evidence) {
        self.guard = evidence;
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            network: self.network.clone(),
            core: self.core.clone(),
            guard: self.guard.clone(),
            generation: self.generation,
            phase: match self.guard.state {
                guard::State::Unknown => Phase::Unknown,
                guard::State::Absent => Phase::Unprotected,
                guard::State::Drift | guard::State::Narrowed => Phase::Degraded,
                guard::State::Configured | guard::State::Emergency => Phase::Blocked,
            },
            profiles: self.config.summaries(),
            saved: self.saved,
            storage_error: self.storage_error,
            mode: self.mode,
        }
    }
    pub fn handle(
        &mut self,
        request: Request,
        save: impl FnOnce(&Config, u64) -> Result<(), ()>,
    ) -> Response {
        let failure = |code, message: &str| Reply::Failure {
            code,
            message: message.into(),
        };
        let result = if request.version != VERSION {
            failure(FaultCode::Protocol, "客户端与服务协议版本不匹配")
        } else {
            match request.command {
                Command::Status => Reply::Status {
                    snapshot: self.snapshot(),
                },
                Command::Connect => failure(FaultCode::Unsupported, engine::ACTIVATION_BLOCKER),
                Command::CoreInfo => Reply::CoreInfo {
                    info: self.core.clone(),
                },
                Command::StartExclusiveTun { .. }
                | Command::CoreCheck { .. }
                | Command::OpenNarrowPath { .. } => failure(
                    FaultCode::Unsupported,
                    "只有Windows SYSTEM服务可执行管理员明确请求的核心隔离检查",
                ),
                Command::Diagnostics => Reply::Diagnostics {
                    report: Diagnostic {
                        guard: self.guard.clone(),
                        product: "LineGuard".into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        mode: self.mode,
                        generation: self.generation,
                        profile_count: self.config.profiles.len(),
                        storage_error: self.storage_error,
                        protection: "no_tunnel_pinned_core_check_only".into(),
                    },
                },
                Command::Import {
                    expected_generation,
                    config,
                } => {
                    if let Err(e) = config.validate() {
                        failure(FaultCode::InvalidInput, &e.to_string())
                    } else if self.storage_error {
                        failure(
                            FaultCode::Storage,
                            "已有配置无法读取，禁止覆盖；请先独立诊断或恢复备份",
                        )
                    } else if expected_generation != self.generation {
                        failure(FaultCode::Conflict, "配置已改变，请刷新后重试")
                    } else if let Some(next) = self.generation.checked_add(1) {
                        if save(&config, next).is_err() {
                            failure(FaultCode::Storage, "加密保存失败；原配置保持不变")
                        } else {
                            self.config = config;
                            self.generation = next;
                            self.saved = true;
                            Reply::Imported {
                                snapshot: self.snapshot(),
                            }
                        }
                    } else {
                        failure(FaultCode::Conflict, "配置版本达到上限，拒绝覆盖")
                    }
                }
            }
        };
        Response {
            version: VERSION,
            id: request.id,
            result,
        }
    }
}

pub fn request(bytes: &[u8]) -> Result<Request, Error> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Format)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn controller() -> Controller {
        Controller::new(Config::default(), 0, false, false, Mode::Console)
    }
    #[test]
    fn policy_phase_tracks_current_evidence_without_protected() {
        let mut c = controller();
        c.observe_guard(guard::Evidence::assess(false, false, false, &[], false, 1));
        assert_eq!(c.snapshot().phase, Phase::Unprotected);
        let observed: Vec<_> = guard::rules().iter().map(|r| (r.key, true)).collect();
        c.observe_guard(guard::Evidence::assess(
            true, true, true, &observed, false, 2,
        ));
        assert_eq!(c.snapshot().phase, Phase::Blocked);
        c.observe_guard(guard::Evidence::assess(
            true,
            true,
            true,
            &observed[..6],
            false,
            3,
        ));
        assert_eq!(c.snapshot().phase, Phase::Degraded);
        c.observe_guard(guard::Evidence::unknown());
        assert_eq!(c.snapshot().phase, Phase::Unknown);
    }
    #[test]
    fn unsupported_connect_has_no_effect() {
        let mut c = controller();
        let r = c.handle(
            Request {
                version: VERSION,
                id: 8,
                command: Command::Connect,
            },
            |_, _| panic!("no save"),
        );
        assert!(matches!(
            r.result,
            Reply::Failure {
                code: FaultCode::Unsupported,
                ..
            }
        ));
        assert_eq!(c.snapshot().generation, 0);
        assert_eq!(c.snapshot().phase, Phase::Unknown);
    }
    #[test]
    fn failed_save_preserves_generation() {
        let mut c = controller();
        let r = c.handle(
            Request {
                version: VERSION,
                id: 1,
                command: Command::Import {
                    expected_generation: 0,
                    config: Config::default(),
                },
            },
            |_, _| Err(()),
        );
        assert!(matches!(
            r.result,
            Reply::Failure {
                code: FaultCode::Storage,
                ..
            }
        ));
        assert_eq!(c.snapshot().generation, 0);
    }
    #[test]
    fn stale_writer_is_rejected() {
        let mut c = controller();
        c.handle(
            Request {
                version: VERSION,
                id: 1,
                command: Command::Import {
                    expected_generation: 0,
                    config: Config::default(),
                },
            },
            |_, _| Ok(()),
        );
        let r = c.handle(
            Request {
                version: VERSION,
                id: 2,
                command: Command::Import {
                    expected_generation: 0,
                    config: Config::default(),
                },
            },
            |_, _| panic!("must not save"),
        );
        assert!(matches!(
            r.result,
            Reply::Failure {
                code: FaultCode::Conflict,
                ..
            }
        ));
    }
    #[test]
    fn unknown_and_oversized_input_rejected() {
        assert!(Config::parse(br#"{"schema":1,"profiles":[],"script":"bad"}"#).is_err());
        assert!(Config::parse(&vec![b' '; MAX_IMPORT + 1]).is_err());
    }
    #[test]
    fn diagnostic_has_no_profile_names_or_credentials() {
        let mut c = controller();
        let r = c.handle(
            Request {
                version: VERSION,
                id: 1,
                command: Command::Diagnostics,
            },
            |_, _| panic!("no save"),
        );
        let json = serde_json::to_string(&r).unwrap();
        for sensitive in ["password", "server", "profiles", "token", "path"] {
            assert!(!json.contains(sensitive));
        }
    }
}
