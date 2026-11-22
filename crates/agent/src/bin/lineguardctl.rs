use lineguard_agent::{Endpoint, call};
use lineguard_core::{Command, Config, MAX_IMPORT, Reply, Request, VERSION};
use std::{
    fs::File,
    io::{self, Read},
};
fn main() {
    if let Err(error) = run() {
        eprintln!("操作失败：{error}");
        std::process::exit(1);
    }
}
fn run() -> io::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let console = args.first().is_some_and(|s| s == "--console");
    if console {
        args.remove(0);
    }
    if args.first().is_some_and(|s| s == "guard") {
        if console {
            return Err(io::Error::other(
                "全局WFP操作不接受--console；请明确使用guard命令",
            ));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        if args.as_slice() == ["guard", "permit", "inspect"] {
            let evidence = lineguard_agent::inspect_permits()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&evidence).map_err(io::Error::other)?
            );
            return Ok(());
        }
        if args.as_slice() == ["guard", "inspect"] {
            println!("{}", lineguard_agent::inspect_guard_details()?);
            return Ok(());
        }
        let evidence = match args.as_slice() {
            [
                "guard",
                "install",
                "--experimental-vm-only",
                "--confirm",
                "BLOCK-ALL-IP",
            ] => lineguard_agent::mutate_guard(true, "BLOCK-ALL-IP", true)?,
            ["guard", "remove", "--confirm", "ALLOW-DIRECT"] => {
                lineguard_agent::mutate_guard(false, "ALLOW-DIRECT", false)?
            }
            _ => {
                return Err(io::Error::other(
                    "危险操作用法：guard inspect | guard permit inspect（只读） | guard install --experimental-vm-only --confirm BLOCK-ALL-IP | guard remove --confirm ALLOW-DIRECT",
                ));
            }
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&evidence).map_err(io::Error::other)?
        );
        return Ok(());
    }
    if args.as_slice() == ["core", "inbox"] && !console {
        println!(
            "管理员离线暂存路径（请以管理员复制固定公开exe到此；程序未复制或执行）：\n{}",
            lineguard_agent::prepare_core_import()?.display()
        );
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "core")
        && args.get(1).is_some_and(|s| s == "manifest")
        && args.len() == 2
    {
        println!("{}", lineguard_core::engine::MANIFEST_JSON);
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "core") && args.get(1).is_some_and(|s| s == "import") {
        if console || args.len() != 5 || args[3] != "--confirm" {
            return Err(io::Error::other(
                "管理员用法：core import <固定版本exe> --confirm ACCEPT-MIHOMO-GPL3-AND-EMBEDDED-WINTUN；须先阅读third-party许可",
            ));
        }
        let info = lineguard_agent::import_core(std::path::Path::new(&args[2]), &args[4])?;
        println!(
            "{}",
            serde_json::to_string_pretty(&info).map_err(io::Error::other)?
        );
        return Ok(());
    }
    let endpoint = Endpoint { console };
    let command = match args.first().map(String::as_str) {
        Some("status") => Command::Status,
        Some("diagnostics") => Command::Diagnostics,
        Some("connect") => Command::Connect,
        Some("core") if args.len() == 2 && args[1] == "info" => Command::CoreInfo,
        Some("core" | "tun")
            if !console
                && args.len() == 5
                && ((args[0] == "core" && args[1] == "check")
                    || (args[0] == "tun" && args[1] == "start"))
                && args[3] == "--confirm" =>
        {
            let index: usize = args[2]
                .parse()
                .map_err(|_| io::Error::other("线路序号从1开始"))?;
            let index = index
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("线路序号从1开始"))?;
            let response = call(
                endpoint,
                Request {
                    version: VERSION,
                    id: 1,
                    command: Command::Status,
                },
            )?;
            let Reply::Status { snapshot } = response.result else {
                return Err(io::Error::other("无法取得配置代次"));
            };
            if args[0] == "tun" {
                Command::StartExclusiveTun {
                    expected_generation: snapshot.generation,
                    index,
                    confirmation: args[4].clone(),
                }
            } else {
                Command::CoreCheck {
                    expected_generation: snapshot.generation,
                    index,
                    confirmation: args[4].clone(),
                }
            }
        }
        Some("import") if args.len() == 2 => {
            let mut data = Vec::new();
            File::open(&args[1])?
                .take((MAX_IMPORT + 1) as u64)
                .read_to_end(&mut data)?;
            let config = Config::parse(&data);
            lineguard_core::wipe(&mut data);
            let config = config.map_err(|_| io::Error::other("离线配置无效"))?;
            let status = call(
                endpoint,
                Request {
                    version: VERSION,
                    id: 1,
                    command: Command::Status,
                },
            )?;
            let Reply::Status { snapshot } = status.result else {
                return Err(io::Error::other("无法取得状态"));
            };
            Command::Import {
                expected_generation: snapshot.generation,
                config,
            }
        }
        _ => {
            println!(
                "LineGuard M3管理开发预览（数据通路未实现；没有防泄露保证）\n用法：lineguardctl [--console] status | diagnostics | connect | import <离线JSON文件>\ncore manifest | core inbox | core info | core import <exe> --confirm ACCEPT-MIHOMO-GPL3-AND-EMBEDDED-WINTUN | core check <线路序号> --confirm CHECK-CONFIG-NO-TUNNEL\ntun start <线路序号> --confirm START-EXCLUSIVE-TUN-BLOCKED（仅独占隔离TUN，全阻断保留，不能联网）"
            );
            return Ok(());
        }
    };
    let response = call(
        endpoint,
        Request {
            version: VERSION,
            id: 2,
            command,
        },
    )?;
    if let Reply::Failure { message, .. } = response.result {
        eprintln!("{message}");
        std::process::exit(2);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(io::Error::other)?
    );
    if let Reply::CoreChecked { report } = &response.result {
        if !report.syntax_accepted
            || report.guard_after.state != lineguard_core::guard::State::Configured
            || report.tunnel_started
        {
            return Err(io::Error::other("配置检查未接受或阻断证据异常；未启动隧道"));
        }
    }
    Ok(())
}
