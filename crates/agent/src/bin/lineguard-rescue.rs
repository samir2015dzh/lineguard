use lineguard_agent::{Endpoint, inspect};
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    if borrowed.as_slice() == ["--version"] {
        println!(
            "LineGuard {} / {}",
            env!("CARGO_PKG_VERSION"),
            lineguard_core::guard::RESCUE_MARKER
        );
        return;
    }
    let remove = borrowed.as_slice() == ["remove", "--confirm", "ALLOW-DIRECT"];
    let recover = borrowed.as_slice()
        == [
            "recover",
            "--confirm",
            lineguard_core::network::RECOVER_INTENT,
        ];
    if remove || recover {
        match lineguard_agent::recover_network(lineguard_core::network::RECOVER_INTENT, remove) {
            Ok(report) => println!("{report}"),
            Err(e) => {
                eprintln!("独立恢复/解除未完成：{e}；不可假定已恢复联网");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.iter().any(|s| s != "inspect" && s != "--console") {
        eprintln!(
            "用法：inspect [--console]；管理员恢复并保持阻断：recover --confirm RESTORE-OWN-NETWORK；管理员恢复后明确解除：remove --confirm ALLOW-DIRECT"
        );
        std::process::exit(2);
    }
    println!("LineGuard 独立只读检查，不依赖后台在线：");
    match inspect(Endpoint {
        console: args.iter().any(|s| s == "--console"),
    }) {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("检查失败：{error}；未修改系统");
            std::process::exit(1);
        }
    }
}
