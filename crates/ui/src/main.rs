#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(windows)]
mod app;
#[cfg(windows)]
fn main() -> eframe::Result {
    let console = std::env::args().any(|arg| arg == "--console");
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 720.0])
            .with_min_inner_size([840.0, 580.0])
            .with_title("LineGuard · 开发预览"),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "LineGuard",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, console)))),
    )
}
#[cfg(not(windows))]
fn main() {
    eprintln!("LineGuard GUI 仅支持 Windows；本机平台没有模拟界面或保护能力。");
}
