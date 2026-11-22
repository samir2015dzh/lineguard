// Shared by crates/{agent,ui}/build.rs via include!(). Embeds the LineGuard icon and a
// VERSIONINFO resource into Windows GNU executables using MinGW windres. No new crate deps.
fn embed_windows_resources() {
    use std::{env, path::PathBuf, process::Command};
    let assets = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../assets");
    println!("cargo:rerun-if-changed={}", assets.join("lineguard.ico").display());
    println!("cargo:rerun-if-env-changed=WINDRES");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("gnu")
    {
        return;
    }
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let numeric: Vec<u16> = version
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|p| p.parse().ok())
        .chain(std::iter::repeat(0))
        .take(4)
        .collect();
    let comma = numeric.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let icon = assets.join("lineguard.ico").canonicalize().expect("assets/lineguard.ico");
    let rc = format!(
        r#"#pragma code_page(65001)
1 ICON "{icon}"
1 VERSIONINFO
FILEVERSION {comma}
PRODUCTVERSION {comma}
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "LineGuard"
      VALUE "FileDescription", "LineGuard development preview (unverified, unsigned)"
      VALUE "FileVersion", "{version}"
      VALUE "ProductName", "LineGuard"
      VALUE "ProductVersion", "{version}"
      VALUE "LegalCopyright", "LineGuard. See LICENSE-NOTICE.md"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        icon = icon.display().to_string().replace('\\', "/"),
    );
    let rc_path = out.join("lineguard.rc");
    std::fs::write(&rc_path, rc).unwrap();
    let object = out.join("lineguard-res.o");
    let windres = env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".into());
    let status = Command::new(&windres)
        .args(["--input-format=rc", "--output-format=coff", "-i"])
        .arg(&rc_path)
        .arg("-o")
        .arg(&object)
        .status();
    match status {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg-bins={}", object.display()),
        _ => panic!("windres ({windres}) failed; install MinGW-w64 binutils or set WINDRES"),
    }
}
