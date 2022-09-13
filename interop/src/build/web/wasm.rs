use crate::util::RunningProcess;
use crate::TEST_SERVER_PORT;
use color_eyre::eyre::Result;
use std::net::SocketAddr;

pub async fn find_wasm_file(deploy_path: &std::path::Path) -> Result<std::path::PathBuf> {
    let wasm_base_path = deploy_path.join("assets");
    let wasm_path = if wasm_base_path.exists() {
        let mut wasm_dir = tokio::fs::read_dir(wasm_base_path.clone()).await?;
        let mut maybe_wasm_path = None;
        while let Some(entry) = wasm_dir.next_entry().await? {
            log::debug!("wasm dir entry: {entry:?}");
            if let Some(ext) = entry.path().extension() {
                if ext == std::ffi::OsStr::new("wasm") {
                    log::debug!("found");
                    maybe_wasm_path = Some(entry);
                }
            }
        }
        maybe_wasm_path
            .map(|entry| entry.path())
            .unwrap_or_else(|| wasm_base_path.join(".not-found"))
    } else {
        wasm_base_path.join(".not-found")
    };

    Ok(wasm_path)
}

pub async fn build_wasm() -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::process::Command;

    let mut spinner = RunningProcess::new("Building WASM bundle...", false);

    let cwd = std::env::current_dir()?;

    let wasm_deploy_path = cwd.join("platforms/web");

    let exe_path = std::env::current_exe()?;
    let exe_folder = exe_path.parent().unwrap();
    let wasm_cache_path = exe_folder.join(".wasm.cache");
    let js_cache_path = exe_folder.join(".js.cache");

    let wasm_path = find_wasm_file(&wasm_deploy_path).await?;
    let js_path = wasm_deploy_path.join("corecrypto.js");

    if !wasm_path.exists() || !js_path.exists() {
        spinner.update("WASM: No JS/WASM files found, rebuilding; Please wait...");
    } else if wasm_cache_path.exists() && js_cache_path.exists() {
        let wasm_hash = hex::decode(tokio::fs::read_to_string(wasm_cache_path.clone()).await?)?;
        let js_hash = hex::decode(tokio::fs::read_to_string(js_cache_path.clone()).await?)?;

        let mut hasher = Sha256::new();
        hasher.update(tokio::fs::read(js_path.clone()).await?);
        let js_current_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(tokio::fs::read(wasm_path.clone()).await?);
        let wasm_current_hash = hasher.finalize();

        if js_current_hash[..] == js_hash && wasm_current_hash[..] == wasm_hash {
            spinner.success("WASM: builds are identical - skipping build");
            return Ok(());
        }

        spinner.update("WASM: Hashes differ, needs rebuild! Please wait...");
    } else {
        spinner.update("WASM: No cache file found, rebuilding to get a cache! Please wait...");
    }

    Command::new("cargo")
        .args(["make", "wasm-build"])
        .current_dir(cwd.join("crypto-ffi"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;

    Command::new("npm")
        .args(["install"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;

    Command::new("npm")
        .args(["run", "build:test"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;

    spinner.update("WASM: Computing new file hashes...");

    let mut hasher = Sha256::new();
    hasher.update(tokio::fs::read(js_path).await?);
    let js_current_hash = hex::encode(hasher.finalize());

    let wasm_path = find_wasm_file(&wasm_deploy_path).await?;
    log::debug!("Found wasm file at {wasm_path:?}");

    let mut hasher = Sha256::new();
    hasher.update(tokio::fs::read(wasm_path).await?);
    let wasm_current_hash = hex::encode(hasher.finalize());

    log::debug!("Cache updated; CoreCrypto.wasm[{wasm_current_hash}] | corecrypto.js[{js_current_hash}]");
    log::debug!("JS Cache Path: {js_cache_path:?} | WASM Cache Path: {wasm_cache_path:?}");

    tokio::fs::write(js_cache_path, js_current_hash).await?;
    tokio::fs::write(wasm_cache_path, wasm_current_hash).await?;

    spinner.success("WASM bundle [OK]");

    Ok(())
}

pub async fn spawn_http_server() -> Result<()> {
    use warp::Filter as _;
    let addr = SocketAddr::from(([0, 0, 0, 0], TEST_SERVER_PORT.parse()?));
    warp::serve(warp::fs::dir("platforms/web".to_string()).boxed())
        .bind(addr)
        .await;

    Ok(())
}
