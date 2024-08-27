// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::util::RunningProcess;
use crate::TEST_SERVER_PORT;
use color_eyre::eyre::Result;
use std::net::SocketAddr;

async fn find_wasm_file(deploy_path: &std::path::Path) -> Result<std::path::PathBuf> {
    let wasm_base_path = deploy_path.to_path_buf();
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

pub(crate) async fn build_wasm() -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::process::Command;

    let cwd = std::env::current_dir()?;

    if cfg!(feature = "proteus") {
        let spinner = RunningProcess::new("Building Cryptobox ESM bundle...", false);

        Command::new("npm")
            .args(["install"])
            .current_dir(cwd.join("interop/src/build/web/cryptobox-esm"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await?;

        Command::new("npm")
            .args(["run", "build"])
            .current_dir(cwd.join("interop/src/build/web/cryptobox-esm"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await?;

        spinner.success("Cryptobox ESM bundle [OK]");
    }

    let mut spinner = RunningProcess::new("Building WASM bundle...", false);

    let wasm_deploy_path = cwd.join("platforms/web");

    let exe_path = std::env::current_exe()?;
    let exe_folder = exe_path.parent().unwrap();
    let wasm_cache_path = exe_folder.join(".wasm.cache");
    let js_cache_path = exe_folder.join(".js.cache");

    let wasm_path = find_wasm_file(&wasm_deploy_path).await?;
    let js_path = wasm_deploy_path.join("corecrypto.js");

    std::fs::copy(
        cwd.join("crypto-ffi/bindings/js/test/index.html"),
        wasm_deploy_path.join("index.html"),
    )?;

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

    let mut cargo_args = vec!["make", "wasm"];
    let mut npm_env = vec![];

    if cfg!(feature = "proteus") {
        spinner.update(
            "`proteus` feature enabled. Building `core-crypto` with proteus support & enabling npm env BUILD_PROTEUS=1; Also building ESM bundle for Cryptobox",
        );
        cargo_args.push("--features");
        cargo_args.push("proteus");
        npm_env.push(("BUILD_PROTEUS", "1"));
    }

    Command::new("cargo")
        .args(&cargo_args)
        .current_dir(cwd.join("crypto-ffi"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;

    Command::new("bun")
        .args(["test"])
        .envs(npm_env.clone())
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

pub(crate) async fn spawn_http_server() -> Result<()> {
    use warp::Filter as _;
    let addr = SocketAddr::from(([0, 0, 0, 0], TEST_SERVER_PORT.parse()?));
    let warp_filter_cc = warp::path("core-crypto").and(warp::fs::dir("platforms/web".to_string()));
    let warp_filter_cbox =
        warp::path("cryptobox").and(warp::fs::dir("interop/src/build/web/cryptobox-esm/dist".to_string()));

    warp::serve(warp_filter_cc.or(warp_filter_cbox).boxed())
        .bind(addr)
        .await;

    Ok(())
}
