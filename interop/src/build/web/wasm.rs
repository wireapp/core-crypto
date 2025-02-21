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

use crate::TEST_SERVER_PORT;
use crate::util::RunningProcess;
use color_eyre::eyre::Result;
use std::net::SocketAddr;
use std::path::PathBuf;

pub(crate) async fn build_wasm(wasm_deploy_path: PathBuf) -> Result<()> {
    use tokio::process::Command;

    let cwd = std::env::current_dir()?;

    if cfg!(feature = "proteus") {
        let spinner = RunningProcess::new("Building Cryptobox ESM bundle...", false);

        Command::new("bun")
            .args(["install"])
            .current_dir(cwd.join("interop/src/build/web/cryptobox-esm"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await?;

        Command::new("bun")
            .args(["run", "build"])
            .current_dir(cwd.join("interop/src/build/web/cryptobox-esm"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await?;

        spinner.success("Cryptobox ESM bundle [OK]");
    }

    let spinner = RunningProcess::new("Building WASM bundle...", false);

    Command::new("cargo")
        .args(["make", "wasm"])
        .current_dir(cwd.join("crypto-ffi"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;

    Command::new("bun")
        .args(["run", "build"])
        .current_dir(cwd.join("crypto-ffi/bindings/js"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;

    std::fs::copy(
        cwd.join("crypto-ffi/bindings/js/test/index.html"),
        wasm_deploy_path.join("index.html"),
    )?;

    std::fs::copy(
        cwd.join("crypto-ffi/bindings/js/src/corecrypto.js"),
        wasm_deploy_path.join("corecrypto.js"),
    )?;

    std::fs::copy(
        cwd.join("crypto-ffi/bindings/js/src/corecrypto.d.ts"),
        wasm_deploy_path.join("corecrypto.d.ts"),
    )?;

    std::fs::copy(
        cwd.join("crypto-ffi/bindings/js/src/core-crypto-ffi_bg.wasm"),
        wasm_deploy_path.join("core-crypto-ffi_bg.wasm"),
    )?;

    spinner.success("WASM bundle [OK]");
    Ok(())
}

pub(crate) async fn spawn_http_server(wasm_deploy_path: PathBuf) -> Result<()> {
    use warp::Filter as _;
    let addr = SocketAddr::from(([0, 0, 0, 0], TEST_SERVER_PORT.parse()?));
    let warp_filter_cc = warp::path("core-crypto").and(warp::fs::dir(wasm_deploy_path));
    let warp_filter_cbox =
        warp::path("cryptobox").and(warp::fs::dir("interop/src/build/web/cryptobox-esm/dist".to_string()));

    warp::serve(warp_filter_cc.or(warp_filter_cbox).boxed())
        .bind(addr)
        .await;

    Ok(())
}
