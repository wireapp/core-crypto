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

pub(crate) fn bind_http_server(wasm_deploy_path: PathBuf) -> (SocketAddr, impl Future<Output = ()> + 'static) {
    use warp::Filter as _;
    let warp_filter_cc = warp::path("core-crypto").and(warp::fs::dir(wasm_deploy_path));
    let warp_filter_cbox =
        warp::path("cryptobox").and(warp::fs::dir("interop/src/build/web/cryptobox-esm/dist".to_string()));

    warp::serve(warp_filter_cc.or(warp_filter_cbox).boxed()).bind_ephemeral(([0, 0, 0, 0], 0))
}
