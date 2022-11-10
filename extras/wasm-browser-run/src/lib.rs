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

pub mod error;
mod webdriver;

use crate::error::*;

pub use crate::webdriver::WebdriverKind;

#[derive(Debug)]
#[allow(dead_code)]
pub struct WebdriverContext {
    kind: WebdriverKind,
    browser: fantoccini::Client,
    driver: tokio::process::Child,
    driver_addr: std::net::SocketAddr,
}

impl WebdriverContext {
    pub async fn init(kind: WebdriverKind, force_install: bool) -> WasmBrowserRunResult<Self> {
        match kind {
            WebdriverKind::Chrome => {}
            k => return Err(WasmBrowserRunError::UnsupportedWebdriver(k.to_string())),
        }

        let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");

        let driver_location = wd_dir.join(kind.as_exe_name());
        if !driver_location.exists() {
            kind.install_webdriver(&wd_dir, force_install).await?;
        }

        let driver_addr = tokio::net::TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let driver = tokio::process::Command::new(driver_location)
            .arg(format!("--port={}", driver_addr.port()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        let caps = serde_json::Map::from_iter(
            vec![
                ("websocketUrl".to_string(), true.into()),
                (
                    "goog:chromeOptions".to_string(),
                    serde_json::json!({
                        "args": [
                            "headless",
                            "disable-dev-shm-usage",
                            "no-sandbox"
                        ]
                    }),
                ),
                (
                    "ms:edgeOptions".to_string(),
                    serde_json::json!({
                        "args": [
                            "headless",
                            "disable-dev-shm-usage",
                            "no-sandbox"
                        ]
                    }),
                ),
                (
                    "moz:firefoxOptions".to_string(),
                    serde_json::json!({
                        "args": ["-headless"]
                    }),
                ),
            ]
            .into_iter(),
        );

        let browser = fantoccini::ClientBuilder::native()
            .capabilities(caps)
            .connect(&format!("http://{driver_addr}"))
            .await
            .map_err(WebdriverError::from)?;

        Ok(Self {
            browser,
            kind,
            driver,
            driver_addr,
        })
    }

    async fn run_http_server(addr: std::net::SocketAddr, mount_point: String) -> WasmBrowserRunResult<()> {
        let mount_point_path = std::path::PathBuf::from(&mount_point);
        if !mount_point_path.exists() {
            return Err(WasmBrowserRunError::MountPointNotFound(mount_point));
        }
        use warp::http::header::{HeaderMap, HeaderValue};
        use warp::Filter as _;

        let mut headers = HeaderMap::new();
        headers.insert("Cross-Origin-Opener-Policy", HeaderValue::from_static("same-origin"));
        headers.insert("Cross-Origin-Embedder-Policy", HeaderValue::from_static("require-corp"));

        let filter = warp::fs::dir(mount_point_path).with(warp::reply::with::headers(headers));

        warp::serve(filter).bind(addr).await;

        Ok(())
    }

    async fn spawn_http_server(
        mount_point: &str,
    ) -> WasmBrowserRunResult<(tokio::task::JoinHandle<WasmBrowserRunResult<()>>, std::net::SocketAddr)> {
        let addr = tokio::net::TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let hwnd = tokio::task::spawn(Self::run_http_server(addr.clone(), mount_point.to_string()));
        Ok((hwnd, addr))
    }

    pub async fn run_wasm_calls(
        &self,
        wasm_file_path: &std::path::Path,
        js: &str,
    ) -> WasmBrowserRunResult<serde_json::Value> {
        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let mount_point = self
            .compile_js_support(Some(&format!("window.__wbr__jsCall = async () => {{ {js} }};")))
            .await?;
        let (hwnd, socket_addr) = Self::spawn_http_server(&mount_point).await?;

        let window = self.browser.new_window(true).await.map_err(WebdriverError::from)?;
        self.browser
            .switch_to_window(window.handle)
            .await
            .map_err(WebdriverError::from)?;

        self.browser
            .goto(&format!("http://{socket_addr}/"))
            .await
            .map_err(WebdriverError::from)?;

        let result = self
            .browser
            .execute_async(
                r#"
const [wasm_path, callback] = arguments;
const wasm = await import(wasm_path);
window.__wbr__jsCall().then(callback);"#,
                vec![wasm_file_path.to_string_lossy().into()],
            )
            .await
            .map_err(WebdriverError::from)?;

        self.browser.close_window().await.map_err(WebdriverError::from)?;

        hwnd.abort();
        let _ = hwnd.await;

        Ok(result)
    }

    pub async fn run_js(&self, js: &str) -> WasmBrowserRunResult<serde_json::Value> {
        let mount_point = self
            .compile_js_support(Some(&format!("window.__wbr__jsCall = async () => {{ {js} }};")))
            .await?;
        let (hwnd, socket_addr) = Self::spawn_http_server(&mount_point).await?;

        let window = self.browser.new_window(true).await.map_err(WebdriverError::from)?;
        self.browser
            .switch_to_window(window.handle)
            .await
            .map_err(WebdriverError::from)?;

        self.browser
            .goto(&format!("http://{socket_addr}/"))
            .await
            .map_err(WebdriverError::from)?;

        let result = self
            .browser
            .execute_async(
                r#"
const [callback] = arguments;
window.__wbr__jsCall().then(callback);"#,
                vec![],
            )
            .await
            .map_err(WebdriverError::from)?;

        self.browser.close_window().await.map_err(WebdriverError::from)?;

        hwnd.abort();
        let _ = hwnd.await;

        Ok(result)
    }

    async fn compile_js_support(&self, mut js: Option<&str>) -> WasmBrowserRunResult<String> {
        let mut builder_hwnd = tokio::process::Command::new("npm")
            .current_dir("./js-builder")
            .arg("start")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        if let Some(js) = js.take() {
            let mut stdin = builder_hwnd.stdin.take().expect("No stdin in npm process!");

            use tokio::io::AsyncWriteExt as _;
            stdin.write_all(js.as_bytes()).await?;

            drop(stdin);
        }

        let out_status = builder_hwnd.wait_with_output().await?;
        if out_status.status.success() {
            Ok(std::path::Path::new("./dist").canonicalize()?.to_string_lossy().into())
        } else {
            let output_str = String::from_utf8_lossy(&out_status.stdout);
            Err(WasmBrowserRunError::NpmError(output_str.to_string()))
        }
    }
}

#[derive(Debug)]
struct WasmTestFileContext {
    pub location: std::path::PathBuf,
    pub tests: Vec<String>,
    pub module: walrus::Module,
}

impl WasmTestFileContext {
    pub fn new(wasm_file_path: impl AsRef<std::path::Path>) -> WasmBrowserRunResult<Self> {
        let location = wasm_file_path.as_ref().to_owned();
        let mut module = walrus::Module::from_file(wasm_file_path).map_err(|e| eyre::eyre!("{e:?}"))?;
        let test_exports = module
            .exports
            .iter()
            // exports starting with "__wbgt_" (wasm-bindgen-test) are `#[wasm_bindgen::test]`-marked functions
            .filter(|e| e.name.starts_with("__wbgt_"))
            .map(|e| e.name.clone())
            .collect();

        let section = module
            .customs
            .remove_raw("__wasm_bindgen_test_unstable")
            .ok_or_else(|| WasmBrowserRunError::InvalidBuildTarget)?;

        if !section.data.contains(&0x01) {
            return Err(WasmBrowserRunError::InvalidWasmBindgenTestCustomSection(hex::encode(
                section.data,
            )));
        }

        let ctx = Self {
            location,
            tests: test_exports,
            module,
        };

        Ok(ctx)
    }

    /// This is for WASM bindgen compatibility purposes;
    ///
    /// See: https://github.com/rustwasm/wasm-bindgen/blob/main/crates/cli/src/bin/wasm-bindgen-test-runner/main.rs#L50
    async fn bindgen_get_tmpdir(&self) -> WasmBrowserRunResult<std::path::PathBuf> {
        let tmpdir = if self.location.to_string_lossy().starts_with("/tmp/rustdoc") {
            self.location.parent()
        } else {
            self.location
                .parent()
                .and_then(std::path::Path::parent)
                .and_then(std::path::Path::parent)
        }
        .map(|p| p.join("wbg-tmp"))
        .ok_or_else(|| eyre::eyre!("file to test doens't follow the expected Cargo conventions"))?;

        // Make sure no stale state is there, and recreate tempdir
        tokio::fs::remove_dir_all(&tmpdir).await?;
        tokio::fs::create_dir(&tmpdir).await?;

        Ok(tmpdir)
    }
}

impl WebdriverContext {
    pub async fn run_wasm_tests(&self, wasm_file_path: &std::path::Path) -> WasmBrowserRunResult<serde_json::Value> {
        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let wasm_tests_ctx = WasmTestFileContext::new(wasm_file_path)?;

        if wasm_tests_ctx.tests.is_empty() {
            return Ok("No tests to run".into());
        }

        let tmpdir = wasm_tests_ctx.bindgen_get_tmpdir().await?;

        let module_name = "wasm-bindgen-test";

        let mut bindgen = wasm_bindgen_cli_support::Bindgen::new();
        bindgen
            .web(true)
            .map_err(|e| eyre::eyre!("{e}"))?
            .debug(true)
            .input_module(module_name, wasm_tests_ctx.module)
            .keep_debug(true)
            .emit_start(false)
            .generate(&tmpdir)
            .map_err(|e| eyre::eyre!("{e}"))?;

        let mount_point = self.compile_js_support(None).await?;
        let wasm_file_name: std::path::PathBuf = wasm_file_path.file_name().unwrap().to_str().unwrap().into();
        let mount_point_path = std::path::PathBuf::from(&mount_point);
        tokio::fs::copy(wasm_file_path, mount_point_path.join(&wasm_file_name)).await?;
        let (hwnd, socket_addr) = Self::spawn_http_server(&mount_point).await?;

        let window = self.browser.new_window(true).await.map_err(WebdriverError::from)?;
        self.browser
            .switch_to_window(window.handle)
            .await
            .map_err(WebdriverError::from)?;

        self.browser
            .goto(&format!("http://{socket_addr}/"))
            .await
            .map_err(WebdriverError::from)?;

        let result = self
            .browser
            .execute_async(
                r#"
const [wasmFileLocation, testList, callback] = arguments;
window.runTests(wasmFileLocation, testsList).then(callback);"#,
                vec![wasm_file_name.to_string_lossy().into(), wasm_tests_ctx.tests.into()],
            )
            .await
            .map_err(WebdriverError::from)?;

        self.browser.close_window().await.map_err(WebdriverError::from)?;

        hwnd.abort();
        let _ = hwnd.await;

        Ok(result)
    }
}
