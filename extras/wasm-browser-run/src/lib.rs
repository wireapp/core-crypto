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
mod webdriver_bidi;

use crate::error::*;

pub use crate::webdriver::WebdriverKind;

pub const DEFAULT_TIMEOUT_SECS: u64 = 20;

#[derive(Debug)]
#[allow(dead_code)]
pub struct WebdriverContext {
    kind: WebdriverKind,
    browser: fantoccini::Client,
    driver: tokio::process::Child,
    driver_addr: std::net::SocketAddr,
    timeout: std::time::Duration,
}

impl WebdriverContext {
    pub async fn init(kind: WebdriverKind, force_install: bool) -> WasmBrowserRunResult<Self> {
        Self::init_with_timeout(kind, force_install, None).await
    }

    pub async fn init_with_timeout(
        kind: WebdriverKind,
        force_install: bool,
        timeout: Option<std::time::Duration>,
    ) -> WasmBrowserRunResult<Self> {
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

        let webdriver_start_timeout = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();
        let mut webdriver_ready = false;
        while start.elapsed() < webdriver_start_timeout {
            webdriver_ready = tokio::net::TcpStream::connect(&driver_addr).await.is_ok();
            if webdriver_ready {
                break;
            }
        }

        if !webdriver_ready {
            return Err(WasmBrowserRunError::WebDriverTimeoutError);
        }

        let timeout = timeout.unwrap_or_else(|| std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let caps = serde_json::Map::from_iter(
            vec![
                ("webSocketUrl".to_string(), true.into()),
                (
                    "timeouts".to_string(),
                    serde_json::json!({
                        "script": timeout.as_secs() * 1000
                    }),
                ),
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

        let browser_session_handshake = browser.get_session_handshake();
        let ws_bidi_uri = browser_session_handshake["capabilities"]
            .get("webSocketUrl")
            .ok_or_else(|| WebdriverError::NoWebDriverBidiSupport)?
            .as_str()
            .ok_or_else(|| WebdriverError::NoWebDriverBidiSupport)?
            .to_string();

        log::info!("WebDriver BiDi ws url: {ws_bidi_uri}");

        let (mut ws_client, _) = tokio_tungstenite::connect_async(&ws_bidi_uri)
            .await
            .map_err(WebdriverError::from)?;

        tokio::spawn(async move {
            use crate::webdriver_bidi::{
                local::{Event, EventData},
                log::{LogEntryInner, LogEvent},
            };
            use futures_util::{SinkExt as _, StreamExt as _};
            use tokio_tungstenite::tungstenite::protocol::Message;

            while let Some(msg) = ws_client.next().await {
                let msg_raw = match msg {
                    Ok(msg) => match msg {
                        Message::Close(_) => {
                            break;
                        }
                        Message::Ping(payload) => {
                            ws_client.send(Message::Pong(payload)).await?;
                            continue;
                        }
                        Message::Pong(_) => continue,
                        msg @ _ => msg.into_data(),
                    },
                    Err(e) => {
                        log::error!("{e}");
                        return Err(e.into());
                    }
                };
                dbg!(serde_json::from_slice::<serde_json::Value>(&msg_raw)?);
                let event: Event = match serde_json::from_slice(&msg_raw) {
                    Ok(event) => event,
                    Err(e) => {
                        log::error!("Failed to deserialize payload: {e:?}");
                        continue;
                    }
                };
                dbg!(&event);
                match event.data {
                    EventData::BrowsingContextEvent(data) => {
                        log::info!("Unimplemented event handling: {:?}", data);
                    }
                    EventData::ScriptEvent(data) => {
                        log::info!("Unimplemented event handling: {:?}", data);
                    }
                    EventData::LogEvent(log_event) => match log_event {
                        LogEvent::EntryAdded(log_entry) => {
                            match log_entry.entry_data {
                                LogEntryInner::Console(console_log) => {
                                    let level = console_log.entry.level.into();
                                    log::log!(target: "webdriver_bidi", level, "{}", console_log);
                                }
                                LogEntryInner::Base(base_log) => {
                                    let level = base_log.level.into();
                                    log::log!(target: "webdriver_bidi", level, "{}", base_log);
                                }
                            };
                        }
                    },
                }
            }

            WasmBrowserRunResult::Ok(())
        });

        Ok(Self {
            browser,
            kind,
            driver,
            driver_addr,
            timeout,
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
        log::debug!("HTTP server address spawned at http://{addr}");
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
        let js_builder_path = std::path::PathBuf::from(file!())
            .parent()
            .and_then(std::path::Path::parent)
            .expect("Incorrect folder structure, cannot find the `js-builder` folder")
            .join("js-builder");

        if !js_builder_path.exists() {
            return Err(eyre::eyre!("Incorrect folder structure, cannot find the `js-builder` folder").into());
        }

        log::warn!("Starting JS support compilation at {js_builder_path:?}");
        let mut builder_hwnd = tokio::process::Command::new("npm")
            .current_dir(&js_builder_path)
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
            Ok(js_builder_path.join("dist").canonicalize()?.to_string_lossy().into())
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
        let test_exports: Vec<String> = module
            .exports
            .iter()
            // exports starting with "__wbgt_" (wasm-bindgen-test) are `#[wasm_bindgen::test]`-marked functions
            .filter(|e| e.name.starts_with("__wbgt_"))
            .map(|e| e.name.clone())
            .collect();

        if test_exports.is_empty() {
            return Ok(Self {
                location,
                module,
                tests: test_exports,
            });
        }

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
        .ok_or_else(|| eyre::eyre!("file to test doesn't follow the expected Cargo conventions"))?;

        // Make sure no stale state is there, and recreate tempdir
        tokio::fs::remove_dir_all(&tmpdir).await?;
        tokio::fs::create_dir(&tmpdir).await?;

        Ok(tmpdir)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TestResultContainerSummary {
    pub successful: bool,
    pub success: u64,
    pub fail: u64,
    pub ignored: u64,
    pub total: u64,
}

/// interface TestResultContainer {
///     details: [string, boolean][],
///     summary: {
///         successful: boolean,
///         success: number,
///         fail: number,
///         ignored: number,
///     },
/// }
#[derive(Debug, Clone, serde::Deserialize)]
struct TestResultContainer {
    pub details: Vec<(String, bool)>,
    pub summary: TestResultContainerSummary,
}

impl WebdriverContext {
    #[allow(dead_code)]
    async fn get_text_from_div(browser: &fantoccini::Client, id: &str) -> WasmBrowserRunResult<String> {
        let element = browser
            .find(fantoccini::Locator::Id(id))
            .await
            .map_err(WebdriverError::from)?;

        Ok(element.text().await.map_err(WebdriverError::from)?)
    }

    pub async fn wasm_tests_list(
        &self,
        wasm_file_path: &std::path::Path,
        only_ignored: bool,
    ) -> WasmBrowserRunResult<Vec<String>> {
        // TODO: Support introspecting ignored tests
        if only_ignored {
            return Ok(vec![]);
        }

        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let wasm_tests_ctx = WasmTestFileContext::new(wasm_file_path)?;

        Ok(wasm_tests_ctx.tests)
    }

    pub async fn run_wasm_tests(
        &self,
        wasm_file_path: &std::path::Path,
        mut exact_test: Option<String>,
    ) -> WasmBrowserRunResult<bool> {
        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let wasm_tests_ctx = WasmTestFileContext::new(wasm_file_path)?;

        log::warn!("Tests to run: {:?}", wasm_tests_ctx.tests);

        if wasm_tests_ctx.tests.is_empty() {
            log::info!("No tests to run!");
            return Ok(true);
        }

        log::warn!("Getting wasm-bindgen tmp dir");
        let tmpdir = wasm_tests_ctx.bindgen_get_tmpdir().await?;
        log::warn!("wasm-bindgen tmp dir: {tmpdir:?}");

        let module_name = wasm_file_path.file_name().unwrap().to_str().unwrap();

        let mut bindgen = wasm_bindgen_cli_support::Bindgen::new();
        bindgen
            .web(true)
            .map_err(|e| eyre::eyre!("{e}"))?
            .input_module(module_name, wasm_tests_ctx.module)
            .debug(false)
            .keep_debug(false)
            .emit_start(false)
            .generate(&tmpdir)
            .map_err(|e| eyre::eyre!("{e}"))?;

        let mount_point = self.compile_js_support(None).await?;
        let wasm_file_name: std::path::PathBuf = module_name.into();
        let mount_point_path = std::path::PathBuf::from(&mount_point);
        log::warn!("Mount point path: {mount_point_path:?}");
        let base = tmpdir.join(module_name);
        let dest = mount_point_path.join(&wasm_file_name).with_extension("");

        let from = base.with_extension("js");
        let to = dest.with_extension("js");
        log::warn!("cp {from:?} -> {to:?}");
        tokio::fs::copy(&from, &to).await?;

        let from = base.with_extension("wasm");
        let to = dest.with_extension("wasm");
        log::warn!("cp {from:?} -> {to:?}");
        tokio::fs::copy(&from, &to).await?;

        let (hwnd, socket_addr) = Self::spawn_http_server(&mount_point).await?;

        let test_file_name = dest.file_name().unwrap().to_string_lossy();

        let window = self.browser.new_window(true).await.map_err(WebdriverError::from)?;
        self.browser
            .switch_to_window(window.handle)
            .await
            .map_err(WebdriverError::from)?;

        self.browser
            .goto(&format!("http://{socket_addr}/"))
            .await
            .map_err(WebdriverError::from)?;

        let now = std::time::Instant::now();

        let tests_list = if let Some(exact_test) = exact_test.take() {
            wasm_tests_ctx
                .tests
                .into_iter()
                .filter(|test_name| *test_name == exact_test)
                .collect()
        } else {
            wasm_tests_ctx.tests
        };

        let raw_results = self
            .browser
            .execute_async(
                r#"
const [fileName, testsList, callback] = arguments;
window.runTests(fileName, testsList).then(callback)"#,
                vec![test_file_name.clone().into(), tests_list.into()],
            )
            .await
            .map_err(WebdriverError::from)?;

        let test_results: TestResultContainer = serde_json::from_value(raw_results)?;

        println!("\nrunning {} tests\n", test_results.summary.total);
        for (test_name, test_result) in test_results.details.iter() {
            let (color, result_str) = if *test_result {
                (better_term::Color::BrightGreen, "ok")
            } else {
                (better_term::Color::Red, "fail")
            };
            println!(
                "test {test_name} ... {color}{result_str}{}",
                better_term::Color::Default
            );
        }

        let (color, result_str) = if test_results.summary.successful {
            (better_term::Color::BrightGreen, "ok")
        } else {
            (better_term::Color::Red, "fail")
        };
        println!(
            "\ntest result: {color}{result_str}{}. {} passed; {} failed; {} ignored; finished in {:.2}s\n",
            better_term::Color::Default,
            test_results.summary.success,
            test_results.summary.fail,
            test_results.summary.ignored,
            now.elapsed().as_secs_f64()
        );

        // Wait for control element (inserted when tests are done)
        // use fantoccini::Locator;

        // let control_elem_id = format!("control_{test_file_name}");

        // let wait_result = self
        //     .browser
        //     .wait()
        //     .at_most(self.timeout)
        //     .for_element(Locator::Id(&control_elem_id))
        //     .await;

        // let result = match wait_result {
        //     Ok(element) => {
        //         let text = element.text().await.map_err(WebdriverError::from)?;
        //         if !text.is_empty() {
        //             return Err(WasmBrowserRunError::ErrorThrownInTest(text));
        //         }
        //         true
        //     }
        //     Err(fantoccini::error::CmdError::WaitTimeout) => {
        //         log::error!(
        //             "Tests have not finished within the allotted timeout ({} seconds)",
        //             self.timeout.as_secs()
        //         );
        //         false
        //     }
        //     Err(e) => return Err(WebdriverError::from(e).into()),
        // };

        // if result {
        //     log::info!("Tests OK");
        // } else {
        //     log::error!("Tests finished with one or more errors");
        // }

        self.browser.close_window().await.map_err(WebdriverError::from)?;

        hwnd.abort();
        let _ = hwnd.await;

        Ok(true)
    }
}
