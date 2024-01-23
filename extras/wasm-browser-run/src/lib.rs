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
mod wasm_test;
pub mod webdriver;
pub mod webdriver_bidi_protocol;

use crate::error::*;

pub use crate::webdriver::WebdriverKind;

pub const DEFAULT_TIMEOUT_SECS: u64 = 20;

#[derive(Debug)]
#[allow(dead_code)]
struct WebdriverContextInner {
    pub(crate) browser: fantoccini::Client,
    pub(crate) driver: tokio::process::Child,
    pub(crate) driver_addr: std::net::SocketAddr,
    pub(crate) webdriver_bidi_uri: Option<String>,
}

impl WebdriverContextInner {
    pub(crate) async fn init(
        driver_location: &std::path::Path,
        timeout: std::time::Duration,
    ) -> WasmBrowserRunResult<Self> {
        let driver_addr = tokio::net::TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let driver = tokio::process::Command::new(driver_location)
            .arg(format!("--port={}", driver_addr.port()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
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

        let mut raw_json = serde_json::json!({
            "webSocketUrl": true,
            "timeouts": {
                "script": timeout.as_secs() * 1000,
            },
            "goog:chromeOptions": {
                "args": [
                    "headless",
                    "disable-dev-shm-usage",
                    "no-sandbox"
                ]
            },
            "ms:edgeOptions": {
                "args": [
                    "headless",
                    "disable-dev-shm-usage",
                    "no-sandbox"
                ]
            },
            "moz:firefoxOptions": {
                "args": ["-headless"]
            }
        });

        // Useful for CI override of installed binaries
        if let Ok(chrome_path) = std::env::var("CHROME_PATH") {
            raw_json["goog:chromeOptions"]["binary"] = chrome_path.into();
        }

        if let Ok(edge_path) = std::env::var("EDGE_PATH") {
            raw_json["ms:edgeOptions"]["binary"] = edge_path.into();
        }

        if let Ok(firefox_path) = std::env::var("FIREFOX_PATH") {
            raw_json["moz:firefoxOptions"]["binary"] = firefox_path.into();
        }

        let serde_json::Value::Object(caps) = raw_json else {
            unreachable!(
                "`serde_json::json!()` did not produce an object when provided an object. Something is broken."
            )
        };

        let browser = fantoccini::ClientBuilder::native()
            .capabilities(caps)
            .connect(&format!("http://{driver_addr}"))
            .await
            .map_err(WebdriverError::from)?;

        let browser_session_handshake = browser.get_session_handshake();
        let webdriver_bidi_uri = browser_session_handshake["capabilities"]
            .get("webSocketUrl")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());

        if let Some(ws_bidi_uri) = &webdriver_bidi_uri {
            tracing::info!("WebDriver BiDi Supported; url: {ws_bidi_uri}");
        } else {
            tracing::warn!("WebDriver implementation does not support BiDi!");
        }

        Ok(Self {
            browser,
            driver,
            driver_addr,
            webdriver_bidi_uri,
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct WebdriverContext {
    kind: WebdriverKind,
    ctx: Option<WebdriverContextInner>,
    driver_location: std::path::PathBuf,
    timeout: std::time::Duration,
    avoid_bidi: bool,
    nocapture: bool,
    debug: bool,
}

impl WebdriverContext {
    pub async fn init(kind: WebdriverKind, force_install: bool) -> WasmBrowserRunResult<Self> {
        match kind {
            WebdriverKind::Chrome => {}
            k => return Err(WasmBrowserRunError::UnsupportedWebdriver(k.to_string())),
        }

        let wd_dir = dirs::home_dir()
            .ok_or_else(|| WasmBrowserRunError::IoError(std::io::ErrorKind::NotFound.into()))?
            .join(".webdrivers");

        kind.install_webdriver(&wd_dir, force_install).await?;
        let driver_location = wd_dir.join(kind.as_exe_name());

        if !driver_location.exists() {
            let sh = xshell::Shell::new()?;
            xshell::cmd!(sh, "ls -al {wd_dir}").run()?;
            return Err(WasmBrowserRunError::WebDriverExecutableNotFound(kind));
        }

        Ok(Self {
            kind,
            ctx: None,
            driver_location,
            timeout: std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            avoid_bidi: false,
            nocapture: false,
            debug: false,
        })
    }

    /// Act as if WebDriver BiDi isn't supported
    pub fn avoid_bidi(mut self, avoid: bool) -> Self {
        self.avoid_bidi = avoid;
        self
    }

    /// Disables log capture -
    pub fn disable_log_capture(mut self, nocapture: bool) -> Self {
        self.nocapture = nocapture;
        self
    }

    pub fn with_timeout(mut self, mut timeout: Option<std::time::Duration>) -> Self {
        if let Some(timeout) = timeout.take() {
            self.timeout = timeout;
        }
        self
    }

    pub fn enable_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    pub async fn webdriver_init(&mut self) -> WasmBrowserRunResult<()> {
        self.ctx = Some(WebdriverContextInner::init(&self.driver_location, self.timeout).await?);
        Ok(())
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
        tracing::debug!("HTTP server address spawned at http://{addr}");
        Ok((hwnd, addr))
    }

    pub async fn run_wasm_calls(
        &self,
        wasm_file_path: &std::path::Path,
        js: &str,
    ) -> WasmBrowserRunResult<serde_json::Value> {
        let Some(ctx) = &self.ctx else {
            return Err(WasmBrowserRunError::WebDriverContextNotInitialized);
        };

        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let mount_point = self
            .compile_js_support(Some(&format!("window.__wbr__jsCall = async () => {{ {js} }};")))
            .await?;
        let (hwnd, socket_addr) = Self::spawn_http_server(&mount_point).await?;

        let window = ctx.browser.new_window(true).await.map_err(WebdriverError::from)?;
        ctx.browser
            .switch_to_window(window.handle)
            .await
            .map_err(WebdriverError::from)?;

        ctx.browser
            .goto(&format!("http://{socket_addr}/"))
            .await
            .map_err(WebdriverError::from)?;

        let result = ctx
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

        ctx.browser.close_window().await.map_err(WebdriverError::from)?;

        hwnd.abort();
        let _ = hwnd.await;

        Ok(result)
    }

    pub async fn run_js(&self, js: &str) -> WasmBrowserRunResult<serde_json::Value> {
        let Some(ctx) = &self.ctx else {
            return Err(WasmBrowserRunError::WebDriverContextNotInitialized);
        };

        let mount_point = self
            .compile_js_support(Some(&format!("window.__wbr__jsCall = async () => {{ {js} }};")))
            .await?;
        let (hwnd, socket_addr) = Self::spawn_http_server(&mount_point).await?;

        let window = ctx.browser.new_window(true).await.map_err(WebdriverError::from)?;
        ctx.browser
            .switch_to_window(window.handle)
            .await
            .map_err(WebdriverError::from)?;

        ctx.browser
            .goto(&format!("http://{socket_addr}/"))
            .await
            .map_err(WebdriverError::from)?;

        let result = ctx
            .browser
            .execute_async(
                r#"
const [callback] = arguments;
window.__wbr__jsCall().then(callback);"#,
                vec![],
            )
            .await
            .map_err(WebdriverError::from)?;

        ctx.browser.close_window().await.map_err(WebdriverError::from)?;

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

        tracing::info!("Starting JS support compilation at {js_builder_path:?}");
        let npm_install_ok = tokio::process::Command::new("npm")
            .current_dir(&js_builder_path)
            .arg("install")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await?
            .success();

        if !npm_install_ok {
            return Err(eyre::eyre!(
                "`npm install` returned an error. Probably something wrong with the setup. Is Node.js installed?"
            )
            .into());
        }

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

    async fn connect_bidi(
        &self,
    ) -> WasmBrowserRunResult<
        std::pin::Pin<
            Box<impl futures_util::Stream<Item = WasmBrowserRunResult<crate::webdriver_bidi_protocol::local::Event>>>,
        >,
    > {
        let Some(ctx) = &self.ctx else {
            return Err(WasmBrowserRunError::WebDriverContextNotInitialized);
        };

        use crate::webdriver_bidi_protocol::local::Event;
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::protocol::Message;

        let Some(ws_bidi_uri) = &ctx.webdriver_bidi_uri else {
            return Err(WebdriverError::NoWebDriverBidiSupport.into());
        };

        tracing::info!(target: "webdriver_bidi", "Connecting to WebDriver BiDi server at {ws_bidi_uri}");

        let (ws_client, _) = tokio_tungstenite::connect_async(ws_bidi_uri)
            .await
            .map_err(WebdriverError::from)?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
        let rx = tokio_stream::wrappers::ReceiverStream::new(rx);
        let (ws_client_tx, ws_client_rx) = ws_client.split();

        tracing::debug!(target: "webdriver_bidi", "Setting up stream and WebSocket ping/pong handler");
        tokio::task::spawn(
            rx.map(|payload| Ok(Message::Pong(payload)))
                .forward(Box::pin(ws_client_tx)),
        );

        let debug = self.debug;

        let wrapped_stream = ws_client_rx.filter_map(move |msg| {
            // dbg!(&msg);
            let tx_inner = tx.clone();
            async move {
                if debug {
                    tracing::debug!(target: "webdriver_bidi", "Got raw msg: {msg:?}");
                }

                let msg_raw = match msg {
                    Ok(msg) => match msg {
                        Message::Ping(payload) => {
                            tracing::debug!(target: "webdriver_bidi", "BiDi WS Ping: {}", hex::encode(&payload));
                            let _ = tx_inner.send(payload).await;
                            return None;
                        }
                        Message::Close(msg) => {
                            tracing::debug!(target: "webdriver_bidi", "Got BiDi WS Close message: {msg:?}");
                            return None;
                        }
                        Message::Pong(payload) => {
                            tracing::debug!(target: "webdriver_bidi", "BiDi WS Pong: {}", hex::encode(payload));
                            return None;
                        }
                        msg @ _ => msg.into_data(),
                    },
                    Err(e) => {
                        tracing::error!("{e}");
                        return Some(Err(e.into()));
                    }
                };

                if debug {
                    tracing::debug!(target: "webdriver_bidi", "Got raw msg payload: {}", hex::encode(&msg_raw));
                }

                let event: Event = match serde_json::from_slice(&msg_raw) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!("Failed to deserialize payload: {e:?}");
                        return None;
                    }
                };

                if debug {
                    tracing::debug!(target: "webdriver_bidi", "{event:?}");
                }

                Some(WasmBrowserRunResult::Ok(event))
            }
        });

        Ok(Box::pin(wrapped_stream))
    }
}
