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
mod webdriver;
mod webdriver_bidi_protocol;

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
    webdriver_bidi_uri: Option<String>,
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

        let serde_json::Value::Object(caps) = serde_json::json!({
            "webSocketUrl": true,
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
        }) else {
            unreachable!("`serde_json::json!()` did not produce an object when provided an object. Something is broken.")
        };

        let browser = fantoccini::ClientBuilder::rustls()
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
            log::info!("WebDriver BiDi Supported; url: {ws_bidi_uri}");
        } else {
            log::warn!("WebDriver implementation does not support BiDi!");
        }

        Ok(Self {
            browser,
            kind,
            driver,
            driver_addr,
            timeout: std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            webdriver_bidi_uri,
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

    async fn connect_bidi(
        &self,
    ) -> WasmBrowserRunResult<
        std::pin::Pin<
            Box<impl futures_util::Stream<Item = WasmBrowserRunResult<crate::webdriver_bidi_protocol::local::Event>>>,
        >,
    > {
        use crate::webdriver_bidi_protocol::local::Event;
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::protocol::Message;

        let Some(ws_bidi_uri) = &self.webdriver_bidi_uri else {
            return Err(WebdriverError::NoWebDriverBidiSupport.into());
        };

        log::warn!(target: "webdriver_bidi", "Connecting to WebDriver BiDi server at {ws_bidi_uri}");

        let (ws_client, _) = tokio_tungstenite::connect_async(ws_bidi_uri)
            .await
            .map_err(WebdriverError::from)?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
        let rx = tokio_stream::wrappers::ReceiverStream::new(rx);
        let (ws_client_tx, ws_client_rx) = ws_client.split();

        log::warn!(target: "webdriver_bidi", "Setting up stream and WebSocket ping/pong handler");
        tokio::task::spawn(rx.map(|payload| Ok(Message::Pong(payload))).forward(ws_client_tx));

        let debug = self.debug;

        let wrapped_stream = ws_client_rx.filter_map(move |msg| {
            let tx_inner = tx.clone();
            async move {
                let msg_raw = match msg {
                    Ok(msg) => match msg {
                        Message::Ping(payload) => {
                            let _ = tx_inner.send(payload).await;
                            return None;
                        }
                        Message::Close(_) | Message::Pong(_) => return None,
                        msg @ _ => msg.into_data(),
                    },
                    Err(e) => {
                        log::error!("{e}");
                        return Some(Err(e.into()));
                    }
                };

                let event: Event = match serde_json::from_slice(&msg_raw) {
                    Ok(event) => event,
                    Err(e) => {
                        log::error!("Failed to deserialize payload: {e:?}");
                        return None;
                    }
                };

                if debug {
                    dbg!(&event);
                }

                Some(WasmBrowserRunResult::Ok(event))
            }
        });

        Ok(Box::pin(wrapped_stream))
    }
}
