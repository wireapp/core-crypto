use std::{io, net::SocketAddr, path::PathBuf, sync::mpsc, time::Duration};

use anyhow::Result;
use core_crypto::{CommitBundle as CcCommitBundle, HistorySecret, MlsTransport};
use core_crypto_ffi::{CommitBundle, HistorySecret as HistorySecretFfi};
use openmls::prelude::MlsMessageOut;
use spinoff::Spinner;
use tokio::sync::RwLock;
use which::which;

/// The lines a child process writes to stdout, read on a background thread.
///
/// Reading a pipe directly blocks until the next line arrives, possibly forever if the app on the other end has
/// hung. Reading through a channel instead lets every wait time out, and shows a closed pipe as an error rather
/// than as an endless run of empty lines.
#[derive(Debug)]
pub(crate) struct ChildLines {
    lines: mpsc::Receiver<io::Result<String>>,
}

impl ChildLines {
    pub(crate) fn new(output: impl io::Read + Send + 'static) -> Self {
        use io::BufRead as _;

        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in io::BufReader::new(output).lines() {
                if sender.send(line).is_err() {
                    // nobody is listening anymore
                    break;
                }
            }
        });
        Self { lines }
    }

    /// Wait up to `timeout` for the next line, without its line terminator.
    pub(crate) fn next_line(&self, timeout: Duration) -> Result<String> {
        use mpsc::RecvTimeoutError;

        match self.lines.recv_timeout(timeout) {
            Ok(line) => Ok(line?),
            Err(RecvTimeoutError::Timeout) => anyhow::bail!("no output within {timeout:?}"),
            Err(RecvTimeoutError::Disconnected) => anyhow::bail!("the output stream closed"),
        }
    }

    /// Wait until a line containing `needle` arrives, and return it.
    ///
    /// Lines before it are discarded. Fails if no such line arrives within `timeout`.
    pub(crate) fn wait_for(&self, needle: &str, timeout: Duration) -> Result<String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let line = self.next_line(remaining)?;
            if line.contains(needle) {
                return Ok(line);
            }
        }
    }
}

pub(crate) struct RunningProcess {
    spinner: Option<Spinner>,
    is_task: bool,
}

impl std::fmt::Debug for RunningProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningProcess")
            .field("is_task", &self.is_task)
            .finish()
    }
}

impl RunningProcess {
    pub(crate) fn new(msg: impl AsRef<str> + std::fmt::Display, is_task: bool) -> Self {
        let spinner = if std::env::var("CI").is_err() {
            Some(Spinner::new(
                spinoff::spinners::Aesthetic,
                msg.as_ref().to_owned(),
                if is_task {
                    spinoff::Color::Green
                } else {
                    spinoff::Color::Blue
                },
            ))
        } else {
            if is_task {
                log::info!("{msg}");
            } else {
                log::debug!("{msg}");
            }

            None
        };

        Self { spinner, is_task }
    }

    pub(crate) fn update(&mut self, msg: impl AsRef<str> + std::fmt::Display) {
        if let Some(spinner) = &mut self.spinner {
            spinner.update_text(msg.as_ref().to_owned());
        } else if self.is_task {
            log::info!("{msg}");
        } else {
            log::debug!("{msg}");
        }
    }

    pub(crate) fn success(self, msg: impl AsRef<str> + std::fmt::Display) {
        if let Some(mut spinner) = self.spinner {
            spinner.success(msg.as_ref());
        } else {
            log::info!("{msg}");
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait MlsTransportTestExt: MlsTransport {
    async fn latest_commit_bundle(&self) -> CcCommitBundle;
    async fn latest_welcome_message(&self) -> MlsMessageOut {
        self.latest_commit_bundle().await.welcome.unwrap().clone()
    }
}

#[derive(Debug, Default)]
pub(crate) struct MlsTransportSuccessProvider {
    latest_commit_bundle: RwLock<Option<CcCommitBundle>>,
}

#[async_trait::async_trait]
impl MlsTransport for MlsTransportSuccessProvider {
    async fn send_commit_bundle(&self, commit_bundle: CcCommitBundle) -> core_crypto::Result<()> {
        self.latest_commit_bundle.write().await.replace(commit_bundle);
        Ok(())
    }

    async fn prepare_for_transport(&self, secret: &HistorySecret) -> core_crypto::Result<core_crypto::TransportData> {
        Ok(format!("history_secret: {:?}", secret.client_id).into_bytes().into())
    }
}

#[async_trait::async_trait]
impl MlsTransportTestExt for MlsTransportSuccessProvider {
    async fn latest_commit_bundle(&self) -> CcCommitBundle {
        self.latest_commit_bundle
            .read()
            .await
            .clone()
            .expect("latest_commit_bundle")
    }
}

#[async_trait::async_trait]
impl core_crypto_ffi::MlsTransport for MlsTransportSuccessProvider {
    async fn send_commit_bundle(&self, _commit_bundle: CommitBundle) -> core_crypto_ffi::MlsTransportResult {
        Ok(())
    }

    async fn prepare_for_transport(&self, history_secret: HistorySecretFfi) -> core_crypto_ffi::MlsTransportData {
        core_crypto::TransportData::from(format!("history_secret: {:?}", history_secret.client_id).into_bytes()).into()
    }
}

/// Copy wasm files from sources into deployment path
pub(crate) fn cp_wasm_files(wasm_deploy_path: PathBuf) -> Result<()> {
    let cwd = std::env::current_dir()?;

    let spinner = RunningProcess::new("Copying data into WASM bundle...", false);

    std::fs::copy(
        cwd.join("interop/src/html/index.html"),
        wasm_deploy_path.join("index.html"),
    )?;

    std::fs::copy(
        cwd.join("crypto-ffi/bindings/js/packages/browser/dist/corecrypto.js"),
        wasm_deploy_path.join("corecrypto.js"),
    )?;

    std::fs::create_dir(wasm_deploy_path.join("autogenerated"))?;
    std::fs::copy(
        cwd.join("crypto-ffi/bindings/js/packages/browser/dist/autogenerated/core_crypto_ffi.wasm"),
        wasm_deploy_path.join("autogenerated/core_crypto_ffi.wasm"),
    )?;

    spinner.success("WASM bundle [OK]");
    Ok(())
}

pub(crate) async fn bind_http_server(wasm_deploy_path: PathBuf) -> (SocketAddr, impl Future<Output = ()> + 'static) {
    use warp::Filter as _;
    let warp_filter_cc = warp::path("core-crypto").and(warp::fs::dir(wasm_deploy_path));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (addr, warp::serve(warp_filter_cc).incoming(listener).run())
}

pub(crate) fn start_webdriver_chrome(addr: &std::net::SocketAddr) -> Result<tokio::process::Child> {
    let chromedriver_path = std::env::var_os("CHROMEDRIVER_PATH")
        .map(PathBuf::from)
        .or_else(|| which("chromedriver").ok())
        .expect("chromedriver must be in PATH or CHROMEDRIVER_PATH must be set");
    Ok(tokio::process::Command::new(chromedriver_path)
        .arg(format!("--port={}", addr.port()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?)
}

pub(crate) async fn setup_browser(
    client: &std::net::SocketAddr,
    server: &std::net::SocketAddr,
    folder: &str,
) -> Result<fantoccini::Client> {
    let spinner = RunningProcess::new("Starting Fantoccini remote browser...", false);
    let mut caps_json = serde_json::json!({
        "goog:chromeOptions": {
            "args": [
                "headless=shell",
                "disable-dev-shm-usage",
                "no-sandbox"
            ]
        }
    });

    if let Ok(chrome_path) = std::env::var("CHROME_PATH") {
        caps_json["goog:chromeOptions"]["binary"] = chrome_path.into();
    }

    let serde_json::Value::Object(caps) = caps_json else {
        unreachable!("`serde_json::json!()` did not produce an object when provided an object. Something is broken.")
    };

    let browser = fantoccini::ClientBuilder::native()
        .capabilities(caps)
        .connect(&format!("http://{client}"))
        .await?;
    browser.goto(&format!("http://{server}/{folder}/index.html")).await?;

    spinner.success("Browser [OK]");
    Ok(browser)
}
