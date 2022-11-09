#[derive(Debug, thiserror::Error)]
pub enum WasmBrowserRunError {
    #[error(transparent)]
    HttpRequestError(#[from] reqwest::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    WebDriverError(#[from] WebdriverError),
    #[error("The mount point [{0}] does not exist")]
    MountPointNotFound(String),
    #[error("The {0} WebDriver isn't supported yet.")]
    UnsupportedWebdriver(String),
    #[error("The platform you're running this code on isn't supported")]
    UnsupportedPlatform,
    #[error("Error while building test JS bundle: {0}")]
    NpmError(String),
    #[error("Cannot find the WASM file located at {0}")]
    WasmFileNotFound(String),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(Debug, thiserror::Error)]
pub enum WebdriverError {
    #[error(transparent)]
    InvalidWindowHandle(#[from] fantoccini::error::InvalidWindowHandle),
    #[error(transparent)]
    WebDriver(#[from] fantoccini::error::WebDriver),
    #[error(transparent)]
    CmdError(#[from] fantoccini::error::CmdError),
    #[error(transparent)]
    NewSessionError(#[from] fantoccini::error::NewSessionError),
}

pub type WasmBrowserRunResult<T> = Result<T, WasmBrowserRunError>;

#[derive(Debug, serde::Deserialize)]
struct GithubResponseLatestReleaseAsset {
    name: String,
    url: String,
}

#[derive(Debug, serde::Deserialize)]
struct GithubResponseLatestRelease {
    tag_name: String,
    assets: Vec<GithubResponseLatestReleaseAsset>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum WebdriverKind {
    Chrome,
    Gecko,
    Edge,
    Safari,
}

impl WebdriverKind {
    const CHROMIUM_MAJOR_VERSION: &str = "107";
    const CHROME_RELEASE_URL: &str = const_format::concatcp!(
        "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_",
        WebdriverKind::CHROMIUM_MAJOR_VERSION
    );

    const EDGE_RELEASE_URL: &str = const_format::concatcp!(
        "https://msedgedriver.azureedge.net/LATEST_RELEASE_",
        WebdriverKind::CHROMIUM_MAJOR_VERSION
    );

    const GECKO_RELEASE_URL: &str = "https://api.github.com/repos/mozilla/geckodriver/releases/latest";

    pub fn as_exe_name(&self) -> &str {
        match self {
            WebdriverKind::Chrome => "chromedriver",
            WebdriverKind::Gecko => "geckodriver",
            WebdriverKind::Edge => "edgedriver",
            WebdriverKind::Safari => "safaridriver",
        }
    }

    fn as_download_filename(&self, version: &str) -> WasmBrowserRunResult<String> {
        let is_aarch64 = std::env::consts::ARCH == "aarch64";
        let is_32_bits = cfg!(target_pointer_width = "32");
        let os = std::env::consts::OS;

        Ok(match self {
            WebdriverKind::Chrome => {
                let (os_filename, ext) = match os {
                    "linux" => ("linux", "64"),
                    "macos" => ("mac", if is_aarch64 { "_arm64" } else { "64" }),
                    "windows" => ("win", "32"),
                    _ => return Err(WasmBrowserRunError::UnsupportedPlatform),
                };

                format!("chromedriver_{os_filename}{ext}.zip")
            }
            WebdriverKind::Gecko => {
                let (os_filename, ext) = match os {
                    "macos" if !is_32_bits && is_aarch64 => ("macos-aarch", "64"),
                    "macos" if !is_32_bits => ("macos", ""),
                    "linux" if !is_32_bits && is_aarch64 => ("linux-aarch", "64"),
                    "linux" if !is_32_bits => ("linux", "64"),
                    "linux" if is_32_bits => ("linux", "32"),
                    "windows" if !is_32_bits && is_aarch64 => ("win-aarch", "64"),
                    "windows" if !is_32_bits => ("win", "64"),
                    "windows" if is_32_bits => ("win", "32"),
                    _ => return Err(WasmBrowserRunError::UnsupportedPlatform),
                };

                format!("geckodriver-{version}-{os_filename}{ext}.tar.gz")
            }
            WebdriverKind::Edge => {
                let (os_filename, ext) = match os {
                    "macos" => ("mac", if is_aarch64 { "64_m1" } else { "64" }),
                    "windows" if !is_32_bits && is_aarch64 => ("aarch", "64"),
                    "windows" if !is_32_bits => ("win", "64"),
                    "windows" if is_32_bits => ("win", "32"),
                    _ => return Err(WasmBrowserRunError::UnsupportedPlatform),
                };

                format!("edgedriver_{os_filename}{ext}.zip")
            }
            WebdriverKind::Safari => "".to_string(),
        })
    }

    async fn download_url(&self) -> WasmBrowserRunResult<(String, String)> {
        let mut geckodriver_response = None;
        let latest_version = match self {
            WebdriverKind::Chrome => reqwest::get(Self::CHROME_RELEASE_URL).await?.text().await?,
            WebdriverKind::Gecko => {
                let gh_response: GithubResponseLatestRelease =
                    reqwest::get(Self::GECKO_RELEASE_URL).await?.json().await?;
                let version = gh_response.tag_name.clone();
                geckodriver_response = Some(gh_response);
                version
            }
            WebdriverKind::Edge => reqwest::get(Self::EDGE_RELEASE_URL).await?.text().await?,
            WebdriverKind::Safari => "".to_string(),
        };

        let download_filename = self.as_download_filename(&latest_version)?;

        let download_url = match self {
            WebdriverKind::Chrome => {
                format!(
                    "https://chromedriver.storage.googleapis.com/index.html?path={latest_version}/{download_filename}"
                )
            }
            WebdriverKind::Gecko => {
                let gh_response = geckodriver_response.take().unwrap();

                if let Some(url) = gh_response
                    .assets
                    .into_iter()
                    .find(|asset| asset.name == download_filename)
                    .map(|asset| asset.url)
                {
                    url
                } else {
                    return Err(WasmBrowserRunError::UnsupportedPlatform);
                }
            }
            WebdriverKind::Edge => {
                format!("https://msedgedriver.azureedge.net/{latest_version}/{download_filename}")
            }
            WebdriverKind::Safari => "".to_string(),
        };

        Ok((download_url, download_filename))
    }

    pub async fn install_webdriver(&self, wd_dir: &std::path::Path, force: bool) -> WasmBrowserRunResult<()> {
        let exe_path = wd_dir.join(self.as_exe_name());
        if force && exe_path.exists() {
            tokio::fs::remove_file(&exe_path).await?;
        }

        if exe_path.exists() {
            return Ok(());
        }

        tokio::fs::create_dir_all(&wd_dir).await?;

        let (driver_url, driver_filename) = self.download_url().await?;

        let mut filestream = reqwest::get(driver_url).await?.bytes_stream();
        let dir = tempfile::tempdir()?;

        let tempfile_path = dir.path().join(driver_filename);

        let mut file = tokio::fs::File::create(&tempfile_path).await?;

        use futures_util::StreamExt as _;
        use tokio::io::AsyncWriteExt as _;
        while let Some(chunk) = filestream.next().await {
            file.write_all(&chunk?).await?;
        }

        file.sync_all().await?;
        drop(file);

        tokio::fs::rename(tempfile_path, exe_path).await?;

        Ok(())
    }
}

impl std::fmt::Display for WebdriverKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                WebdriverKind::Chrome => "Chrome",
                WebdriverKind::Gecko => "Gecko",
                WebdriverKind::Edge => "Edge",
                WebdriverKind::Safari => "Safari",
            }
        )
    }
}

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

    fn detect_test_exports(&self, wasm_file_path: impl AsRef<std::path::Path>) -> WasmBrowserRunResult<Vec<String>> {
        let module = walrus::Module::from_file(wasm_file_path).map_err(|e| eyre::eyre!("{e:?}"))?;
        let test_exports = module
            .exports
            .iter()
            // exports starting with "__wbgt_" (wasm-bindgen-test) are `#[wasm_bindgen::test]`-marked functions
            .filter(|e| e.name.starts_with("__wbgt_"))
            .map(|e| e.name.clone())
            .collect();

        Ok(test_exports)
    }

    pub async fn run_wasm_tests(&self, wasm_file_path: &std::path::Path) -> WasmBrowserRunResult<serde_json::Value> {
        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let wasm_tests = self.detect_test_exports(wasm_file_path)?;

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
                vec![wasm_file_name.to_string_lossy().into(), wasm_tests.into()],
            )
            .await
            .map_err(WebdriverError::from)?;

        self.browser.close_window().await.map_err(WebdriverError::from)?;

        hwnd.abort();
        let _ = hwnd.await;

        Ok(result)
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
