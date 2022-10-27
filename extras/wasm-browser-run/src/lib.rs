#[derive(Debug, thiserror::Error)]
pub enum WasmBrowserRunError {
    #[error(transparent)]
    HttpRequestError(#[from] reqwest::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("The {0} WebDriver isn't supported yet.")]
    UnsupportedWebdriver(String),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type WasmBrowserRunResult<T> = Result<T, WasmBrowserRunError>;

#[derive(Debug)]
#[repr(u8)]
pub enum WebdriverKind {
    Chrome,
    Gecko,
    Edge,
    Safari,
}

impl WebdriverKind {
    const CHROME_MAJOR_VERSION: &str = "107";
    const CHROME_RELEASE_URL: &str = const_format::concatcp!(
        "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_",
        WebdriverKind::CHROME_MAJOR_VERSION
    );

    pub fn as_exe_name(&self) -> &str {
        match self {
            WebdriverKind::Chrome => "chromedriver",
            WebdriverKind::Gecko => "geckodriver",
            WebdriverKind::Edge => "edgedriver",
            WebdriverKind::Safari => "safaridriver",
        }
    }

    pub async fn download_url(&self) -> WasmBrowserRunResult<String> {
        let latest_release_url = match self {
            WebdriverKind::Chrome => Self::CHROME_RELEASE_URL,
            WebdriverKind::Gecko => todo!(),
            WebdriverKind::Edge => todo!(),
            WebdriverKind::Safari => todo!(),
        };

        let latest_version = reqwest::get(latest_release_url).await?.text().await?;

        let download_url = match self {
            WebdriverKind::Chrome => {
                format!("https://chromedriver.storage.googleapis.com/index.html?path={latest_version}/")
            }
            WebdriverKind::Gecko => todo!(),
            WebdriverKind::Edge => todo!(),
            WebdriverKind::Safari => todo!(),
        };

        Ok(download_url)
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
pub struct WebdriverContext {
    kind: WebdriverKind,
    browser: fantoccini::Client,
    driver: tokio::process::Child,
    driver_addr: std::net::SocketAddr,
}

impl WebdriverContext {
    pub async fn init(kind: WebdriverKind) -> WasmBrowserRunResult<Self> {
        match kind {
            WebdriverKind::Chrome => {}
            k => return Err(WasmBrowserRunError::UnsupportedWebdriver(k.to_string())),
        }

        let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");

        let driver_location = wd_dir.join(kind.as_exe_name());
        if !driver_location.exists() {
            // TODO: Throw error or install
        }

        let driver_addr = tokio::net::TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let driver = tokio::process::Command::new(driver_location)
            .arg(format!("--port={}", driver_addr.port()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        let browser = match kind {
            WebdriverKind::Chrome => todo!(),
            k => return Err(WasmBrowserRunError::UnsupportedWebdriver(k.to_string())),
        };

        Ok(Self {
            browser,
            kind,
            driver,
            driver_addr,
        })
    }
}

async fn install_webdriver(wd_dir: &std::path::Path, kind: WebdriverKind, force: bool) -> WasmBrowserRunResult<()> {
    if force {
        tokio::fs::remove_dir(&wd_dir).await?;
    }

    let driver_url = kind.download_url().await?;
    // TODO: Download webdriver flavor
    // TODO: Move it to HOME/.webdrivers
    // let driver_installer = match kind {
    //     WebdriverKind::Chrome => webdriver_install::Driver::Chrome,
    //     WebdriverKind::Gecko => webdriver_install::Driver::Gecko,
    //     _ => unimplemented!(),
    // };

    // if !wd_dir.join(kind.as_exe_name()).exists() {
    //     driver_installer.install()?;
    // }

    Ok(())
}
