use crate::util::RunningProcess;
use color_eyre::eyre::Result;

pub(crate) async fn setup_webdriver(force: bool) -> Result<()> {
    let mut spinner = RunningProcess::new("Setting up WebDriver & co...", false);

    let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");
    let chrome = webdriver_installation::WebdriverKind::Chrome;

    if force {
        spinner.update("FORCE_WEBDRIVER_INSTALL is set. Forcefully removing webdrivers...");
        std::fs::remove_dir(&wd_dir)?;
    }

    if !wd_dir.join(chrome.as_exe_name()).exists() {
        spinner.update("Chrome WebDriver isn't installed. Installing...");
        chrome.install_webdriver(&wd_dir, force).await?;
    }

    spinner.update("Chrome WebDriver installed");

    spinner.success("WebDriver setup [OK]");

    Ok(())
}

pub(crate) async fn start_webdriver_chrome(addr: &std::net::SocketAddr) -> Result<tokio::process::Child> {
    let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");

    Ok(tokio::process::Command::new(wd_dir.join("chromedriver"))
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
