use crate::util::RunningProcess;
use crate::TEST_SERVER_URI;
use color_eyre::eyre::Result;

pub fn setup_webdriver() -> Result<()> {
    let mut spinner = RunningProcess::new("Setting up WebDriver & co...", false);

    let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");
    let chrome = webdriver_install::Driver::Chrome;
    if !wd_dir.join(chrome.as_str()).exists() {
        spinner.update("Chrome WebDriver isn't installed. Installing...");
        chrome.install()?;
    }
    spinner.update("Chrome WebDriver installed");

    spinner.success("WebDriver setup [OK]");

    Ok(())
}

pub async fn start_webdriver_chrome(addr: &std::net::SocketAddr) -> Result<tokio::process::Child> {
    let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");

    Ok(tokio::process::Command::new(wd_dir.join("chromedriver"))
        .arg(format!("--port={}", addr.port()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?)
}

pub async fn setup_browser(addr: &std::net::SocketAddr) -> Result<fantoccini::Client> {
    let spinner = RunningProcess::new("Starting Fantoccini remote browser...", false);
    let caps = serde_json::Map::from_iter(
        vec![(
            "goog:chromeOptions".to_string(),
            serde_json::json!({
                "args": [
                    "headless",
                    "disable-dev-shm-usage",
                    "no-sandbox"
                ]
            }),
        )]
        .into_iter(),
    );

    let browser = fantoccini::ClientBuilder::native()
        .capabilities(caps)
        .connect(&format!("http://{addr}"))
        .await?;
    browser.goto(&format!("{TEST_SERVER_URI}/index.html")).await?;

    spinner.success("Browser [OK]");

    Ok(browser)
}
