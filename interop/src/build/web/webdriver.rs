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

use crate::util::RunningProcess;
use crate::TEST_SERVER_URI;
use color_eyre::eyre::Result;

pub fn setup_webdriver(force: bool) -> Result<()> {
    let mut spinner = RunningProcess::new("Setting up WebDriver & co...", false);

    let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");
    let chrome = webdriver_install::Driver::Chrome;

    if force {
        spinner.update("FORCE_WEBDRIVER_INSTALL is set. Forcefully removing webdrivers...");
        std::fs::remove_dir(&wd_dir)?;
    }

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

pub async fn setup_browser(addr: &std::net::SocketAddr, folder: &str) -> Result<fantoccini::Client> {
    // let spinner = RunningProcess::new("Starting Fantoccini remote browser...", false);
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
    browser.goto(&format!("{TEST_SERVER_URI}/{folder}/index.html")).await?;

    // spinner.success("Browser [OK]");

    Ok(browser)
}
