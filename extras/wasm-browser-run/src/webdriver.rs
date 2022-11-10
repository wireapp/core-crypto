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

use crate::error::*;

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
