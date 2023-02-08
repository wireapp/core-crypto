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
    const CHROMIUM_MAJOR_VERSION: &str = "109";
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
                format!("https://chromedriver.storage.googleapis.com/{latest_version}/{download_filename}")
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
        let exe_name = self.as_exe_name();
        let exe_path = wd_dir.join(&exe_name);
        let remove = force && exe_path.exists();

        if remove {
            tokio::fs::remove_file(&exe_path).await?;
        }

        // TODO: Check version properly
        // if exe_path.exists() {
        //     let output = tokio::process::Command::new(exe_path.clone())
        //         .args(["--version"])
        //         .output()
        //         .await?;

        //     let output = String::from_utf8_lossy(&output.stdout);
        //     output.contains()
        // }

        if exe_path.exists() {
            return Ok(());
        }

        tokio::fs::create_dir_all(&wd_dir).await?;

        let (driver_url, driver_filename) = self.download_url().await?;

        if driver_url.is_empty() || driver_filename.is_empty() {
            return Ok(());
        }

        let sh = xshell::Shell::new()?;

        // let mut filestream = reqwest::get(driver_url.clone()).await?.bytes_stream();
        let dir = tempfile::tempdir()?;

        let tempfile_path = dir.path().join(driver_filename);
        // let extension = tempfile_path.extension().unwrap().to_str().unwrap().to_string();

        xshell::cmd!(sh, "wget {driver_url} -O {tempfile_path}")
            .ignore_stdout()
            .ignore_stderr()
            .run()?;

        // TODO: Do things properly and download with reqwest & unzip with `zip`, `flate2` and `tar`

        // let mut file = tokio::fs::File::create(&tempfile_path).await?;

        // use futures_util::StreamExt as _;
        // use tokio::io::AsyncWriteExt as _;
        // let mut wrote = 0usize;
        // while let Some(chunk) = filestream.next().await {
        //     let chunk = chunk?;
        //     let chunk_len = chunk.len();
        //     file.write_all(&chunk).await?;
        //     wrote += chunk_len;
        // }

        // dbg!(wrote);
        // dbg!(&tempfile_path);

        // file.sync_all().await?;
        // let file = file.into_std().await;

        // let wd_dir_inner = wd_dir.to_owned();
        // dbg!(&wd_dir);

        // let file = match extension.as_str() {
        //     "zip" => {
        //         let mut zip = zip::ZipArchive::new(file).map_err(WebdriverError::from)?;
        //         zip.extract(wd_dir_inner).map_err(WebdriverError::from)?;

        //         zip.into_inner()
        //     },
        //     "tar.gz" => {
        //         let gz = flate2::read::GzDecoder::new(file);
        //         let mut tar = tar::Archive::new(gz);
        //         tar.set_preserve_permissions(true);
        //         tar.set_unpack_xattrs(true);
        //         tar.unpack(wd_dir_inner)?;
        //         tar.into_inner().into_inner()
        //     },
        //     _ => unreachable!("Unlikely branch encountered. No handling of this kind of file."),
        // };

        // tracing::warn!("Got file: {file:?}");
        // tracing::warn!("Unzipped {tempfile_path:?} -> {wd_dir:?}");

        // // Make sure the file has the executable bit set
        // #[cfg(unix)]
        // {
        //     let file = tokio::fs::File::from_std(file);
        //     let mut perms = file.metadata().await?.permissions();
        //     use std::os::unix::fs::PermissionsExt as _;
        //     perms.set_mode(0o755);
        //     file.set_permissions(perms).await?;
        //     file.sync_all().await?;
        //     drop(file);
        // }

        match tempfile_path.extension().unwrap().to_str().unwrap() {
            "zip" => xshell::cmd!(sh, "unzip -o {tempfile_path} -d {wd_dir}")
                .ignore_stdout()
                .ignore_stderr()
                .run()?,
            "tar.gz" => xshell::cmd!(sh, "tar -xzf {tempfile_path} {wd_dir}")
                .ignore_stdout()
                .ignore_stderr()
                .run()?,
            _ => unreachable!("Unlikely branch encountered. No handling of this kind of file."),
        }

        // tokio::fs::rename(tempfile_path, exe_path).await?;
        drop(tempfile_path);

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
