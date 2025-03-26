use crate::error::*;

const CHROMEDRIVER_RELEASE_ENDPOINT: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";

#[derive(Debug, serde::Deserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
enum ChromeDriverReleaseDetailsChannel {
    Stable,
    Beta,
    Dev,
    Canary,
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
#[repr(u8)]
enum ChromeDriverReleaseDetailsChannelInfoPlatform {
    #[serde(rename = "linux64")]
    LinuxX64,
    #[serde(rename = "mac-arm64")]
    MacArm64,
    #[serde(rename = "mac-x64")]
    MacX64,
    #[serde(rename = "win32")]
    Win32,
    #[serde(rename = "win64")]
    Win64,
}

impl ChromeDriverReleaseDetailsChannelInfoPlatform {
    pub(crate) fn detect() -> WasmBrowserRunResult<Self> {
        let is_aarch64 = std::env::consts::ARCH == "aarch64";
        let is_32_bits = cfg!(target_pointer_width = "32");
        let os = std::env::consts::OS;
        Ok(match os {
            "macos" => {
                if is_aarch64 {
                    Self::MacArm64
                } else {
                    Self::MacX64
                }
            }
            "linux" => {
                if is_32_bits || is_aarch64 {
                    return Err(WasmBrowserRunError::UnsupportedPlatform);
                }
                Self::LinuxX64
            }
            "windows" => {
                if is_32_bits {
                    Self::Win32
                } else {
                    Self::Win64
                }
            }
            _ => return Err(WasmBrowserRunError::UnsupportedPlatform),
        })
    }

    pub(crate) fn to_filename(&self) -> String {
        format!(
            "chromedriver-{}",
            match self {
                Self::LinuxX64 => "linux64",
                Self::MacArm64 => "mac-arm64",
                Self::MacX64 => "mac-x64",
                Self::Win32 => "win32",
                Self::Win64 => "win64",
            }
        )
    }
}

#[derive(Debug, serde::Deserialize)]
struct ChromeDriverReleaseDetailsChannelInfoDownload {
    platform: ChromeDriverReleaseDetailsChannelInfoPlatform,
    url: String,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct ChromeDriverReleaseDetailsChannelInfoDownloads {
    chrome: Vec<ChromeDriverReleaseDetailsChannelInfoDownload>,
    chromedriver: Vec<ChromeDriverReleaseDetailsChannelInfoDownload>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct ChromeDriverReleaseDetailsChannelInfo {
    channel: ChromeDriverReleaseDetailsChannel,
    version: String,
    revision: String,
    downloads: ChromeDriverReleaseDetailsChannelInfoDownloads,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct ChromeDriverReleaseDetails {
    timestamp: chrono::DateTime<chrono::Utc>,
    channels: std::collections::HashMap<ChromeDriverReleaseDetailsChannel, ChromeDriverReleaseDetailsChannelInfo>,
}

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
    const CHROMIUM_MAJOR_VERSION: &'static str = "121";

    const EDGE_RELEASE_URL: &'static str = const_format::concatcp!(
        "https://msedgedriver.azureedge.net/LATEST_RELEASE_",
        WebdriverKind::CHROMIUM_MAJOR_VERSION
    );

    const GECKO_RELEASE_URL: &'static str = "https://api.github.com/repos/mozilla/geckodriver/releases/latest";

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
            WebdriverKind::Chrome | WebdriverKind::Safari => "".to_string(),
        })
    }

    async fn download_url(&self) -> WasmBrowserRunResult<(String, String)> {
        let mut geckodriver_response = None;
        let mut chromedriver_response = None;
        let latest_version = match self {
            WebdriverKind::Chrome => {
                let cd_response: ChromeDriverReleaseDetails =
                    reqwest::get(CHROMEDRIVER_RELEASE_ENDPOINT).await?.json().await?;
                chromedriver_response = Some(cd_response);
                "".to_string()
            }
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

        let mut download_filename = self.as_download_filename(&latest_version)?;

        let download_url = match self {
            WebdriverKind::Chrome => {
                let platform = ChromeDriverReleaseDetailsChannelInfoPlatform::detect()?;
                let channel = chromedriver_response
                    .take()
                    .unwrap()
                    .channels
                    .remove(&ChromeDriverReleaseDetailsChannel::Canary)
                    .unwrap();

                let download_url = channel
                    .downloads
                    .chromedriver
                    .into_iter()
                    .find_map(|rd| (rd.platform == platform).then_some(rd.url))
                    .ok_or_else(|| WasmBrowserRunError::UnsupportedPlatform)?;

                let url_parsed = url::Url::parse(&download_url)?;
                download_filename = url_parsed
                    .path_segments()
                    .and_then(|iter| iter.last())
                    .ok_or_else(|| WebdriverError::NoDownloadUrlFound)?
                    .into();

                download_url
            }
            WebdriverKind::Gecko => geckodriver_response
                .take()
                .unwrap()
                .assets
                .into_iter()
                .find_map(|asset| (asset.name == download_filename).then_some(asset.url))
                .ok_or_else(|| WasmBrowserRunError::UnsupportedPlatform)?,
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

        // TODO: Check version properly. Tracking issue: WPB-9636
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

        // TODO: Do things properly and download with reqwest & unzip with `zip`, `flate2` and `tar`. Tracking issue: WPB-9636

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

        let mut cleanup_folder = None;

        let command = match tempfile_path.extension().unwrap().to_str().unwrap() {
            "zip" => {
                if matches!(self, WebdriverKind::Chrome) {
                    let platform = ChromeDriverReleaseDetailsChannelInfoPlatform::detect()?;
                    let subfolder = platform.to_filename();
                    cleanup_folder = Some(subfolder.clone());
                    xshell::cmd!(sh, "unzip -o {tempfile_path} ''{subfolder}/*'' -d {wd_dir}")
                } else {
                    xshell::cmd!(sh, "unzip -o {tempfile_path} -d {wd_dir}")
                }
            }
            "tar.gz" => xshell::cmd!(sh, "tar -xzf {tempfile_path} {wd_dir}"),
            _ => unreachable!("Unlikely branch encountered. No handling of this kind of file."),
        };

        command.ignore_stdout().ignore_stderr().run()?;

        if let Some(cleanup_folder) = cleanup_folder.take() {
            let mut rmdir_target = wd_dir.to_path_buf();
            rmdir_target.push(cleanup_folder);

            let mut exe_path_target = rmdir_target.clone();
            exe_path_target.push(exe_name);

            tokio::fs::rename(exe_path_target, exe_path).await?;
            tokio::fs::remove_dir_all(rmdir_target).await?;
        }

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
