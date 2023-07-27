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

#[derive(Debug, thiserror::Error)]
pub enum WasmBrowserRunError {
    #[error(transparent)]
    HttpRequestError(#[from] reqwest::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    WebDriverError(#[from] WebdriverError),
    #[error(transparent)]
    ShellError(#[from] xshell::Error),
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    #[error("The WebDriver context hasn't been initialized. Please call WebDriverContext::webdriver_init() first!")]
    WebDriverContextNotInitialized,
    #[error(
        "For some reason the webdriver implementation is not responding within the allotted timeout (5s by default)."
    )]
    WebDriverTimeoutError,
    #[error("The WebDriver executable [{0}] couldn't be found despite having downloaded successfully")]
    WebDriverExecutableNotFound(crate::WebdriverKind),
    #[error("The mount point [{0}] does not exist")]
    MountPointNotFound(String),
    #[error("The {0} WebDriver isn't supported yet.")]
    UnsupportedWebdriver(String),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    WebDriverBiDiWebsocketError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("The platform you're running this code on isn't supported")]
    UnsupportedPlatform,
    #[error("Error while building test JS bundle: {0}")]
    NpmError(String),
    #[error("Cannot find the WASM file located at {0}")]
    WasmFileNotFound(String),
    #[error("Tests have failed with the following error\n\n{0}")]
    ErrorThrownInTest(String),
    #[error("Invalid __wasm_bindgen_test_unstable custom section value - expected to find 0x01, found {0}")]
    InvalidWasmBindgenTestCustomSection(String),
    #[error(
        r#"
This test suite is only configured to run in node.js, but we're only running
browser tests so skipping. If you'd like to run the tests in a browser
include this in your crate when testing:

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

You'll likely want to put that in a `#[cfg(test)]` module or at the top of an
integration test.
"#
    )]
    InvalidBuildTarget,
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(Debug, thiserror::Error)]
pub enum WebdriverError {
    #[error(transparent)]
    SyncTaskError(#[from] tokio::task::JoinError),
    #[error(transparent)]
    SyncIoError(#[from] tokio::sync::oneshot::error::RecvError),
    #[error(transparent)]
    WebDriverPackageUnzipError(#[from] zip::result::ZipError),
    #[error(transparent)]
    InvalidWindowHandle(#[from] fantoccini::error::InvalidWindowHandle),
    #[error(transparent)]
    WebDriver(#[from] fantoccini::error::WebDriver),
    #[error(transparent)]
    CmdError(#[from] fantoccini::error::CmdError),
    #[error(transparent)]
    NewSessionError(#[from] fantoccini::error::NewSessionError),
    #[error("The session handshake didn't contain a `webSocketUrl` meaning that this WebDriver implementation doesn't support WebDriver BiDi protocol.")]
    NoWebDriverBidiSupport,
    #[error("The download URL for the WebDriver cannot be parsed")]
    NoDownloadUrlFound,
    #[error(transparent)]
    WebsocketError(#[from] tokio_tungstenite::tungstenite::Error),
}

pub type WasmBrowserRunResult<T> = Result<T, WasmBrowserRunError>;
