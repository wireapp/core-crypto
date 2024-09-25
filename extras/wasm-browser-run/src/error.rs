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
    #[error("The platform you're running this code on isn't supported")]
    UnsupportedPlatform,
}

#[derive(Debug, thiserror::Error)]
pub enum WebdriverError {
    #[error("The download URL for the WebDriver cannot be parsed")]
    NoDownloadUrlFound,
}

pub type WasmBrowserRunResult<T> = Result<T, WasmBrowserRunError>;
