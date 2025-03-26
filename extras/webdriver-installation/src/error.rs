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
