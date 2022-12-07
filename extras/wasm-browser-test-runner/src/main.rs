use clap::Parser;
use color_eyre::eyre::Result;
use wasm_browser_run::{WebdriverContext, WebdriverKind};

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
#[repr(u8)]
enum CliWebdriverKind {
    Chrome,
    Firefox,
    Edge,
    Safari,
}

impl Into<WebdriverKind> for CliWebdriverKind {
    fn into(self) -> WebdriverKind {
        match self {
            Self::Chrome => WebdriverKind::Chrome,
            Self::Firefox => WebdriverKind::Gecko,
            Self::Edge => WebdriverKind::Edge,
            Self::Safari => WebdriverKind::Safari,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    webdriver: CliWebdriverKind,
    #[arg(short, long)]
    force_install_webdriver: bool,
    #[arg(short, long)]
    timeout: Option<u64>,
    #[arg(long)]
    verbose: bool,
    wasm_test_bin_path: String,
    wasm_lib_name: Option<String>,
}

fn init_logger(verbose: bool) {
    let default_log_level = if verbose { "debug" } else { "info" };
    let log_setting = if let Ok(log_setting) = std::env::var("RUST_LOG") {
        format!("{default_log_level},{log_setting}")
    } else {
        default_log_level.to_string()
    };
    std::env::set_var("RUST_LOG", log_setting);

    pretty_env_logger::init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();

    init_logger(args.verbose);

    log::warn!("Args: {args:?}");

    if args.timeout.is_none() {
        // Compatibility layer with wasm-bindgen-test-runner
        if let Ok(timeout) = std::env::var("WASM_BINDGEN_TEST_TIMEOUT") {
            args.timeout = Some(timeout.parse()?);
        }
    }

    let ctx = WebdriverContext::init_with_timeout(
        args.webdriver.into(),
        args.force_install_webdriver,
        args.timeout.map(std::time::Duration::from_secs),
    )
    .await?;

    let wasm_file_to_test = std::path::PathBuf::from(args.wasm_test_bin_path);
    log::warn!("WASM file path: {wasm_file_to_test:?}");

    if !wasm_file_to_test.exists() {
        panic!("The file at {wasm_file_to_test:?} does not exist!");
    }

    ctx.run_wasm_tests(&wasm_file_to_test).await?;

    Ok(())
}
