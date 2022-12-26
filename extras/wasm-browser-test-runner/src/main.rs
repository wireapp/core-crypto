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

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
#[repr(u8)]
enum CliFormat {
    Pretty,
    Terse,
    Json,
    Junit,
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
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(long)]
    no_bidi: bool,
    #[arg(long)]
    list: bool,
    #[arg(long)]
    ignored: bool,
    #[arg(long)]
    nocapture: bool,
    #[arg(long)]
    exact: Option<String>,
    #[arg(long)]
    format: Option<CliFormat>,
    wasm_test_bin_path: String,
    wasm_lib_name: Option<String>,
    test_filter: Option<String>,
}

fn init_logger(verbose: u8) {
    if verbose == 0 {
        return;
    }
    let verbose_level = std::cmp::min(verbose, log::Level::max() as usize as u8) as usize;
    // SAFETY: Safe because we clamped the level above
    let default_log_level = log::Level::iter().nth(verbose_level).unwrap();
    let log_setting = if let Ok(log_setting) = std::env::var("RUST_LOG") {
        format!("{},{log_setting}", default_log_level.as_str().to_lowercase())
    } else {
        default_log_level.as_str().to_lowercase().to_string()
    };
    std::env::set_var("RUST_LOG", log_setting);

    pretty_env_logger::init();
}

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: To achieve nextest compat, we need to spawn some sort of daemon then only issue commands to it.
    // TODO: Otherwise, the whole process of spawning stuff is too costly and causes errors as we recompile stuff with different hashes.
    // TODO: Basically everything is too sequential

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
        args.verbose > 1,
        args.timeout.map(std::time::Duration::from_secs),
    )
    .await?;

    let wasm_file_to_test = std::path::PathBuf::from(args.wasm_test_bin_path);
    log::warn!("WASM file path: {wasm_file_to_test:?}");

    if !wasm_file_to_test.exists() {
        panic!("The file at {wasm_file_to_test:?} does not exist!");
    }

    if args.list {
        for test in ctx.wasm_tests_list(&wasm_file_to_test, args.ignored).await? {
            println!("{test}: test");
        }
    } else {
        let test_results = ctx
            .run_wasm_tests(&wasm_file_to_test, args.no_bidi, args.test_filter, args.exact)
            .await?;
        println!("{test_results}");
    }

    Ok(())
}
