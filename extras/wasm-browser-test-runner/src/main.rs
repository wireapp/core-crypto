use color_eyre::eyre::Result;
use wasm_browser_run::{WebdriverContext, WebdriverKind, DEFAULT_TIMEOUT_SECS};

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

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Choose which WebDriver implementation to download/install/run
    #[arg(long)]
    webdriver: CliWebdriverKind,
    /// Forces reinstalling the webdriver. Can be useful for local setups where the implementation became outdated over time.
    ///
    /// Note: WebDriver versions usually don't mix and match with installed binary browsers. For instance, if you have
    /// chromedriver 107 with a Google Chrome 108 host, some random problems might occur. Make sure versions do match!
    #[arg(short, long)]
    force_install_webdriver: bool,
    /// This controls the timeout of WebDriver script execution.
    /// Not needed in BiDi mode as the script is a fire-and-forget and relies on subsequent BiDi events to learn about test completion
    #[arg(short, long)]
    timeout: Option<u64>,
    /// Verbose level. This is a multiple flag, i.e. `-vvv` stands for verbose level 3 which corresponds to WARN
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Avoids communicating over BiDi. Usually not needed as we do a runtime detection of the WebDriver impl's BiDi capabilities
    #[arg(long, conflicts_with("nocapture"))]
    no_bidi: bool,
    /// Returns a list of tests. Useful for `cargo-nextest` compatibility
    #[arg(long)]
    list: bool,
    /// Placeholder flag for `cargo-nextest compat`. Returns nothing.
    #[arg(long)]
    ignored: bool,
    /// Echoes back test logs that were captured and silenced. Only does something in BiDi mode
    #[arg(long)]
    nocapture: bool,
    /// Perform a single test. `cargo-nextest` stuff. Be warned, executing many tests this way is insanely slow
    /// and most likely doesn't work
    #[arg(long)]
    exact: Option<String>,
    /// Output format. Does absolutely nothing right now.
    #[arg(long)]
    format: Option<CliFormat>,
    /// Path to the wasm binary to test
    wasm_test_bin_path: String,
    /// Test filter to run a certain sub-selection of tests
    test_filter: Option<String>,
    /// Sometimes needed arg where the cargo test runner will supply a lib name. Does nothing as far as we're concerned.
    wasm_lib_name: Option<std::path::PathBuf>,
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
    use clap::Parser as _;
    let mut args = Args::parse();

    init_logger(args.verbose);

    if args.timeout.is_none() {
        // Compatibility layer with wasm-bindgen-test-runner
        if let Ok(timeout) = std::env::var("WASM_BINDGEN_TEST_TIMEOUT") {
            args.timeout = Some(timeout.parse()?);
        }
    }
    log::warn!("Args: {args:?}");

    tokio::select! {
        res = test_runner(args) => {
            if let Err(err) = res {
                panic!("{err}");
            }
        },
        _ = tokio::signal::ctrl_c() => {
            log::warn!("Aborted!");
        },
    };

    Ok(())
}

async fn test_runner(args: Args) -> Result<()> {
    // TODO: To achieve nextest compat, we need to spawn some sort of daemon then only issue commands to it.
    // TODO: Otherwise, the whole process of spawning stuff is too costly and causes errors as we recompile stuff with different hashes.
    // TODO: Basically everything is too sequential

    let mut ctx = WebdriverContext::init(args.webdriver.into(), args.force_install_webdriver)
        .await?
        .avoid_bidi(args.no_bidi)
        .disable_log_capture(args.nocapture)
        .with_timeout(args.timeout.map(std::time::Duration::from_secs))
        .enable_debug(args.verbose > 1);

    ctx.webdriver_init().await?;

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
            .run_wasm_tests(&wasm_file_to_test, args.test_filter, args.exact)
            .await?;
        println!("{test_results}");
    }

    Ok(())
}
