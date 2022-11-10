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
    #[arg(last = true)]
    wasm_test_bin_path: String,
}

// FIXME: Args support:
// corelib on  chore/wasm-test-runner [!?] is 📦 v0.6.0-pre.4 via  v16.16.0 via 🦀 v1.65.0
// ❯ cargo test --lib crypto --target wasm32-unknown-unknown
//     Finished test [unoptimized + debuginfo] target(s) in 0.16s
//      Running unittests src/lib.rs (target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm)
//     Finished dev [unoptimized + debuginfo] target(s) in 0.08s
//      Running `/home/otak/Dev/wire/corelib/extras/wasm-browser-test-runner/target/debug/wasm-browser-test-runner --webdriver chrome /home/otak/Dev/wire/corelib/target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm crypto`
// error: Found argument '/home/otak/Dev/wire/corelib/target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm' which wasn't expected, or isn't valid in this context

// Usage: wasm-browser-test-runner [OPTIONS] --webdriver <WEBDRIVER> -- <WASM_TEST_BIN_PATH>

// For more information try '--help'
// error: test failed, to rerun pass `-p core-crypto --lib`

// Caused by:
//   process didn't exit successfully: `cargo run --bin wasm-browser-test-runner --manifest-path ../extras/wasm-browser-test-runner/Cargo.toml -- --webdriver chrome /home/otak/Dev/wire/corelib/target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm crypto` (exit status: 2)

// corelib on  chore/wasm-test-runner [!?] is 📦 v0.6.0-pre.4 via  v16.16.0 via 🦀 v1.65.0
// ❯ cargo test --target wasm32-unknown-unknown
//     Finished test [unoptimized + debuginfo] target(s) in 0.16s
//      Running unittests src/lib.rs (target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm)
//     Finished dev [unoptimized + debuginfo] target(s) in 0.08s
//      Running `/home/otak/Dev/wire/corelib/extras/wasm-browser-test-runner/target/debug/wasm-browser-test-runner --webdriver chrome /home/otak/Dev/wire/corelib/target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm`
// error: Found argument '/home/otak/Dev/wire/corelib/target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm' which wasn't expected, or isn't valid in this context

// Usage: wasm-browser-test-runner [OPTIONS] --webdriver <WEBDRIVER> -- <WASM_TEST_BIN_PATH>

// For more information try '--help'
// error: test failed, to rerun pass `-p core-crypto --lib`

// Caused by:
//   process didn't exit successfully: `cargo run --bin wasm-browser-test-runner --manifest-path ../extras/wasm-browser-test-runner/Cargo.toml -- --webdriver chrome /home/otak/Dev/wire/corelib/target/wasm32-unknown-unknown/debug/deps/core_crypto-a8b9273bc359ac72.wasm` (exit status: 2)

#[tokio::main]
async fn main() -> Result<()> {
    femme::start();

    let args = Args::parse();
    let ctx = WebdriverContext::init(args.webdriver.into(), args.force_install_webdriver).await?;

    let wasm_file_to_test = std::path::PathBuf::from(args.wasm_test_bin_path);

    ctx.run_wasm_tests(&wasm_file_to_test).await?;

    Ok(())
}
