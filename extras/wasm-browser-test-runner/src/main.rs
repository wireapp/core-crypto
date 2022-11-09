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

#[tokio::main]
async fn main() -> Result<()> {
    femme::start();

    let args = Args::parse();
    let ctx = WebdriverContext::init(args.webdriver.into(), args.force_install_webdriver).await?;

    let path = std::path::Path::new(&args.wasm_test_bin_path);

    ctx.run_wasm_tests(&path).await?;

    Ok(())
}
