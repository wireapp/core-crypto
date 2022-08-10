use color_eyre::eyre::Result;

const WEBDRIVER_URI: &str = "http://localhost:9515";
const TEST_SERVER_PORT: &str = "8000";
const TEST_SERVER_URI: &str = concat!("http://localhost:", 8000);

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    femme::start();
    let _ = tokio::task::spawn_blocking(setup_webdriver).await?;

    build_wasm().await?;
    log::info!("WASM bundle loaded and ready");
    let http_server_hwnd = tokio::task::spawn(spawn_http_server());
    log::info!("HTTP server started at 0.0.0.0:{TEST_SERVER_PORT}");
    let mut chrome_webdriver = start_webdriver_chrome().await?;

    let caps = serde_json::Map::from_iter(
        vec![("chromeOptions".to_string(), serde_json::json!({"args": ["--headless"]}))].into_iter(),
    );

    let c = fantoccini::ClientBuilder::native()
        .capabilities(caps)
        .connect(WEBDRIVER_URI)
        .await?;
    c.goto(&format!("{TEST_SERVER_URI}/index.html")).await?;

    let wasm_client_config = serde_json::json!({
        "databaseName": "roundtrip message test 1",
        "key": "test",
        "clientId": "test"
    });

    let keypackage_wasm = c
        .execute_async(
            &tokio::fs::read_to_string("src/wasm.setup.step1.js").await?,
            vec![wasm_client_config],
        )
        .await?;

    log::info!("Got keypackage: {keypackage_wasm:?}");

    // TODO: Publish a keypackage
    // TODO: Load a local client
    // TODO: Create a conversation
    // TODO: Invite web user to a conversation through its KP

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    chrome_webdriver.kill().await?;
    http_server_hwnd.abort();
    Ok(())
}

fn setup_webdriver() -> Result<()> {
    let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");
    let chrome = webdriver_install::Driver::Chrome;
    let ff = webdriver_install::Driver::Gecko;
    if !wd_dir.join(chrome.as_str()).exists() {
        log::info!("Chrome WebDriver isn't installed. Installing...");
        chrome.install()?;
    }
    log::info!("Chrome WebDriver installed");
    if !wd_dir.join(ff.as_str()).exists() {
        log::info!("Gecko WebDriver (Firefox) isn't installed. Installing...");
        ff.install()?;
    }

    log::info!("Gecko (Firefox) WebDriver installed");

    Ok(())
}

async fn start_webdriver_chrome() -> Result<tokio::process::Child> {
    let wd_dir = dirs::home_dir().unwrap().join(".webdrivers");

    Ok(tokio::process::Command::new(wd_dir.join("chromedriver")).spawn()?)
}

async fn find_wasm_file(deploy_path: &std::path::PathBuf) -> Result<std::path::PathBuf> {
    let wasm_base_path = deploy_path.join("assets");
    let wasm_path = if wasm_base_path.exists() {
        let mut wasm_dir = tokio::fs::read_dir(wasm_base_path.clone()).await?;
        let mut maybe_wasm_path = None;
        while let Some(entry) = wasm_dir.next_entry().await? {
            log::debug!("wasm dir entry: {entry:?}");
            if let Some(ext) = entry.path().extension() {
                if ext == std::ffi::OsStr::new("wasm") {
                    log::debug!("found");
                    maybe_wasm_path = Some(entry);
                }
            }
        }
        maybe_wasm_path
            .map(|entry| entry.path())
            .unwrap_or_else(|| wasm_base_path.join(".not-found"))
    } else {
        wasm_base_path.join(".not-found")
    };

    Ok(wasm_path)
}

async fn build_wasm() -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::process::Command;

    let wasm_deploy_path = std::path::PathBuf::from("../platforms/web");

    let exe_path = std::env::current_exe()?;
    let wasm_cache_path = exe_path.join(".wasm.cache");
    let js_cache_path = exe_path.join(".js.cache");

    let wasm_path = find_wasm_file(&wasm_deploy_path).await?;
    let js_path = wasm_deploy_path.join("corecrypto.js");

    if !wasm_path.exists() || !js_path.exists() {
        log::info!("No JS/WASM files found, rebuilding");
    } else if wasm_cache_path.exists() && js_cache_path.exists() {
        let wasm_hash = hex::decode(tokio::fs::read_to_string(wasm_cache_path.clone()).await?)?;
        let js_hash = hex::decode(tokio::fs::read_to_string(js_cache_path.clone()).await?)?;

        let mut hasher = Sha256::new();
        hasher.update(tokio::fs::read(js_path.clone()).await?);
        let js_current_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(tokio::fs::read(wasm_path.clone()).await?);
        let wasm_current_hash = hasher.finalize();

        if js_current_hash[..] == js_hash && wasm_current_hash[..] == wasm_hash {
            log::info!("WASM/JS builds are identical - skipping build");
            return Ok(());
        }

        log::info!("WASM/JS needs rebuild!");
    } else {
        log::info!("No cache file found, rebuilding to get a cache!");
    }

    Command::new("cargo")
        .args(["make", "wasm"])
        .current_dir("../crypto-ffi")
        .status()
        .await?;

    Command::new("npm")
        .args(["run", "build:test"])
        .current_dir("..")
        .status()
        .await?;

    log::info!("Computing new file hashes...");

    let mut hasher = Sha256::new();
    hasher.update(tokio::fs::read(js_path).await?);
    let js_current_hash = hex::encode(hasher.finalize());

    let wasm_path = find_wasm_file(&wasm_deploy_path).await?;
    log::info!("Found wasm file at {wasm_path:?}");

    let mut hasher = Sha256::new();
    hasher.update(tokio::fs::read(wasm_path).await?);
    let wasm_current_hash = hex::encode(hasher.finalize());

    log::info!("Cache updated; CoreCrypto.wasm[{wasm_current_hash}] | corecrypto.js[{js_current_hash}]");

    tokio::fs::write(js_cache_path, js_current_hash).await?;
    tokio::fs::write(wasm_cache_path, wasm_current_hash).await?;

    Ok(())
}

async fn spawn_http_server() -> Result<()> {
    warpy::server::run(
        "../platforms/web".into(),
        [0, 0, 0, 0],
        "".into(),
        Some(TEST_SERVER_PORT.parse()?),
        false,
    )
    .await?;

    Ok(())
}
