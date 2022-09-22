use color_eyre::eyre::Result;

#[cfg(not(target_family = "wasm"))]
mod build;
#[cfg(not(target_family = "wasm"))]
mod clients;
#[cfg(not(target_family = "wasm"))]
mod util;

#[cfg(not(target_family = "wasm"))]
const TEST_SERVER_PORT: &str = "8000";
#[cfg(not(target_family = "wasm"))]
const TEST_SERVER_URI: &str = const_format::concatcp!("http://localhost:", TEST_SERVER_PORT);

// TODO: Add support for Android emulator
// TODO: Add support for iOS emulator when on macOS
fn main() -> Result<()> {
    run_test()
}

// need to be handled like this because https://github.com/rust-lang/cargo/issues/5220, otherwise
// it complains over a lacking main function
#[cfg(not(target_family = "wasm"))]
fn run_test() -> Result<()> {
    use color_eyre::eyre::eyre;
    use std::time::{Duration, Instant};

    #[cfg(not(target_family = "wasm"))]
    use tokio::net::{TcpListener, TcpStream};

    use core_crypto::prelude::{tls_codec::Serialize, *};

    const MAIN_CLIENTID: &str = "test_main";
    const CONVERSATION_ID: &[u8] = b"test_conversation";
    const ROUNDTRIP_MSG_AMOUNT: usize = 100;

    // because cannot use `#[tokio::main]` on wasm target because tokio does not compile on this target
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            color_eyre::install()?;
            if std::env::var("RUST_LOG").is_ok() || std::env::var("CI").is_ok() {
                femme::start();
            }

            // Check if we have a correct pwd
            let current_dir = std::env::current_dir()?;
            if current_dir.ends_with("interop") {
                let new_cwd = current_dir.parent().unwrap();
                log::info!("cwd was {current_dir:?}; setting it to {new_cwd:?}");
                std::env::set_current_dir(new_cwd)?;
            }

            let _ = tokio::task::spawn_blocking(build::web::webdriver::setup_webdriver).await?;

            build::web::wasm::build_wasm().await?;

            let spinner = util::RunningProcess::new("Starting HTTP server...", false);
            let http_server_hwnd = tokio::task::spawn(build::web::wasm::spawn_http_server());
            spinner.success(&format!("HTTP server started at 0.0.0.0:{TEST_SERVER_PORT} [OK]"));

            let mut spinner = util::RunningProcess::new("Starting WebDriver [ChromeDriver & GeckoDriver]...", false);
            let chrome_driver_addr = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
            let mut chrome_webdriver = build::web::webdriver::start_webdriver_chrome(&chrome_driver_addr).await?;
            spinner.update("Sleeping to wait for Webdrivers to get ready...");
            let timeout = Duration::from_secs(5);
            let start = Instant::now();
            while start.elapsed() < timeout {
                let chrome_ready = TcpStream::connect(&chrome_driver_addr).await.is_ok();
                if chrome_ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            spinner.success("WebDriver [OK]");

            let spinner = util::RunningProcess::new("Step 0: Initializing clients & env...", true);

            let configuration =
                MlsCentralConfiguration::try_new("whatever".into(), "test".into(), MAIN_CLIENTID.into())?;
            let mut master_client = MlsCentral::try_new_in_memory(configuration, None).await?;

            let conversation_id = CONVERSATION_ID.to_vec();
            master_client
                .new_conversation(conversation_id.clone(), Default::default())
                .await?;

            let mut clients: Vec<Box<dyn clients::EmulatedClient>> = vec![];
            clients.push(Box::new(clients::native::NativeClient::new().await?));
            clients.push(Box::new(clients::web::WebClient::new(&chrome_driver_addr).await?));

            spinner.success("Step 0: Initializing clients [OK]");

            let spinner = util::RunningProcess::new("Step 1: Fetching KeyPackages from clients...", true);

            let mut members = vec![];
            for c in clients.iter_mut() {
                let kp = c.get_keypackage().await?;
                members.push(ConversationMember::new_raw(c.client_id().into(), kp)?);
            }

            spinner.success("Step 1: KeyPackages [OK]");

            let spinner = util::RunningProcess::new("Step 2: Adding clients to conversation...", true);

            let conversation_add_msg = master_client
                .add_members_to_conversation(&conversation_id, members.as_mut_slice())
                .await?;

            master_client.commit_accepted(&conversation_id).await?;

            let welcome_raw = conversation_add_msg.welcome.tls_serialize_detached()?;

            for c in clients.iter_mut() {
                let conversation_id_from_welcome = c.process_welcome(&welcome_raw).await?;
                assert_eq!(conversation_id_from_welcome, conversation_id);
            }

            spinner.success("Step 2: Added clients [OK]");

            let mut spinner = util::RunningProcess::new(
                format!("Step 3: Roundtripping messages [0/{ROUNDTRIP_MSG_AMOUNT}]"),
                true,
            );

            let mut prng = rand::thread_rng();
            let mut message = [0u8; 128];
            for i in 0..ROUNDTRIP_MSG_AMOUNT {
                use rand::RngCore as _;

                prng.fill_bytes(&mut message);

                let mut message_to_decrypt = master_client.encrypt_message(&conversation_id, &message).await?;

                for c in clients.iter_mut() {
                    let decrypted_message = c
                        .decrypt_message(&conversation_id, &message_to_decrypt)
                        .await?
                        .ok_or_else(|| eyre!("No message, something went very wrong [Client = {}]", c.client_type()))?;

                    assert_eq!(
                        decrypted_message,
                        message,
                        "Messages differ [Client = {}]",
                        c.client_type()
                    );

                    message_to_decrypt = c.encrypt_message(&conversation_id, &decrypted_message).await?;
                }

                let decrypted_master = master_client
                    .decrypt_message(&conversation_id, message_to_decrypt)
                    .await?
                    .app_msg
                    .ok_or_else(|| eyre!("No message recieved on master client"))?;

                assert_eq!(decrypted_master, message);

                spinner.update(format!(
                    "Step 3: Roundtripping messages... [{i}/{ROUNDTRIP_MSG_AMOUNT}]"
                ));
            }

            spinner.success(&format!(
                "Step 3: Roundtripping {ROUNDTRIP_MSG_AMOUNT} messages... [OK]"
            ));

            chrome_webdriver.kill().await?;
            http_server_hwnd.abort();
            Ok(())
        })
}

#[cfg(target_family = "wasm")]
fn run_test() -> Result<()> {
    panic!("E2E tests are not supported on this target")
}
