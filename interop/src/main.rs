#![cfg_attr(target_family = "wasm", allow(dead_code, unused_imports))]

use core_crypto::DatabaseKey;

#[cfg(not(target_family = "wasm"))]
use crate::util::{MlsTransportSuccessProvider, MlsTransportTestExt};
use color_eyre::eyre::{Result, eyre};
use core_crypto::prelude::CiphersuiteName;
use std::sync::Arc;
use tls_codec::Serialize;

#[cfg(not(target_family = "wasm"))]
mod clients;
#[cfg(not(target_family = "wasm"))]
mod util;

const MLS_MAIN_CLIENTID: &[u8] = b"test_main";
const MLS_CONVERSATION_ID: &[u8] = b"test_conversation";
const ROUNDTRIP_MSG_AMOUNT: usize = 100;

const CIPHERSUITE_IN_USE: CiphersuiteName = CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// TODO: Add support for Android emulator. Tracking issue: WPB-9646
// TODO: Add support for iOS emulator when on macOS. Tracking issue: WPB-9646
fn main() -> Result<()> {
    run_test()
}

#[cfg(not(target_family = "wasm"))]
async fn create_mls_clients<'a>(
    chrome_driver_addr: &'a std::net::SocketAddr,
    web_server: &'a std::net::SocketAddr,
) -> Vec<Box<dyn clients::EmulatedMlsClient>> {
    vec![
        #[cfg(target_os = "ios")]
        Box::new(clients::corecrypto::ios::CoreCryptoIosClient::new().await.unwrap()),
        Box::new(
            clients::corecrypto::native::CoreCryptoNativeClient::new()
                .await
                .unwrap(),
        ),
        Box::new(clients::corecrypto::ffi::CoreCryptoFfiClient::new().await.unwrap()),
        Box::new(
            clients::corecrypto::web::CoreCryptoWebClient::new(chrome_driver_addr, web_server)
                .await
                .unwrap(),
        ),
    ]
}

#[cfg(all(not(target_family = "wasm"), feature = "proteus"))]
async fn create_proteus_clients<'a>(
    chrome_driver_addr: &'a std::net::SocketAddr,
    web_server: &'a std::net::SocketAddr,
) -> Vec<Box<dyn clients::EmulatedProteusClient>> {
    vec![
        #[cfg(target_os = "ios")]
        Box::new(clients::corecrypto::ios::CoreCryptoIosClient::new().await.unwrap()),
        Box::new(
            clients::corecrypto::native::CoreCryptoNativeClient::new()
                .await
                .unwrap(),
        ),
        Box::new(clients::corecrypto::ffi::CoreCryptoFfiClient::new().await.unwrap()),
        Box::new(
            clients::corecrypto::web::CoreCryptoWebClient::new(chrome_driver_addr, web_server)
                .await
                .unwrap(),
        ),
    ]
}

// need to be handled like this because https://github.com/rust-lang/cargo/issues/5220, otherwise
// it complains over a lacking main function
#[cfg(not(target_family = "wasm"))]
fn run_test() -> Result<()> {
    use std::time::{Duration, Instant};

    use tokio::net::{TcpListener, TcpStream};

    color_eyre::install()?;
    env_logger::init();

    // Check if we have a correct pwd
    let current_dir = std::env::current_dir()?;
    if current_dir.ends_with("interop") {
        let new_cwd = current_dir.parent().unwrap();
        log::info!("cwd was {current_dir:?}; setting it to {new_cwd:?}");
        std::env::set_current_dir(new_cwd)?;
    }
    let tempdir = tempfile::tempdir()?;

    // because cannot use `#[tokio::main]` on wasm target because tokio does not compile on this target
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        util::cp_wasm_files(tempdir.path().to_path_buf()).await?;

        let spinner = util::RunningProcess::new("Starting HTTP server...", false);
        let (server, server_task) = util::bind_http_server(tempdir.path().to_path_buf());
        let http_server_hwnd = tokio::task::spawn(server_task);
        spinner.success(format!("HTTP server started {server} [OK]"));

        let mut spinner = util::RunningProcess::new("Starting WebDriver [ChromeDriver & GeckoDriver]...", false);
        let chrome_driver_addr = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
        let mut chrome_webdriver = util::start_webdriver_chrome(&chrome_driver_addr).await?;
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

        run_mls_test(&chrome_driver_addr, &server).await?;

        #[cfg(feature = "proteus")]
        run_proteus_test(&chrome_driver_addr, &server).await?;

        chrome_webdriver.kill().await?;
        http_server_hwnd.abort();
        Ok(())
    })
}

#[cfg(target_family = "wasm")]
fn run_test() -> Result<()> {
    panic!("E2E tests cannot be run on WASM")
}

#[cfg(not(target_family = "wasm"))]
async fn run_mls_test(chrome_driver_addr: &std::net::SocketAddr, web_server: &std::net::SocketAddr) -> Result<()> {
    use core_crypto::prelude::*;
    use rand::distributions::DistString;

    log::info!("Using ciphersuite {CIPHERSUITE_IN_USE}");

    let spinner = util::RunningProcess::new("[MLS] Step 0: Initializing clients & env...", true);

    let mut clients = create_mls_clients(chrome_driver_addr, web_server).await;
    let configuration = SessionConfig::builder()
        .in_memory()
        .database_key(DatabaseKey::generate())
        .client_id(MLS_MAIN_CLIENTID.into())
        .ciphersuites([CIPHERSUITE_IN_USE.into()])
        .build()
        .validate()?;
    let master_client = Session::try_new(configuration).await?;

    let conversation_id = MLS_CONVERSATION_ID.to_vec();
    let config = MlsConversationConfiguration {
        ciphersuite: CIPHERSUITE_IN_USE.into(),
        ..Default::default()
    };
    let cc = CoreCrypto::from(master_client.clone());

    let success_provider = Arc::new(MlsTransportSuccessProvider::default());

    cc.provide_transport(success_provider.clone()).await;
    let transaction = cc.new_transaction().await?;
    transaction
        .new_conversation(&conversation_id, MlsCredentialType::Basic, config)
        .await?;

    spinner.success("[MLS] Step 0: Initializing clients [OK]");

    let spinner = util::RunningProcess::new("[MLS] Step 1: Fetching KeyPackages from clients...", true);

    use tls_codec::Deserialize as _;
    let mut key_packages = vec![];
    for c in clients.iter() {
        let kp = c.get_keypackage().await?;
        let kp = KeyPackageIn::tls_deserialize(&mut kp.as_slice())?;
        key_packages.push(kp);
    }

    spinner.success("[MLS] Step 1: KeyPackages [OK]");

    let spinner = util::RunningProcess::new("[MLS] Step 2: Adding clients to conversation...", true);

    transaction
        .conversation(&conversation_id)
        .await?
        .add_members(key_packages)
        .await?;

    let conversation_add_msg = success_provider.latest_welcome_message().await;
    let welcome_raw = conversation_add_msg.tls_serialize_detached()?;

    for c in clients.iter_mut() {
        let conversation_id_from_welcome = c.process_welcome(&welcome_raw).await?;
        assert_eq!(conversation_id_from_welcome, conversation_id);
    }

    spinner.success("[MLS] Step 2: Added clients [OK]");

    let mut spinner = util::RunningProcess::new(
        format!("[MLS] Step 3: Roundtripping messages [0/{ROUNDTRIP_MSG_AMOUNT}]"),
        true,
    );

    let mut prng = rand::thread_rng();
    let mut message;
    for i in 1..=ROUNDTRIP_MSG_AMOUNT {
        message = rand::distributions::Alphanumeric.sample_string(&mut prng, 16);

        log::info!(
            "Master client [{}] >>> {}",
            hex::encode(master_client.id().await?.as_slice()),
            message
        );

        let mut message_to_decrypt = transaction
            .conversation(&conversation_id)
            .await?
            .encrypt_message(&message)
            .await?;

        for c in clients.iter_mut() {
            let decrypted_message_raw = c
                .decrypt_message(&conversation_id, &message_to_decrypt)
                .await?
                .ok_or_else(|| {
                    eyre!(
                        "[MLS] No message, something went very wrong [Client = {}]",
                        c.client_type()
                    )
                })?;

            let decrypted_message = String::from_utf8(decrypted_message_raw)?;

            log::info!(
                "{} [{}] <<< {}",
                c.client_name(),
                hex::encode(c.client_id()),
                decrypted_message
            );

            assert_eq!(
                decrypted_message,
                message,
                "[MLS] Messages differ [Client = {}]",
                c.client_type()
            );

            message_to_decrypt = c
                .encrypt_message(&conversation_id, decrypted_message.as_bytes())
                .await?;
        }

        let decrypted_master_raw = transaction
            .conversation(&conversation_id)
            .await
            .unwrap()
            .decrypt_message(message_to_decrypt)
            .await?
            .app_msg
            .ok_or_else(|| eyre!("[MLS] No message received on master client"))?;

        let decrypted_master = String::from_utf8(decrypted_master_raw)?;

        assert_eq!(decrypted_master, message);

        spinner.update(format!(
            "[MLS] Step 3: Roundtripping messages... [{i}/{ROUNDTRIP_MSG_AMOUNT}]"
        ));
    }

    spinner.success(format!(
        "[MLS] Step 3: Roundtripping {ROUNDTRIP_MSG_AMOUNT} messages... [OK]"
    ));

    let spinner = util::RunningProcess::new("[MLS] Step 4: Deleting clients...", true);
    for client in &mut clients {
        client.wipe().await?;
    }
    spinner.success("[MLS] Step 4: Deleting clients [OK]");

    Ok(())
}

#[cfg(all(not(target_family = "wasm"), feature = "proteus"))]
async fn run_proteus_test(chrome_driver_addr: &std::net::SocketAddr, web_server: &std::net::SocketAddr) -> Result<()> {
    use core_crypto::prelude::*;

    let spinner = util::RunningProcess::new("[Proteus] Step 0: Initializing clients & env...", true);

    let mut clients = create_proteus_clients(chrome_driver_addr, web_server).await;

    for client in &mut clients {
        client.init().await?;
    }

    let configuration = SessionConfig::builder()
        .in_memory()
        .database_key(DatabaseKey::generate())
        .client_id(MLS_MAIN_CLIENTID.into())
        .ciphersuites([CIPHERSUITE_IN_USE.into()])
        .build()
        .validate()?;
    let master_client = CoreCrypto::from(Session::try_new(configuration).await?);
    let transaction = master_client.new_transaction().await?;
    transaction.proteus_init().await?;

    let master_fingerprint = master_client.proteus_fingerprint().await?;

    spinner.success("[Proteus] Step 0: Initializing clients [OK]");

    let mut spinner = util::RunningProcess::new("[Proteus] Step 1: Fetching PreKeys from clients...", true);

    let mut client_type_mapping = std::collections::HashMap::new();
    let mut prekeys = std::collections::HashMap::new();
    for c in clients.iter_mut() {
        let client_name = c.client_name();
        spinner.update(format!("[Proteus] Step 1: PreKeys - {client_name}"));
        let fingerprint = c.fingerprint().await?;
        spinner.update(format!("[Proteus] Step 1: PreKeys - {fingerprint}@{client_name}"));
        client_type_mapping.insert(fingerprint.clone(), client_name.to_string());
        let prekey = c.get_prekey().await?;
        prekeys.insert(fingerprint, prekey);
    }

    spinner.success("[Proteus] Step 1: PreKeys [OK]");

    let mut spinner = util::RunningProcess::new("[Proteus] Step 2: Creating sessions...", true);

    let mut master_sessions = vec![];
    let mut messages = std::collections::HashMap::new();
    const PROTEUS_INITIAL_MESSAGE: &[u8] = b"Hello world!";
    for (fingerprint, prekey) in prekeys {
        spinner.update(format!(
            "[Proteus] Step 2: Session master -> {fingerprint}@{}",
            client_type_mapping[&fingerprint]
        ));
        let session_arc = transaction.proteus_session_from_prekey(&fingerprint, &prekey).await?;
        let mut session = session_arc.write().await;
        messages.insert(fingerprint, session.encrypt(PROTEUS_INITIAL_MESSAGE)?);
        master_sessions.push(session.identifier().to_string());
    }

    let session_id_with_master = format!("session-{master_fingerprint}");
    for c in clients.iter_mut() {
        let fingerprint = c.fingerprint().await?;
        spinner.update(format!(
            "[Proteus] Step 2: Session {fingerprint}@{} -> master",
            c.client_name()
        ));
        let message = messages.remove(&fingerprint).unwrap();
        let message_recv = c.session_from_message(&session_id_with_master, &message).await?;
        assert_eq!(PROTEUS_INITIAL_MESSAGE, message_recv);
    }

    assert!(messages.is_empty());

    spinner.success("[Proteus] Step 2: Creating sessions [OK]");

    let mut spinner = util::RunningProcess::new(
        format!("[Proteus] Step 3: Roundtripping messages [0/{ROUNDTRIP_MSG_AMOUNT}]"),
        true,
    );

    let mut prng = rand::thread_rng();
    let mut message = [0u8; 128];
    let mut master_messages_to_decrypt = std::collections::HashMap::new();
    for i in 0..ROUNDTRIP_MSG_AMOUNT {
        use rand::RngCore as _;

        prng.fill_bytes(&mut message);

        let mut messages_to_decrypt = transaction.proteus_encrypt_batched(&master_sessions, &message).await?;

        for c in clients.iter_mut() {
            let fingerprint = c.fingerprint().await?;
            let decrypted_message = c
                .decrypt(
                    &session_id_with_master,
                    &messages_to_decrypt.remove(&fingerprint).unwrap(),
                )
                .await?;

            assert_eq!(
                decrypted_message,
                message,
                "[Proteus] Messages differ [Client = {}::{}]",
                c.client_name(),
                c.client_type(),
            );

            let ciphertext = c.encrypt(&session_id_with_master, &decrypted_message).await?;
            master_messages_to_decrypt.insert(fingerprint, ciphertext);
        }

        for (fingerprint, encrypted) in master_messages_to_decrypt.drain() {
            let decrypted = transaction.proteus_decrypt(&fingerprint, &encrypted).await?;
            assert_eq!(decrypted, message);
        }

        spinner.update(format!(
            "[Proteus] Step 3: Roundtripping messages... [{i}/{ROUNDTRIP_MSG_AMOUNT}]"
        ));
    }

    clients.clear();

    spinner.success(format!(
        "[Proteus] Step 3: Roundtripping {ROUNDTRIP_MSG_AMOUNT} messages... [OK]"
    ));

    let spinner = util::RunningProcess::new("[Proteus] Step 4: Deleting clients...", true);
    for client in &mut clients {
        client.wipe().await?;
    }
    spinner.success("[Proteus] Step 4: Deleting clients [OK]");

    Ok(())
}
