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

#![cfg_attr(target_family = "wasm", allow(dead_code, unused_imports))]

use color_eyre::eyre::{eyre, Result};
use std::rc::Rc;
use tls_codec::Serialize;

#[cfg(not(target_family = "wasm"))]
use crate::clients::{EmulatedClient, EmulatedProteusClient};
use core_crypto::prelude::CiphersuiteName;

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

const MLS_MAIN_CLIENTID: &[u8] = b"test_main";
const MLS_CONVERSATION_ID: &[u8] = b"test_conversation";
const ROUNDTRIP_MSG_AMOUNT: usize = 100;

const CIPHERSUITE_IN_USE: CiphersuiteName = CiphersuiteName::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// TODO: Add support for Android emulator. Tracking issue: WPB-9646
// TODO: Add support for iOS emulator when on macOS. Tracking issue: WPB-9646
fn main() -> Result<()> {
    run_test()
}

// need to be handled like this because https://github.com/rust-lang/cargo/issues/5220, otherwise
// it complains over a lacking main function
#[cfg(not(target_family = "wasm"))]
fn run_test() -> Result<()> {
    use std::time::{Duration, Instant};

    use tokio::net::{TcpListener, TcpStream};

    color_eyre::install()?;
    if std::env::var("RUST_LOG").is_ok() || std::env::var("CI").is_ok() {
        femme::start();
    }

    let force_webdriver_install = std::env::var("FORCE_WEBDRIVER_INSTALL").is_ok();

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
        build::web::webdriver::setup_webdriver(force_webdriver_install).await?;

        build::web::wasm::build_wasm(tempdir.path().to_path_buf()).await?;

        let spinner = util::RunningProcess::new("Starting HTTP server...", false);
        let http_server_hwnd = tokio::task::spawn(build::web::wasm::spawn_http_server(tempdir.path().to_path_buf()));
        spinner.success(format!("HTTP server started at 0.0.0.0:{TEST_SERVER_PORT} [OK]"));

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

        run_mls_test(&chrome_driver_addr).await?;

        #[cfg(feature = "proteus")]
        run_proteus_test(&chrome_driver_addr).await?;

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
async fn run_mls_test(chrome_driver_addr: &std::net::SocketAddr) -> Result<()> {
    use core_crypto::prelude::*;
    use rand::distributions::DistString;

    log::info!("Using ciphersuite {}", CIPHERSUITE_IN_USE);

    let spinner = util::RunningProcess::new("[MLS] Step 0: Initializing clients & env...", true);

    let native_client = Rc::new(clients::corecrypto::native::CoreCryptoNativeClient::new().await?);
    let ffi_client = Rc::new(clients::corecrypto::ffi::CoreCryptoFfiClient::new().await?);
    let web_client = Rc::new(clients::corecrypto::web::CoreCryptoWebClient::new(chrome_driver_addr).await?);

    let mut clients: Vec<Rc<dyn clients::EmulatedMlsClient>> =
        vec![native_client.clone(), ffi_client.clone(), web_client.clone()];

    let ciphersuites = vec![CIPHERSUITE_IN_USE.into()];
    let configuration = MlsCentralConfiguration::try_new(
        "whatever".into(),
        "test".into(),
        Some(MLS_MAIN_CLIENTID.into()),
        ciphersuites,
        None,
        Some(100),
    )?;
    let master_client = MlsCentral::try_new_in_memory(configuration).await?;

    let conversation_id = MLS_CONVERSATION_ID.to_vec();
    let config = MlsConversationConfiguration {
        ciphersuite: CIPHERSUITE_IN_USE.into(),
        ..Default::default()
    };
    let cc = CoreCrypto::from(master_client.clone());
    let transaction = cc.new_transaction().await?;
    transaction
        .new_conversation(&conversation_id, MlsCredentialType::Basic, config)
        .await?;

    spinner.success("[MLS] Step 0: Initializing clients [OK]");

    let spinner = util::RunningProcess::new("[MLS] Step 1: Fetching KeyPackages from clients...", true);

    use tls_codec::Deserialize as _;
    let mut key_packages = vec![];
    for c in clients.iter_mut() {
        let kp = c.get_keypackage().await?;
        let kp = KeyPackageIn::tls_deserialize(&mut kp.as_slice())?;
        key_packages.push(kp);
    }

    spinner.success("[MLS] Step 1: KeyPackages [OK]");

    let spinner = util::RunningProcess::new("[MLS] Step 2: Adding clients to conversation...", true);

    let conversation_add_msg = transaction
        .add_members_to_conversation(&conversation_id, key_packages)
        .await?;

    transaction.commit_accepted(&conversation_id).await?;

    let welcome_raw = conversation_add_msg.welcome.tls_serialize_detached()?;

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
            hex::encode(master_client.client_id().await?.as_slice()),
            message
        );

        let mut message_to_decrypt = transaction.encrypt_message(&conversation_id, &message).await?;

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
            .decrypt_message(&conversation_id, message_to_decrypt)
            .await?
            .app_msg
            .ok_or_else(|| eyre!("[MLS] No message received on master client"))?;

        let decrypted_master = String::from_utf8(decrypted_master_raw)?;

        assert_eq!(decrypted_master, message);

        spinner.update(format!(
            "[MLS] Step 3: Roundtripping messages... [{i}/{ROUNDTRIP_MSG_AMOUNT}]"
        ));
    }

    clients.clear();

    spinner.success(format!(
        "[MLS] Step 3: Roundtripping {ROUNDTRIP_MSG_AMOUNT} messages... [OK]"
    ));

    let spinner = util::RunningProcess::new("[MLS] Step 4: Deleting clients...", true);

    Rc::into_inner(native_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;
    Rc::into_inner(ffi_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;
    Rc::into_inner(web_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;

    spinner.success("[MLS] Step 4: Deleting clients [OK]");

    Ok(())
}

#[cfg(all(not(target_family = "wasm"), feature = "proteus"))]
async fn run_proteus_test(chrome_driver_addr: &std::net::SocketAddr) -> Result<()> {
    use core_crypto::prelude::*;

    let spinner = util::RunningProcess::new("[Proteus] Step 0: Initializing clients & env...", true);

    let mut native_client = clients::corecrypto::native::CoreCryptoNativeClient::new().await?;
    let mut ffi_client = clients::corecrypto::ffi::CoreCryptoFfiClient::new().await?;
    let mut web_client = clients::corecrypto::web::CoreCryptoWebClient::new(chrome_driver_addr).await?;
    let mut cryptobox_native_client = clients::cryptobox::native::CryptoboxNativeClient::new();
    let mut cryptobox_web_client = clients::cryptobox::web::CryptoboxWebClient::new(chrome_driver_addr).await?;

    native_client.init().await?;
    ffi_client.init().await?;
    web_client.init().await?;
    cryptobox_native_client.init().await?;
    cryptobox_web_client.init().await?;

    let native_client = Rc::new(native_client);
    let ffi_client = Rc::new(ffi_client);
    let web_client = Rc::new(web_client);
    let cryptobox_native_client = Rc::new(cryptobox_native_client);
    let cryptobox_web_client = Rc::new(cryptobox_web_client);

    let mut clients: Vec<Rc<dyn clients::EmulatedProteusClient>> = vec![
        native_client.clone(),
        ffi_client.clone(),
        web_client.clone(),
        cryptobox_native_client.clone(),
        cryptobox_web_client.clone(),
    ];

    let configuration = MlsCentralConfiguration::try_new(
        "whatever".into(),
        "test".into(),
        Some(MLS_MAIN_CLIENTID.into()),
        vec![MlsCiphersuite::default()],
        None,
        Some(100),
    )?;
    let master_client = CoreCrypto::from(MlsCentral::try_new_in_memory(configuration).await?);
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

    Rc::into_inner(native_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;
    Rc::into_inner(ffi_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;
    Rc::into_inner(web_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;
    Rc::into_inner(cryptobox_native_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;
    Rc::into_inner(cryptobox_web_client)
        .expect("Only one strong reference to the interop client")
        .wipe()
        .await?;

    spinner.success("[Proteus] Step 4: Deleting clients [OK]");

    Ok(())
}
