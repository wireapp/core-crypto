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

// TODO: Add support for Android emulator
// TODO: Add support for iOS emulator when on macOS
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

    // because cannot use `#[tokio::main]` on wasm target because tokio does not compile on this target
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let _ = tokio::task::spawn_blocking(move || build::web::webdriver::setup_webdriver(force_webdriver_install))
            .await?;

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
    use core_crypto::prelude::{tls_codec::Serialize, *};

    let spinner = util::RunningProcess::new("[MLS] Step 0: Initializing clients & env...", true);

    let mut clients: Vec<Box<dyn clients::EmulatedMlsClient>> = vec![];
    clients.push(Box::new(
        clients::corecrypto::native::CoreCryptoNativeClient::new().await?,
    ));
    clients.push(Box::new(
        clients::corecrypto::web::CoreCryptoWebClient::new(chrome_driver_addr).await?,
    ));

    let ciphersuites = vec![MlsCiphersuite::default()];
    let configuration = MlsCentralConfiguration::try_new(
        "whatever".into(),
        "test".into(),
        Some(MLS_MAIN_CLIENTID.into()),
        ciphersuites,
    )?;
    let mut master_client = MlsCentral::try_new_in_memory(configuration, None).await?;

    let conversation_id = MLS_CONVERSATION_ID.to_vec();
    master_client
        .new_conversation(conversation_id.clone(), Default::default())
        .await?;

    spinner.success("[MLS] Step 0: Initializing clients [OK]");

    let spinner = util::RunningProcess::new("[MLS] Step 1: Fetching KeyPackages from clients...", true);

    let mut members = vec![];
    for c in clients.iter_mut() {
        let kp = c.get_keypackage().await?;
        members.push(ConversationMember::new_raw(c.client_id().into(), kp)?);
    }

    spinner.success("[MLS] Step 1: KeyPackages [OK]");

    let spinner = util::RunningProcess::new("[MLS] Step 2: Adding clients to conversation...", true);

    let conversation_add_msg = master_client
        .add_members_to_conversation(&conversation_id, members.as_mut_slice())
        .await?;

    master_client.commit_accepted(&conversation_id).await?;

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
    let mut message = [0u8; 128];
    for i in 0..ROUNDTRIP_MSG_AMOUNT {
        use rand::RngCore as _;

        prng.fill_bytes(&mut message);

        let mut message_to_decrypt = master_client.encrypt_message(&conversation_id, &message).await?;

        for c in clients.iter_mut() {
            let decrypted_message = c
                .decrypt_message(&conversation_id, &message_to_decrypt)
                .await?
                .ok_or_else(|| {
                    eyre!(
                        "[MLS] No message, something went very wrong [Client = {}]",
                        c.client_type()
                    )
                })?;

            assert_eq!(
                decrypted_message,
                message,
                "[MLS] Messages differ [Client = {}]",
                c.client_type()
            );

            message_to_decrypt = c.encrypt_message(&conversation_id, &decrypted_message).await?;
        }

        let decrypted_master = master_client
            .decrypt_message(&conversation_id, message_to_decrypt)
            .await?
            .app_msg
            .ok_or_else(|| eyre!("[MLS] No message recieved on master client"))?;

        assert_eq!(decrypted_master, message);

        spinner.update(format!(
            "[MLS] Step 3: Roundtripping messages... [{i}/{ROUNDTRIP_MSG_AMOUNT}]"
        ));
    }

    spinner.success(&format!(
        "[MLS] Step 3: Roundtripping {ROUNDTRIP_MSG_AMOUNT} messages... [OK]"
    ));

    Ok(())
}

#[cfg(all(not(target_family = "wasm"), feature = "proteus"))]
async fn run_proteus_test(chrome_driver_addr: &std::net::SocketAddr) -> Result<()> {
    use core_crypto::prelude::*;

    let spinner = util::RunningProcess::new("[Proteus] Step 0: Initializing clients & env...", true);

    let mut clients: Vec<Box<dyn clients::EmulatedProteusClient>> = vec![];
    clients.push(Box::new(
        clients::corecrypto::native::CoreCryptoNativeClient::new().await?,
    ));
    clients.push(Box::new(
        clients::corecrypto::web::CoreCryptoWebClient::new(chrome_driver_addr).await?,
    ));
    clients.push(Box::new(clients::cryptobox::native::CryptoboxNativeClient::new()));
    clients.push(Box::new(
        clients::cryptobox::web::CryptoboxWebClient::new(chrome_driver_addr).await?,
    ));

    for c in clients.iter_mut() {
        c.init().await?;
    }

    let configuration = MlsCentralConfiguration::try_new(
        "whatever".into(),
        "test".into(),
        Some(MLS_MAIN_CLIENTID.into()),
        vec![MlsCiphersuite::default()],
    )?;
    let mut master_client = CoreCrypto::from(MlsCentral::try_new_in_memory(configuration, None).await?);
    master_client.proteus_init().await?;

    let master_fingerprint = master_client.proteus_fingerprint()?;

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
        let session = master_client.proteus_session_from_prekey(&fingerprint, &prekey).await?;
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

        let mut messages_to_decrypt = master_client
            .proteus_encrypt_batched(&master_sessions, &message)
            .await?;

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
                "[Proteus] Messages differ [Client = {}]",
                c.client_type()
            );

            let ciphertext = c.encrypt(&session_id_with_master, &decrypted_message).await?;
            master_messages_to_decrypt.insert(fingerprint, ciphertext);
        }

        for (fingerprint, encrypted) in master_messages_to_decrypt.drain() {
            let decrypted = master_client.proteus_decrypt(&fingerprint, &encrypted).await?;
            assert_eq!(decrypted, message);
        }

        spinner.update(format!(
            "[Proteus] Step 3: Roundtripping messages... [{i}/{ROUNDTRIP_MSG_AMOUNT}]"
        ));
    }

    spinner.success(&format!(
        "[Proteus] Step 3: Roundtripping {ROUNDTRIP_MSG_AMOUNT} messages... [OK]"
    ));

    Ok(())
}
