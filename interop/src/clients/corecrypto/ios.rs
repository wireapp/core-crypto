// Wire
// Copyright (C) 2025 Wire Swiss GmbH

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

use crate::{
    CIPHERSUITE_IN_USE,
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
};
use base64::{Engine as _, engine::general_purpose};
use color_eyre::eyre::Result;
use core_crypto::prelude::{KeyPackage, KeyPackageIn};
use std::cell::{Cell, RefCell};
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use thiserror::Error;
use tls_codec::Deserialize;

#[derive(Debug)]
struct SimulatorDriver {
    device: String,
    process: Child,
    output: RefCell<BufReader<ChildStdout>>,
}

#[derive(Debug, serde::Deserialize)]
enum InteropResult {
    #[serde(rename = "success")]
    Success { value: String },
    #[serde(rename = "failure")]
    Failure { message: String },
}

#[derive(Error, Debug)]
#[error("simulator driver error: {msg}")]
struct SimulatorDriverError {
    msg: String,
}

impl SimulatorDriver {
    fn new(device: String, application: String) -> Self {
        log::info!("launching application: {}", application);

        let mut process = Command::new("xcrun")
            .args([
                "simctl",
                "launch",
                "--console-pty",
                "--terminate-running-process",
                &device,
                &application,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to launch application");

        let mut output = BufReader::new(
            process
                .stdout
                .take()
                .expect("Expected stdout to be available on child process"),
        );
        let mut line = String::new();

        // Waiting for confirmation that the application has launched.
        while !line.contains("Ready") {
            line.clear();
            output
                .read_line(&mut line)
                .expect("was expecting ready signal on stdout");
        }

        log::info!("application launched: {}", line);

        Self {
            device,
            process,
            output: RefCell::new(output),
        }
    }

    async fn execute(&self, action: String) -> Result<String> {
        log::info!("interop://{}", action);

        Command::new("xcrun")
            .args([
                "simctl",
                "openurl",
                &self.device,
                format!("interop://{}", action).as_str(),
            ])
            .output()
            .expect("Failed to execute action");

        let mut result = String::new();
        let mut output = self.output.try_borrow_mut()?;

        output.read_line(&mut result)?;

        log::info!("{}", result);

        let result: InteropResult = serde_json::from_str(result.trim())?;

        match result {
            InteropResult::Success { value } => Ok(value),
            InteropResult::Failure { message } => Err(SimulatorDriverError { msg: message }.into()),
        }
    }
}

impl Drop for SimulatorDriver {
    fn drop(&mut self) {
        self.process.kill().expect("expected child process to be killed")
    }
}

#[derive(Debug)]
pub(crate) struct CoreCryptoIosClient {
    driver: SimulatorDriver,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: Cell<u16>,
}

impl CoreCryptoIosClient {
    pub(crate) async fn new() -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_str = client_id.as_hyphenated().to_string();
        let client_id_base64 = general_purpose::STANDARD.encode(client_id_str.as_str());
        let ciphersuite = CIPHERSUITE_IN_USE as u16;

        let driver = SimulatorDriver::new("booted".into(), "com.wire.InteropClient".into());
        log::info!("initialising core crypto with ciphersuite {}", ciphersuite);
        driver
            .execute(format!(
                "init-mls?client={}&ciphersuite={}",
                client_id_base64, ciphersuite
            ))
            .await?;

        Ok(Self {
            driver,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: Cell::new(0),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedClient for CoreCryptoIosClient {
    fn client_name(&self) -> &str {
        "CoreCrypto::ios"
    }

    fn client_type(&self) -> EmulatedClientType {
        EmulatedClientType::AppleiOS
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_slice()
    }

    fn client_protocol(&self) -> EmulatedClientProtocol {
        EmulatedClientProtocol::MLS | EmulatedClientProtocol::PROTEUS
    }

    async fn wipe(mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoIosClient {
    async fn get_keypackage(&self) -> Result<Vec<u8>> {
        let ciphersuite = CIPHERSUITE_IN_USE as u16;
        let start = std::time::Instant::now();
        let kp_base64 = self
            .driver
            .execute(format!("get-key-package?ciphersuite={}", ciphersuite))
            .await?;
        let kp_raw = general_purpose::STANDARD.decode(kp_base64)?;
        let kp: KeyPackage = KeyPackageIn::tls_deserialize(&mut kp_raw.as_slice())?.into();

        log::info!(
            "KP Init Key [took {}ms]: Client {} [{}] - {}",
            start.elapsed().as_millis(),
            self.client_name(),
            hex::encode(&self.client_id),
            hex::encode(kp.hpke_init_key()),
        );

        Ok(kp_raw)
    }

    async fn add_client(&self, conversation_id: &[u8], kp: &[u8]) -> Result<()> {
        let cid_base64 = general_purpose::STANDARD.encode(conversation_id);
        let kp_base64 = general_purpose::STANDARD.encode(kp);
        let ciphersuite = CIPHERSUITE_IN_USE as u16;
        self.driver
            .execute(format!(
                "add-client?cid={}&ciphersuite={}&kp={}",
                cid_base64, ciphersuite, kp_base64
            ))
            .await?;

        Ok(())
    }

    async fn kick_client(&self, conversation_id: &[u8], client_id: &[u8]) -> Result<()> {
        let cid_base64 = general_purpose::STANDARD.encode(conversation_id);
        let client_id_base64 = general_purpose::STANDARD.encode(client_id);
        self.driver
            .execute(format!("remove-client?cid={}&client={}", cid_base64, client_id_base64))
            .await?;

        Ok(())
    }

    async fn process_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        let welcome_path = std::env::temp_dir().join(format!("welcome-{}", uuid::Uuid::new_v4().as_hyphenated()));
        fs::write(&welcome_path, welcome)?;
        let conversation_id_base64 = self
            .driver
            .execute(format!(
                "process-welcome?welcome_path={}",
                welcome_path.to_str().unwrap()
            ))
            .await?;
        let conversation_id = general_purpose::STANDARD.decode(conversation_id_base64)?;

        Ok(conversation_id)
    }

    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let cid_base64 = general_purpose::STANDARD.encode(conversation_id);
        let message_base64 = general_purpose::STANDARD.encode(message);
        let encrypted_message_base64 = self
            .driver
            .execute(format!("encrypt-message?cid={}&message={}", cid_base64, message_base64))
            .await?;
        let encrypted_message = general_purpose::STANDARD.decode(encrypted_message_base64)?;

        Ok(encrypted_message)
    }

    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let cid_base64 = general_purpose::STANDARD.encode(conversation_id);
        let message_base64 = general_purpose::STANDARD.encode(message);
        let result = self
            .driver
            .execute(format!("decrypt-message?cid={}&message={}", cid_base64, message_base64))
            .await?;

        if result == "decrypted protocol message" {
            Ok(None)
        } else {
            let decrypted_message = general_purpose::STANDARD.decode(result)?;
            Ok(Some(decrypted_message))
        }
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoIosClient {
    async fn init(&mut self) -> Result<()> {
        self.driver.execute("init-proteus".into()).await?;
        Ok(())
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        let prekey_last_id = self.prekey_last_id.get() + 1;
        self.prekey_last_id.replace(prekey_last_id);

        let prekey_base64 = self.driver.execute(format!("get-prekey?id={}", prekey_last_id)).await?;
        let prekey = general_purpose::STANDARD.decode(prekey_base64)?;

        Ok(prekey)
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let prekey_base64 = general_purpose::STANDARD.encode(prekey);
        self.driver
            .execute(format!(
                "session-from-prekey?session_id={}&prekey={}",
                session_id, prekey_base64
            ))
            .await?;

        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let message_base64 = general_purpose::STANDARD.encode(message);
        let decrypted_message_base64 = self
            .driver
            .execute(format!(
                "session-from-message?session_id={}&message={}",
                session_id, message_base64
            ))
            .await?;
        let decrypted_message = general_purpose::STANDARD.decode(decrypted_message_base64)?;

        Ok(decrypted_message)
    }
    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let plaintext_base64 = general_purpose::STANDARD.encode(plaintext);
        let encrypted_message_base64 = self
            .driver
            .execute(format!(
                "encrypt-proteus?session_id={}&message={}",
                session_id, plaintext_base64
            ))
            .await?;
        let encrypted_message = general_purpose::STANDARD.decode(encrypted_message_base64)?;

        Ok(encrypted_message)
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext);
        let decrypted_message_base64 = self
            .driver
            .execute(format!(
                "decrypt-proteus?session_id={}&message={}",
                session_id, ciphertext_base64
            ))
            .await?;
        let decrypted_message = general_purpose::STANDARD.decode(decrypted_message_base64)?;

        Ok(decrypted_message)
    }

    async fn fingerprint(&self) -> Result<String> {
        let fingerprint = self.driver.execute("get-fingerprint".into()).await?;

        Ok(fingerprint)
    }
}
