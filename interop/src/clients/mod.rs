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

use color_eyre::eyre::Result;
use core_crypto::prelude::MlsCiphersuite;

pub mod corecrypto;
#[cfg(feature = "proteus")]
pub mod cryptobox;

bitflags::bitflags! {
    pub struct EmulatedClientProtocol: u8 {
        const MLS = 0x01;
        const PROTEUS = 0x02;
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum EmulatedClientType {
    Native,
    Web,
    // TODO: Bind with & drive iOS Emulator
    AppleiOS,
    // TODO: Bind with & drive Android Emulator
    Android,
}

impl std::fmt::Display for EmulatedClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            EmulatedClientType::Native => "Native",
            EmulatedClientType::Web => "Web",
            EmulatedClientType::AppleiOS => "iOS",
            EmulatedClientType::Android => "Android",
        };

        write!(f, "{repr}")
    }
}

#[async_trait::async_trait(?Send)]
pub trait EmulatedClient {
    fn client_name(&self) -> &str;
    fn client_type(&self) -> EmulatedClientType;
    fn client_id(&self) -> &[u8];
    fn client_protocol(&self) -> EmulatedClientProtocol;
    async fn wipe(mut self) -> Result<()>;
}

#[async_trait::async_trait(?Send)]
pub trait EmulatedMlsClient: EmulatedClient {
    async fn get_keypackage(&mut self) -> Result<Vec<u8>>;
    async fn add_client(&mut self, conversation_id: &[u8], client_id: &[u8], kp: &[u8]) -> Result<Vec<u8>>;
    async fn kick_client(&mut self, conversation_id: &[u8], client_id: &[u8]) -> Result<Vec<u8>>;
    async fn process_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>>;
    async fn encrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    // TODO: Make it more complex so that we can extract other things like proposals etc
    async fn decrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>>;
}

#[async_trait::async_trait(?Send)]
pub trait EmulatedProteusClient: EmulatedClient {
    async fn init(&mut self) -> Result<()> {
        Ok(())
    }
    async fn get_prekey(&mut self) -> Result<Vec<u8>>;
    async fn session_from_prekey(&mut self, session_id: &str, prekey: &[u8]) -> Result<()>;
    async fn session_from_message(&mut self, session_id: &str, message: &[u8]) -> Result<Vec<u8>>;
    async fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
    async fn fingerprint(&self) -> Result<String>;
}

#[async_trait::async_trait(?Send)]
pub trait EmulatedE2eIdentityClient: EmulatedClient {
    async fn new_acme_enrollment(&mut self, ciphersuite: MlsCiphersuite) -> Result<()>;
}
