#![allow(clippy::assign_op_pattern)]

use color_eyre::eyre::Result;
use core_crypto::prelude::MlsCiphersuite;

pub(crate) mod corecrypto;

bitflags::bitflags! {
    pub(crate) struct EmulatedClientProtocol: u8 {
        const MLS = 0x01;
        const PROTEUS = 0x02;
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[allow(dead_code)]
pub(crate) enum EmulatedClientType {
    Native,
    // Natively test the FFI in `generic.rs`
    NativeFfi,
    Web,
    // TODO: Bind with & drive iOS Emulator. Tracking issue: WPB-9646
    AppleiOS,
    // TODO: Bind with & drive Android Emulator. Tracking issue: WPB-9646
    Android,
}

impl std::fmt::Display for EmulatedClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            Self::Native => "Native",
            Self::NativeFfi => "Native FFI",
            Self::Web => "Web",
            Self::AppleiOS => "iOS",
            Self::Android => "Android",
        };

        write!(f, "{repr}")
    }
}

#[async_trait::async_trait(?Send)]
#[allow(dead_code)]
pub(crate) trait EmulatedClient {
    fn client_name(&self) -> &str;
    fn client_type(&self) -> EmulatedClientType;
    fn client_id(&self) -> &[u8];
    fn client_protocol(&self) -> EmulatedClientProtocol;
    async fn wipe(&mut self) -> Result<()>;
}

#[async_trait::async_trait(?Send)]
#[allow(dead_code)]
pub(crate) trait EmulatedMlsClient: EmulatedClient {
    async fn get_keypackage(&self) -> Result<Vec<u8>>;
    async fn add_client(&self, conversation_id: &[u8], kp: &[u8]) -> Result<()>;
    async fn kick_client(&self, conversation_id: &[u8], client_id: &[u8]) -> Result<()>;
    async fn process_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>>;
    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    // TODO: Make it more complex so that we can extract other things like proposals etc. Tracking issue: WPB-9647
    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>>;
}

#[async_trait::async_trait(?Send)]
#[allow(dead_code)]
pub(crate) trait EmulatedProteusClient: EmulatedClient {
    async fn init(&mut self) -> Result<()> {
        Ok(())
    }
    async fn get_prekey(&self) -> Result<Vec<u8>>;
    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()>;
    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>>;
    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
    async fn fingerprint(&self) -> Result<String>;
}

#[async_trait::async_trait(?Send)]
#[allow(dead_code)]
pub(crate) trait EmulatedE2eIdentityClient: EmulatedClient {
    async fn e2ei_new_enrollment(&mut self, ciphersuite: MlsCiphersuite) -> Result<()>;
}
