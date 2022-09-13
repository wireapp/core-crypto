use color_eyre::eyre::Result;

pub mod native;
pub mod web;

#[derive(Debug)]
pub enum EmulatedClientType {
    Native,
    Web,
    // AppleiOS,
    // Android,
}

impl std::fmt::Display for EmulatedClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            EmulatedClientType::Native => "Native",
            EmulatedClientType::Web => "Web",
            // EmulatedClientType::AppleiOS => "iOS",
            // EmulatedClientType::Android => "Android",
        };

        write!(f, "{repr}")
    }
}

#[async_trait::async_trait(?Send)]
pub trait EmulatedClient {
    fn client_type(&self) -> EmulatedClientType;
    fn client_id(&self) -> &[u8];
    async fn get_keypackage(&mut self) -> Result<Vec<u8>>;
    async fn add_client(&mut self, conversation_id: &[u8], client_id: &[u8], kp: &[u8]) -> Result<Vec<u8>>;
    async fn kick_client(&mut self, conversation_id: &[u8], client_id: &[u8]) -> Result<Vec<u8>>;
    async fn process_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>>;
    async fn encrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    // TODO: Make it more complex so that we can extract other things like proposals etc
    async fn decrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>>;
}
