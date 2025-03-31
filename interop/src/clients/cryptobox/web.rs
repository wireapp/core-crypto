use crate::clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedProteusClient};
use color_eyre::eyre::Result;
use std::cell::Cell;
use std::net::SocketAddr;

#[derive(Debug)]
pub(crate) struct CryptoboxWebClient {
    browser: fantoccini::Client,
    client_id: uuid::Uuid,
    prekey_last_id: Cell<u16>,
}

impl CryptoboxWebClient {
    pub(crate) async fn new(driver_addr: &SocketAddr, server: &SocketAddr) -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();
        let browser = crate::build::web::webdriver::setup_browser(driver_addr, server, "cryptobox").await?;

        Ok(Self {
            browser,
            client_id,
            #[cfg(feature = "proteus")]
            prekey_last_id: Cell::new(0),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedClient for CryptoboxWebClient {
    fn client_name(&self) -> &str {
        "Cryptobox::web"
    }

    fn client_type(&self) -> EmulatedClientType {
        EmulatedClientType::Web
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_bytes().as_slice()
    }

    fn client_protocol(&self) -> EmulatedClientProtocol {
        EmulatedClientProtocol::PROTEUS
    }

    async fn wipe(mut self) -> Result<()> {
        let _ = self
            .browser
            .execute_async(
                r#"
const [callback] = arguments;
window.cbox.deleteData().then(callback);"#,
                vec![],
            )
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedProteusClient for CryptoboxWebClient {
    async fn init(&mut self) -> Result<()> {
        self.browser
            .execute_async(
                r#"
const [clientId, callback] = arguments;
// const { createCryptobox } = await import("./cryptobox.js");
const storeName = `cryptobox-e2e-interop-${clientId}`;
const cryptobox = await window.createCryptobox(storeName);
window.cbox = cryptobox;
callback();"#,
                vec![self.client_id.as_hyphenated().to_string().into()],
            )
            .await?;

        Ok(())
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        self.prekey_last_id.replace(self.prekey_last_id.get() + 1);

        let json_response = self
            .browser
            .execute_async(
                r#"
const [prekeyId, callback] = arguments;
const [prekey] = await window.cbox.new_prekeys(prekeyId, 1);
const { key } = window.cbox.serialize_prekey(prekey);
callback(key);"#,
                vec![self.prekey_last_id.get().into()],
            )
            .await?;

        let key_b64 = json_response.as_str().unwrap();

        use base64::Engine as _;
        Ok(base64::prelude::BASE64_STANDARD.decode(key_b64)?)
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        self.browser
            .execute_async(
                r#"
const [sessionId, prekey, callback] = arguments;
const prekeyBundle = Uint8Array.from(Object.values(prekey));
await window.cbox.session_from_prekey(sessionId, prekeyBundle.buffer);
callback();"#,
                vec![session_id.into(), prekey.into()],
            )
            .await?;

        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [sessionId, message, callback] = arguments;
const envelope = Uint8Array.from(Object.values(message));
const cleartext = await window.cbox.decrypt(sessionId, envelope.buffer);
callback(cleartext);"#,
                vec![session_id.into(), message.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [sessionId, plaintext, callback] = arguments;
const plaintextBuffer = Uint8Array.from(Object.values(plaintext));
const encrypted = await window.cbox.encrypt(sessionId, plaintextBuffer.buffer);
callback(new Uint8Array(encrypted));"#,
                vec![session_id.into(), plaintext.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [sessionId, ciphertext, callback] = arguments;
const ciphertextBuffer = Uint8Array.from(Object.values(ciphertext));
const plaintext = await window.cbox.decrypt(sessionId, ciphertextBuffer.buffer);
callback(new Uint8Array(plaintext));"#,
                vec![session_id.into(), ciphertext.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn fingerprint(&self) -> Result<String> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [callback] = arguments;
const identity = window.cbox.getIdentity();
callback(identity.public_key.fingerprint());"#,
                vec![],
            )
            .await
            .map(|value| value.as_str().unwrap().to_string())?)
    }
}
