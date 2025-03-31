use crate::{
    CIPHERSUITE_IN_USE,
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
};
use color_eyre::eyre::Result;
use core_crypto::prelude::{KeyPackage, KeyPackageIn};
use std::cell::Cell;
use std::net::SocketAddr;
use tls_codec::Deserialize;

#[derive(Debug)]
pub(crate) struct CoreCryptoWebClient {
    browser: fantoccini::Client,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: Cell<u16>,
}

impl CoreCryptoWebClient {
    pub(crate) async fn new(driver_addr: &SocketAddr, server: &SocketAddr) -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_str = client_id.as_hyphenated().to_string();
        let ciphersuite = CIPHERSUITE_IN_USE as u16;
        let client_config = serde_json::json!({
            "databaseName": format!("db-{client_id_str}"),
            "key": "test",
            "ciphersuites": [ciphersuite],
            "clientId": client_id_str
        });
        let browser = crate::build::web::webdriver::setup_browser(driver_addr, server, "core-crypto").await?;

        let _ = browser
            .execute_async(
                r#"
const [clientConfig, callback] = arguments;
const { CoreCrypto, Ciphersuite, CredentialType } = await import("./corecrypto.js");
window.CoreCrypto = CoreCrypto;
window.cc = await window.CoreCrypto.init(clientConfig);
window.ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
window.credentialType = CredentialType.Basic;

window.deliveryService = {
    async sendCommitBundle() {
        return "success";
    },
    async sendMessage() {
        return "success";
    },
};

await window.cc.provideTransport(window.deliveryService);

callback();"#,
                vec![client_config],
            )
            .await?;

        Ok(Self {
            browser,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: Cell::new(0),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedClient for CoreCryptoWebClient {
    fn client_name(&self) -> &str {
        "CoreCrypto::wasm"
    }

    fn client_type(&self) -> EmulatedClientType {
        EmulatedClientType::Web
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_slice()
    }

    fn client_protocol(&self) -> EmulatedClientProtocol {
        EmulatedClientProtocol::MLS | EmulatedClientProtocol::PROTEUS
    }

    async fn wipe(mut self) -> Result<()> {
        let client_id = uuid::Uuid::from_slice(self.client_id.as_slice())?;
        let client_id_str = client_id.as_hyphenated().to_string();
        let database_name = format!("db-{client_id_str}");
        let _ = self
            .browser
            .execute_async(
                r#"
    const [databaseName, callback] = arguments;
    await window.cc.close();
    const result = window.indexedDB.deleteDatabase(databaseName);
    result.onsuccess = callback;
    result.onfailure = callback;"#,
                vec![serde_json::json!(database_name)],
            )
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoWebClient {
    async fn get_keypackage(&self) -> Result<Vec<u8>> {
        let ciphersuite = CIPHERSUITE_IN_USE as u16;
        let start = std::time::Instant::now();
        let kp_raw = self
            .browser
            .execute_async(
                r#"
const [ciphersuite, callback] = arguments;
window.cc.transaction((ctx) =>
    ctx.clientKeypackages(ciphersuite, window.credentialType, 1)
).then(([kp]) => callback(kp));"#,
                vec![serde_json::json!(ciphersuite)],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value::<Vec<u8>>(value)?))?;

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
        self.browser
            .execute_async(
                r#"
const [cId, kp, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const keyPackage = Uint8Array.from(Object.values(kp));
if (!window.cc.conversationExists(conversationId)) {
    await window.cc.transaction((ctx) =>
        ctx.createConversation(conversationId)
    );
}
window.cc.transaction((ctx) =>
    ctx.addClientsToConversation(conversationId, [{ kp: keyPackage }]))
.then(({ welcome }) => callback(welcome));"#,
                vec![conversation_id.into(), kp.into()],
            )
            .await?;
        Ok(())
    }

    async fn kick_client(&self, conversation_id: &[u8], client_id: &[u8]) -> Result<()> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [cId, clId, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const clientId = Uint8Array.from(Object.values(clId));
window.cc.transaction((ctx) =>
    ctx.removeClientsFromConversation(conversationId, [clientId]))
.then(({ commit }) => callback(commit));"#,
                vec![conversation_id.into(), client_id.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn process_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [welcome, callback] = arguments;
const welcomeMessage = Uint8Array.from(Object.values(welcome));
window.cc.transaction((ctx) =>
    ctx.processWelcomeMessage(welcomeMessage))
.then(({ id }) => callback(id));"#,
                vec![welcome.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [cId, cleartext, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const message = Uint8Array.from(Object.values(cleartext));
window.cc.transaction((ctx) =>
    ctx.encryptMessage(conversationId, message))
.then(callback);"#,
                vec![conversation_id.into(), message.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let res = self
            .browser
            .execute_async(
                r#"
const [cId, encMessage, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const encryptedMessage = Uint8Array.from(Object.values(encMessage));
window.cc.transaction((ctx) =>
    ctx.decryptMessage(conversationId, encryptedMessage)
).then(({ message }) => callback(message));"#,
                vec![conversation_id.into(), message.into()],
            )
            .await?;

        if res.is_null() {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_value(res)?))
        }
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoWebClient {
    async fn init(&mut self) -> Result<()> {
        self.browser
            .execute_async(
                r#"
const [callback] = arguments;
window.cc.transaction((ctx) =>
    ctx.proteusInit()
).then(callback);"#,
                vec![],
            )
            .await?;

        Ok(())
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        let prekey_last_id = self.prekey_last_id.get() + 1;
        self.prekey_last_id.replace(prekey_last_id);
        let prekey = self
            .browser
            .execute_async(
                r#"
const [prekeyId, callback] = arguments;
window.cc.transaction((ctx) =>
    ctx.proteusNewPrekey(prekeyId)
).then(callback);"#,
                vec![prekey_last_id.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;

        Ok(prekey)
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        self.browser
            .execute_async(
                r#"
const [sessionId, prekey, callback] = arguments;
const prekeyBuffer = Uint8Array.from(Object.values(prekey));
window.cc.transaction((ctx) =>
    ctx.proteusSessionFromPrekey(sessionId, prekeyBuffer)
).then(callback);"#,
                vec![session_id.into(), prekey.into()],
            )
            .await?;
        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let cleartext = self
            .browser
            .execute_async(
                r#"
const [sessionId, message, callback] = arguments;
const messageBuffer = Uint8Array.from(Object.values(message));
window.cc.transaction((ctx) =>
    ctx.proteusSessionFromMessage(sessionId, messageBuffer)
).then(callback);"#,
                vec![session_id.into(), message.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;

        Ok(cleartext)
    }
    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = self
            .browser
            .execute_async(
                r#"
const [sessionId, plaintext, callback] = arguments;
const plaintextBuffer = Uint8Array.from(Object.values(plaintext));
window.cc.transaction((ctx) =>
    ctx.proteusEncrypt(sessionId, plaintextBuffer)
).then(callback);"#,
                vec![session_id.into(), plaintext.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;

        Ok(ciphertext)
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cleartext = self
            .browser
            .execute_async(
                r#"
const [sessionId, ciphertext, callback] = arguments;
const ciphertextBuffer = Uint8Array.from(Object.values(ciphertext));
window.cc.transaction((ctx) =>
    ctx.proteusDecrypt(sessionId, ciphertextBuffer)
).then(callback);"#,
                vec![session_id.into(), ciphertext.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;

        Ok(cleartext)
    }

    async fn fingerprint(&self) -> Result<String> {
        Ok(self
            .browser
            .execute_async(
                "const [callback] = arguments; window.cc.proteusFingerprint().then(callback);",
                vec![],
            )
            .await?
            .as_str()
            .unwrap()
            .into())
    }
}
