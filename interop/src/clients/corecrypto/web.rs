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

use crate::clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient};
use color_eyre::eyre::Result;
use core_crypto::mls::MlsCiphersuite;
use std::net::SocketAddr;

#[derive(Debug)]
pub struct CoreCryptoWebClient {
    browser: fantoccini::Client,
    client_id: Vec<u8>,
    #[cfg(feature = "proteus")]
    prekey_last_id: u16,
}

impl CoreCryptoWebClient {
    pub async fn new(driver_addr: &SocketAddr) -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_str = client_id.as_hyphenated().to_string();
        let client_config = serde_json::json!({
            "databaseName": format!("db-{client_id_str}"),
            "key": "test",
            "clientId": client_id_str
        });
        let browser = crate::build::web::webdriver::setup_browser(driver_addr, "core-crypto").await?;

        let _ = browser
            .execute_async(
                r#"
const [clientConfig, callback] = arguments;
const { CoreCrypto } = await import("./corecrypto.js");
window.CoreCrypto = CoreCrypto;
window.cc = await window.CoreCrypto.init(clientConfig);
callback();"#,
                vec![client_config],
            )
            .await?;

        Ok(Self {
            browser,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: 0,
        })
    }

    #[allow(dead_code)]
    pub async fn new_deferred(driver_addr: &SocketAddr) -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_str = client_id.as_hyphenated().to_string();
        let client_config = serde_json::json!({
            "databaseName": format!("db-{client_id_str}"),
            "key": "test"
        });
        let browser = crate::build::web::webdriver::setup_browser(driver_addr, "core-crypto").await?;

        let _ = browser
            .execute_async(
                r#"
const [clientConfig, callback] = arguments;
const { CoreCrypto } = await import("./corecrypto.js");
window.CoreCrypto = CoreCrypto;
window.cc = await window.CoreCrypto.deferredInit(clientConfig);
callback();"#,
                vec![client_config],
            )
            .await?;

        Ok(Self {
            browser,
            client_id: client_id.into_bytes().into(),
            #[cfg(feature = "proteus")]
            prekey_last_id: 0,
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
        let _ = self
            .browser
            .execute_async(
                r#"
    const [callback] = arguments;
    window.cc.wipe().then(callback);"#,
                vec![],
            )
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoWebClient {
    async fn get_keypackage(&mut self) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [callback] = arguments;
window.cc.clientKeypackages(1).then(([kp]) => callback(kp));"#,
                vec![],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn add_client(&mut self, conversation_id: &[u8], client_id: &[u8], kp: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [cId, clId, kp, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const clientId = Uint8Array.from(Object.values(clId));
const keyPackage = Uint8Array.from(Object.values(kp));
if (!window.cc.conversationExists(conversationId)) {
    await window.cc.createConversation(conversationId);
}
window.cc.addClientsToConversation(conversationId, [{ id: clientId, kp: keyPackage }])
    .then(({ welcome }) => callback(welcome));"#,
                vec![conversation_id.into(), client_id.into(), kp.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn kick_client(&mut self, conversation_id: &[u8], client_id: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [cId, clId, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const clientId = Uint8Array.from(Object.values(clId));
window.cc.removeClientsFromConversation(conversationId, [clientId])
    .then(({ commit }) => callback(commit));"#,
                vec![conversation_id.into(), client_id.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn process_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [welcome, callback] = arguments;
const welcomeMessage = Uint8Array.from(Object.values(welcome));
window.cc.processWelcomeMessage(welcomeMessage)
    .then(callback);"#,
                vec![welcome.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn encrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .browser
            .execute_async(
                r#"
const [cId, cleartext, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const message = Uint8Array.from(Object.values(cleartext));
window.cc.encryptMessage(conversationId, message)
    .then(callback);"#,
                vec![conversation_id.into(), message.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?)
    }

    async fn decrypt_message(&mut self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let res = self
            .browser
            .execute_async(
                r#"
const [cId, encMessage, callback] = arguments;
const conversationId = Uint8Array.from(Object.values(cId));
const encryptedMessage = Uint8Array.from(Object.values(encMessage));
window.cc.decryptMessage(conversationId, encryptedMessage)
    .then(({ message }) => callback(message));"#,
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
window.cc.proteusInit().then(callback);"#,
                vec![],
            )
            .await?;

        Ok(())
    }

    async fn get_prekey(&mut self) -> Result<Vec<u8>> {
        self.prekey_last_id += 1;
        let prekey = self
            .browser
            .execute_async(
                r#"
const [prekeyId, callback] = arguments;
window.cc.proteusNewPrekey(prekeyId).then(callback);"#,
                vec![self.prekey_last_id.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;

        Ok(prekey)
    }

    async fn session_from_prekey(&mut self, session_id: &str, prekey: &[u8]) -> Result<()> {
        self.browser
            .execute_async(
                r#"
const [sessionId, prekey, callback] = arguments;
const prekeyBuffer = Uint8Array.from(Object.values(prekey));
window.cc.proteusSessionFromPrekey(sessionId, prekeyBuffer).then(callback);"#,
                vec![session_id.into(), prekey.into()],
            )
            .await?;
        Ok(())
    }

    async fn session_from_message(&mut self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let cleartext = self
            .browser
            .execute_async(
                r#"
const [sessionId, message, callback] = arguments;
const messageBuffer = Uint8Array.from(Object.values(message));
window.cc.proteusSessionFromMessage(sessionId, messageBuffer).then(callback);"#,
                vec![session_id.into(), message.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;

        Ok(cleartext)
    }
    async fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = self
            .browser
            .execute_async(
                r#"
const [sessionId, plaintext, callback] = arguments;
const plaintextBuffer = Uint8Array.from(Object.values(plaintext));
window.cc.proteusEncrypt(sessionId, plaintextBuffer).then(callback);"#,
                vec![session_id.into(), plaintext.into()],
            )
            .await
            .and_then(|value| Ok(serde_json::from_value(value)?))?;

        Ok(ciphertext)
    }

    async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cleartext = self
            .browser
            .execute_async(
                r#"
const [sessionId, ciphertext, callback] = arguments;
const ciphertextBuffer = Uint8Array.from(Object.values(ciphertext));
window.cc.proteusDecrypt(sessionId, ciphertextBuffer).then(callback);"#,
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

#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedE2eIdentityClient for CoreCryptoWebClient {
    async fn new_acme_enrollment(&mut self, _ciphersuite: MlsCiphersuite) -> Result<()> {
        let script = include_str!("e2ei.js");
        Ok(self.browser.execute_async(script, vec![]).await.map(|_| ())?)
    }
}
