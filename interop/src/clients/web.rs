use std::net::SocketAddr;

use color_eyre::eyre::Result;

#[derive(Debug)]
pub struct WebClient {
    browser: fantoccini::Client,
    client_id: Vec<u8>,
}

impl WebClient {
    pub async fn new(driver_addr: &SocketAddr) -> Result<Self> {
        let client_id = uuid::Uuid::new_v4();
        let client_id_str = client_id.as_hyphenated().to_string();
        let client_config = serde_json::json!({
            "databaseName": format!("db-{client_id_str}"),
            "key": "test",
            "clientId": client_id_str
        });
        let browser = crate::build::web::webdriver::setup_browser(driver_addr).await?;

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
        })
    }
}

#[async_trait::async_trait(?Send)]
impl super::EmulatedClient for WebClient {
    fn client_type(&self) -> super::EmulatedClientType {
        super::EmulatedClientType::Web
    }

    fn client_id(&self) -> &[u8] {
        self.client_id.as_slice()
    }

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
