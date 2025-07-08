use crate::{
    CIPHERSUITE_IN_USE,
    clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedMlsClient},
};
use color_eyre::eyre::{ContextCompat as _, Result, WrapErr as _, eyre};
use core_crypto::prelude::{KeyPackage, KeyPackageIn};
use std::cell::Cell;
use std::net::SocketAddr;
use tls_codec::Deserialize;
use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator as _};

const MLS_TS: &str = include_str!("mls.ts");
#[cfg(feature = "proteus")]
const PROTEUS_TS: &str = include_str!("proteus.ts");

/// Find and return the body of a function defined in the provided source.
fn js_function_body_from(source: &str, name: &str) -> Result<String> {
    let ts_lang = &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
    let mut parser = Parser::new();
    parser.set_language(ts_lang).expect("loading TS grammar");
    let tree = parser.parse(source, None).context("parsing source")?;

    // this query will produce one match per statement in the function body
    let query = Query::new(
        ts_lang,
        "(function_declaration name: (identifier) @ident body: (statement_block (_) @body))",
    )
    .context("creating query")?;
    let mut cursor = QueryCursor::new();

    let mut output = String::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    // QueryMatches doesn't implement Iterator for Reasons
    while let Some(matched_fn) = matches.next() {
        let [matched_name, body] = matched_fn.captures else {
            unreachable!("our query will always produce exactly 2 captures");
        };

        let matched_name = matched_name
            .node
            .utf8_text(source.as_bytes())
            .expect("source is utf8 by definition as &str");

        if matched_name == name {
            let body = body
                .node
                .utf8_text(source.as_bytes())
                .expect("source is utf8 by definition as &str");

            output.push_str(body);
            output.push('\n');
        }
    }

    Ok(output)
}

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
            "ciphersuites": [ciphersuite],
            "clientId": client_id_str
        });

        let js = js_function_body_from(MLS_TS, "ccNew").context("getting `ccNew` from `mls.ts`")?;
        let browser = crate::build::web::webdriver::setup_browser(driver_addr, server, "core-crypto").await?;
        browser.execute(&js, vec![client_config]).await?;

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

    async fn wipe(&mut self) -> Result<()> {
        let client_id = uuid::Uuid::from_slice(self.client_id.as_slice())?;
        let client_id_str = client_id.as_hyphenated().to_string();
        let database_name = format!("db-{client_id_str}");
        self.browser
            .execute_async(
                r#"
    const [databaseName, callback] = arguments;
    await window.cc.close();
    const result = window.indexedDB.deleteDatabase(databaseName);
    result.onsuccess = callback;
    result.onfailure = callback;
    "#,
                vec![serde_json::json!(database_name)],
            )
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedMlsClient for CoreCryptoWebClient {
    async fn get_keypackage(&self) -> Result<Vec<u8>> {
        let js = js_function_body_from(MLS_TS, "getKeypackage").context("getting `getKeypackage` from `mls.ts`")?;
        let start = std::time::Instant::now();
        let kp_raw = self.browser.execute(&js, vec![]).await?;
        let kp_raw = serde_json::from_value::<Vec<u8>>(kp_raw)?;

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
        let js = js_function_body_from(MLS_TS, "addClient").context("getting `addClient` from `mls.ts`")?;
        self.browser
            .execute(&js, vec![conversation_id.into(), kp.into()])
            .await?;
        Ok(())
    }

    async fn kick_client(&self, conversation_id: &[u8], client_id: &[u8]) -> Result<()> {
        let js = js_function_body_from(MLS_TS, "kickClient").context("getting `kickClient` from `mls.ts`")?;
        self.browser
            .execute(&js, vec![conversation_id.into(), client_id.into()])
            .await?;
        Ok(())
    }

    async fn process_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>> {
        let js = js_function_body_from(MLS_TS, "processWelcome").context("getting `processWelcome` from `mls.ts`")?;
        let welcome = self.browser.execute(&js, vec![welcome.into()]).await?;
        serde_json::from_value(welcome).map_err(Into::into)
    }

    async fn encrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let js = js_function_body_from(MLS_TS, "encryptMessage").context("getting `encryptMessage` from `mls.ts`")?;
        let ciphertext = self
            .browser
            .execute(&js, vec![conversation_id.into(), message.into()])
            .await?;
        serde_json::from_value(ciphertext).map_err(Into::into)
    }

    async fn decrypt_message(&self, conversation_id: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>> {
        let js = js_function_body_from(MLS_TS, "decryptMessage").context("getting `decryptMessage` from `mls.ts`")?;
        let plaintext = self
            .browser
            .execute(&js, vec![conversation_id.into(), message.into()])
            .await?;
        serde_json::from_value(plaintext).map_err(Into::into)
    }
}

#[cfg(feature = "proteus")]
#[async_trait::async_trait(?Send)]
impl crate::clients::EmulatedProteusClient for CoreCryptoWebClient {
    async fn init(&mut self) -> Result<()> {
        let js = js_function_body_from(PROTEUS_TS, "proteusInit").context("getting `proteusInit` from `proteus.ts`")?;
        self.browser.execute(&js, vec![]).await?;

        Ok(())
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        let prekey_last_id = self.prekey_last_id.get() + 1;
        self.prekey_last_id.replace(prekey_last_id);
        let js = js_function_body_from(PROTEUS_TS, "getPrekey").context("getting `getPrekey` from `proteus.ts`")?;
        let prekey = self.browser.execute(&js, vec![prekey_last_id.into()]).await?;
        serde_json::from_value(prekey).map_err(Into::into)
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let js = js_function_body_from(PROTEUS_TS, "sessionFromPrekey")
            .context("getting `sessionFromPrekey` from `proteus.ts`")?;
        self.browser
            .execute(&js, vec![session_id.into(), prekey.into()])
            .await?;
        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let js = js_function_body_from(PROTEUS_TS, "sessionFromMessage")
            .context("getting `sessionFromMessage` from `proteus.ts`")?;
        let cleartext = self
            .browser
            .execute(&js, vec![session_id.into(), message.into()])
            .await?;
        serde_json::from_value(cleartext).map_err(Into::into)
    }

    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let js = js_function_body_from(PROTEUS_TS, "encrypt").context("getting `encrypt` from `proteus.ts`")?;
        let ciphertext = self
            .browser
            .execute(&js, vec![session_id.into(), plaintext.into()])
            .await?;
        serde_json::from_value(ciphertext).map_err(Into::into)
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let js = js_function_body_from(PROTEUS_TS, "decrypt").context("getting `decrypt` from `proteus.ts`")?;
        let cleartext = self
            .browser
            .execute(&js, vec![session_id.into(), ciphertext.into()])
            .await?;
        serde_json::from_value(cleartext).map_err(Into::into)
    }

    async fn fingerprint(&self) -> Result<String> {
        let js = js_function_body_from(PROTEUS_TS, "fingerprint").context("getting `fingerprint` from `proteus.ts`")?;
        self.browser
            .execute(&js, vec![])
            .await?
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or(eyre!("no proteus fingerprint returned"))
    }
}
