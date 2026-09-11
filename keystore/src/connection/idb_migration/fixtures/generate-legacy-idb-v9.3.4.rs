// How `legacy-idb-v9.3.4.json` was produced. Not compiled: this is a wasm-bindgen integration test written against
// the v9.3.4 core-crypto API, and only builds in a checkout of that tag. See README.md alongside for the procedure.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use core_crypto::{
    DatabaseKey, MlsTransportData, MlsTransportResponse, prelude::*, transaction_context::Error as TransactionError,
    transaction_context::TransactionContext,
};
use openmls::prelude::MlsMessageInBody;
use tls_codec::Deserialize as _;
use core_crypto_keystore::{connection::ConnectionType, entities::MlsBufferedCommit};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const NAME: &str = "corecrypto.legacy-fixture.v9_3_4";
const DATABASE_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const ALICE_CLIENT_ID: &str = "alice-legacy-fixture@wire.com:0a1b2c3d";
const BOB_CLIENT_ID: &str = "bob-legacy-fixture@wire.com:9f8e7d6c";
const ESTABLISHED_CONVERSATION_ID: &[u8] = b"legacy-fixture-established-conversation";
const PENDING_CONVERSATION_ID: &[u8] = b"legacy-fixture-pending-conversation";
const BUFFERED_COMMIT: &[u8] = b"a commit buffered for the established conversation";
const PROTEUS_PREKEY_ID: u16 = 7;
const PROTEUS_SESSION_ID: &str = "legacy-fixture-proteus-session-with-bob";
const CONSUMER_DATA: &[u8] = b"consumer data kept across the import";
const CRL_DISTRIBUTION_POINT: &str = "https://example.com/legacy-fixture.crl";

const ROOT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBjzCCAUGgAwIBAgIUTTSOvZWaT1V5dD+BpsKO66MNQe4wBQYDK2VwMDUxHzAd\nBgNVBAMMFkxlZ2FjeSBGaXh0dXJlIFJvb3QgQ0ExEjAQBgNVBAoMCVdpcmUgVGVz\ndDAeFw0yNjA5MTEwODAzMjdaFw0zNjA5MDgwODAzMjdaMDUxHzAdBgNVBAMMFkxl\nZ2FjeSBGaXh0dXJlIFJvb3QgQ0ExEjAQBgNVBAoMCVdpcmUgVGVzdDAqMAUGAytl\ncAMhADxKbOwXVgOmzS0d+iLZnSGsww7r3mc21jNE2S10XZSmo2MwYTAfBgNVHSME\nGDAWgBQxcZm+PcYZBeGnbcBf+4jS1NjeAzAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud\nDwEB/wQEAwIBBjAdBgNVHQ4EFgQUMXGZvj3GGQXhp23AX/uI0tTY3gMwBQYDK2Vw\nA0EAWzblUPUv6Urg4yjVsnZ7ri0ZnbnbXs+/J8OaddwHhlPfZa+GrJegA+ReRd2O\nRfvc9tpgpXpoRDt37oBkHgJCBw==\n-----END CERTIFICATE-----\n";
const INTERMEDIATE_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB1TCCAYegAwIBAgIUd7Cw1vR5PPIjFqVp1e2HdLaKR3wwBQYDK2VwMDUxHzAd\nBgNVBAMMFkxlZ2FjeSBGaXh0dXJlIFJvb3QgQ0ExEjAQBgNVBAoMCVdpcmUgVGVz\ndDAeFw0yNjA5MTEwODAzMjdaFw0zMTA5MTAwODAzMjdaMD0xJzAlBgNVBAMMHkxl\nZ2FjeSBGaXh0dXJlIEludGVybWVkaWF0ZSBDQTESMBAGA1UECgwJV2lyZSBUZXN0\nMCowBQYDK2VwAyEAmJc68WGo153AW2FuWqhX6Q+5zHysEE5ajRqFhjuB6K6jgaAw\ngZ0wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE\nFHzwJPpAfYzv3mi0wUDNRuSJsO6kMB8GA1UdIwQYMBaAFDFxmb49xhkF4adtwF/7\niNLU2N4DMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHBzOi8vZXhhbXBsZS5jb20vbGVn\nYWN5LWZpeHR1cmUuY3JsMAUGAytlcANBAObrpXittWIiHtqv/BG2oamnhqtXQWfG\n0GoHtgLsbW6JtLGKde7UIvPUMpMV8hvOwJgdNFKoatl+xM57eA90yAo=\n-----END CERTIFICATE-----\n";
const CRL_DER_HEX: &str = "3081c33077020101300506032b6570303d3127302506035504030c1e4c6567616379204669787475726520496e7465726d65646961746520434131123010060355040a0c09576972652054657374170d3236303931313038303332375a170d3336303930383038303332375aa00e300c300a0603551d140403020101300506032b657003410027743ad2694f5960f6b8a9b7b13bab8845dfc04dcb6c2abff379bb0655958a0eccd5ce5ea71b2b1c42a3c35da46e3fab731452e0f7567b7bc724fe9c6d593c0e";

/// A transport which accepts everything, remembers the last commit bundle, and can be told to answer `Retry`.
///
/// `Retry` makes `join_by_external_commit` return before merging, leaving the pending group persisted, which is
/// the state a real client is in between sending its external commit and receiving it back.
#[derive(Debug, Default)]
struct Transport {
    retry_commits: AtomicBool,
    latest_commit_bundle: Mutex<Option<MlsCommitBundle>>,
}

#[async_trait::async_trait(?Send)]
impl MlsTransport for Transport {
    async fn send_commit_bundle(&self, commit_bundle: MlsCommitBundle) -> core_crypto::Result<MlsTransportResponse> {
        if self.retry_commits.load(Ordering::SeqCst) {
            return Ok(MlsTransportResponse::Retry);
        }
        *self.latest_commit_bundle.lock().unwrap() = Some(commit_bundle);
        Ok(MlsTransportResponse::Success)
    }

    async fn send_message(&self, _mls_message: Vec<u8>) -> core_crypto::Result<MlsTransportResponse> {
        Ok(MlsTransportResponse::Success)
    }

    async fn prepare_for_transport(&self, _secret: &HistorySecret) -> core_crypto::Result<MlsTransportData> {
        Ok(MlsTransportData(Vec::new()))
    }
}

async fn session(
    location: ConnectionType<'_>,
    key: DatabaseKey,
    client_id: &str,
    ciphersuite: MlsCiphersuite,
) -> (CoreCrypto, TransactionContext, Arc<Transport>) {
    let config = SessionConfig::builder()
        .db_connection_type(location)
        .database_key(key)
        .ciphersuites([ciphersuite])
        .build()
        .validate()
        .unwrap();
    let session = Session::try_new(config).await.unwrap();
    let transport = Arc::new(Transport::default());
    session.provide_transport(transport.clone()).await;
    let cc = CoreCrypto::from(session);
    let tx = cc.new_transaction().await.unwrap();
    tx.mls_init(ClientIdentifier::Basic(ClientId::from(client_id.as_bytes())), vec![ciphersuite], Some(2))
        .await
        .unwrap();
    (cc, tx, transport)
}

const DUMP_JS: &str = r#"(function (name) {
  const enc = (v) => {
    if (v instanceof Uint8Array) return { "$u8": Array.from(v).map((b) => b.toString(16).padStart(2, "0")).join("") };
    if (v instanceof ArrayBuffer) return enc(new Uint8Array(v));
    if (Array.isArray(v)) return v.map(enc);
    if (v === null || typeof v !== "object") return v;
    if (ArrayBuffer.isView(v)) throw new Error("unexpected typed array " + v.constructor.name);
    const o = {};
    for (const k of Object.keys(v)) o[k] = enc(v[k]);
    return o;
  };
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const db = req.result;
      const names = Array.from(db.objectStoreNames).sort();
      const tx = db.transaction(names, "readonly");
      const stores = {};
      let pending = names.length;
      names.forEach((n) => {
        const s = tx.objectStore(n);
        const kr = s.getAllKeys();
        const vr = s.getAll();
        vr.onerror = () => reject(vr.error);
        vr.onsuccess = () => {
          stores[n] = kr.result.map((k, i) => ({ key: enc(k), value: enc(vr.result[i]) }));
          if (--pending === 0) {
            const out = JSON.stringify({ version: db.version, stores }, null, 1);
            db.close();
            resolve(out);
          }
        };
      });
    };
  });
})"#;

const DELETE_JS: &str = r#"(function (name) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(name);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(null);
    req.onblocked = () => reject(new Error("blocked"));
  });
})"#;

async fn call_js(code: &str, name: &str) -> JsValue {
    let function: js_sys::Function = js_sys::eval(code).unwrap().into();
    let promise: js_sys::Promise = function.call1(&JsValue::NULL, &JsValue::from_str(name)).unwrap().into();
    JsFuture::from(promise).await.unwrap()
}

#[wasm_bindgen_test]
async fn dump_legacy_fixture() {
    console_error_panic_hook::set_once();
    call_js(DELETE_JS, NAME).await;

    let ciphersuite = MlsCiphersuite::default();
    let key_bytes: [u8; 32] = hex::decode(DATABASE_KEY_HEX).unwrap().try_into().unwrap();
    let key = DatabaseKey::from(key_bytes);

    let (alice_cc, alice, alice_transport) =
        session(ConnectionType::Persistent(NAME), key, ALICE_CLIENT_ID, ciphersuite).await;
    let (_bob_cc, bob, bob_transport) =
        session(ConnectionType::InMemory, DatabaseKey::generate(), BOB_CLIENT_ID, ciphersuite).await;

    // a PKI environment: trust anchor, one intermediate, one CRL issued by that intermediate
    alice.e2ei_register_acme_ca(ROOT_CA_PEM.to_owned()).await.unwrap();
    alice
        .e2ei_register_intermediate_ca_pem(INTERMEDIATE_CA_PEM.to_owned())
        .await
        .unwrap();
    alice
        .e2ei_register_crl(CRL_DISTRIBUTION_POINT.to_owned(), hex::decode(CRL_DER_HEX).unwrap())
        .await
        .unwrap();

    // an established conversation alice created and added bob to
    let established = ESTABLISHED_CONVERSATION_ID.to_vec();
    let config = MlsConversationConfiguration {
        ciphersuite,
        ..Default::default()
    };
    alice
        .new_conversation(&established, MlsCredentialType::Basic, config.clone())
        .await
        .unwrap();
    let bob_key_packages = bob
        .get_or_create_client_keypackages(ciphersuite, MlsCredentialType::Basic, 1)
        .await
        .unwrap()
        .into_iter()
        .map(KeyPackageIn::from)
        .collect();
    alice
        .conversation(&established)
        .await
        .unwrap()
        .add_members(bob_key_packages)
        .await
        .unwrap();

    // a conversation bob created, which alice is in the middle of joining by external commit
    let pending = PENDING_CONVERSATION_ID.to_vec();
    bob.new_conversation(&pending, MlsCredentialType::Basic, config)
        .await
        .unwrap();
    bob.conversation(&pending).await.unwrap().update_key_material().await.unwrap();
    let GroupInfoPayload::Plaintext(group_info) = bob_transport
        .latest_commit_bundle
        .lock()
        .unwrap()
        .take()
        .expect("bob's update produced a commit bundle")
        .group_info
        .payload;
    let MlsMessageInBody::GroupInfo(group_info) = MlsMessageIn::tls_deserialize(&mut group_info.as_slice())
        .unwrap()
        .extract()
    else {
        panic!("the commit bundle's group info payload is a group info");
    };
    alice_transport.retry_commits.store(true, Ordering::SeqCst);
    alice
        .join_by_external_commit(group_info, MlsCustomConfiguration::default(), MlsCredentialType::Basic)
        .await
        .expect_err("the transport asked for a retry, so the join stays pending");
    alice_transport.retry_commits.store(false, Ordering::SeqCst);

    // a message from bob in that conversation, which alice can only buffer until her join is merged
    let message = bob
        .conversation(&pending)
        .await
        .unwrap()
        .encrypt_message(b"hello alice, from before your join was merged")
        .await
        .unwrap();
    match alice.conversation(&pending).await {
        Err(TransactionError::PendingConversation(mut pending_conversation)) => {
            pending_conversation
                .try_process_own_join_commit(&message)
                .await
                .expect_err("a message which is not our own join commit is buffered");
        }
        other => panic!("expected the pending conversation, got {:?}", other.map(|_| ())),
    }

    // a buffered commit for the established conversation; nothing parses its bytes during migration
    alice
        .mls_provider()
        .await
        .unwrap()
        .keystore()
        .save(MlsBufferedCommit::new(established.clone(), BUFFERED_COMMIT.to_vec()))
        .await
        .unwrap();

    // proteus: identity, a prekey, and a session established from one of bob's prekeys
    alice.proteus_init().await.unwrap();
    bob.proteus_init().await.unwrap();
    let (_bob_prekey_id, bob_prekey) = bob.proteus_new_prekey_auto().await.unwrap();
    alice.proteus_new_prekey(PROTEUS_PREKEY_ID).await.unwrap();
    alice
        .proteus_session_from_prekey(PROTEUS_SESSION_ID, &bob_prekey)
        .await
        .unwrap();

    alice.set_data(CONSUMER_DATA.to_vec()).await.unwrap();

    alice.finish().await.unwrap();
    bob.finish().await.unwrap();
    alice_cc.take().close().await.unwrap();

    let json = call_js(DUMP_JS, NAME).await.as_string().unwrap();
    panic!(
        "FIXTURE_BEGIN\n{{\"generated_by\": \"v9.3.4\", \"database_key\": \"{DATABASE_KEY_HEX}\",{}\nFIXTURE_END",
        &json[1..]
    );
}
