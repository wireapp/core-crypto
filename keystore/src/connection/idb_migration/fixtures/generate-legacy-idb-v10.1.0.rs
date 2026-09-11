// How `legacy-idb-v10.1.0.json` was produced. Not compiled: this is a wasm-bindgen integration test written against
// the v10.1.0 keystore API, and only builds in a checkout of that tag. See README.md alongside for the procedure.

use core_crypto_keystore::{Database, DatabaseKey, connection::ConnectionType, entities::*};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const DATABASE_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TRUST_ANCHOR_DER_HEX: &str = "3082018330820135a003020102021478dd9ad7d53d8440279d73da2861bcfc80673771300506032b657030373115301306035504030c0c5465737420526f6f742043413111300f060355040a0c0854657374204f7267310b3009060355040613025553301e170d3236303830363132343234305a170d3336303830333132343234305a30373115301306035504030c0c5465737420526f6f742043413111300f060355040a0c0854657374204f7267310b3009060355040613025553302a300506032b65700321009c7509321c52f2b69a6d6f43ac2df0ead8684d9887f61184628798de4f548abda3533051301d0603551d0e0416041481f1c65c09a7871a651e3433262f40716e28a756301f0603551d2304183016801481f1c65c09a7871a651e3433262f40716e28a756300f0603551d130101ff040530030101ff300506032b6570034100e52b1d9b421a4df49c9508dde6dfe7dc2e432caef4b570bbc7a4297619f9edc36ab63c554272fb47bcabf191c2a6cd7e5ee660a5a11b571fffafd20998bea40d";
const BASIC_CREDENTIAL_HEX: &str = "00011c73657373696f6e206964206f66207468652063726564656e7469616c";

const GROUP_ID: &[u8] = b"an established conversation";
const PENDING_GROUP_ID: &[u8] = b"a conversation joined by external commit";

fn epoch_keypair_id() -> Vec<u8> {
    let mut id = GROUP_ID.to_vec();
    id.extend_from_slice(&3u32.to_be_bytes());
    id.extend_from_slice(&7u64.to_be_bytes());
    id
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

#[wasm_bindgen_test]
async fn dump_legacy_fixture() {
    let name = "corecrypto.legacy-fixture.v10_1_0";
    idb::Factory::new().unwrap().delete(name).unwrap().await.unwrap();
    let key = DatabaseKey::try_from(hex::decode(DATABASE_KEY_HEX).unwrap()).unwrap();

    let db = Database::open(ConnectionType::Persistent(name), &key).await.unwrap();
    db.new_transaction().await.unwrap();

    db.save(ConsumerData { content: b"consumer data kept across the import".to_vec() }).await.unwrap();
    db.save(E2eiAcmeCA { content: hex::decode(TRUST_ANCHOR_DER_HEX).unwrap() }).await.unwrap();
    db.save(E2eiCrl {
        distribution_point: "https://example.com/crl".to_owned(),
        content: b"a DER certificate list".to_vec(),
    })
    .await
    .unwrap();
    db.save(E2eiIntermediateCert {
        ski_aki_pair: "ski+aki".to_owned(),
        content: b"a DER intermediate certificate".to_vec(),
    })
    .await
    .unwrap();
    db.save(MlsPendingMessage {
        foreign_id: PENDING_GROUP_ID.to_vec(),
        message: b"a message which arrived before the pending join was merged".to_vec(),
    })
    .await
    .unwrap();
    db.save(PersistedMlsGroup {
        id: GROUP_ID.to_vec(),
        state: b"serialized state of the established conversation".to_vec(),
        parent_id: Some(b"parent of the established conversation".to_vec()),
    })
    .await
    .unwrap();
    db.save(PersistedMlsPendingGroup {
        id: PENDING_GROUP_ID.to_vec(),
        state: b"serialized state of the pending conversation".to_vec(),
        parent_id: None,
        custom_configuration: b"custom configuration of the pending conversation".to_vec(),
    })
    .await
    .unwrap();
    db.save(StoredBufferedCommit::new(
        GROUP_ID.to_vec(),
        b"a commit buffered for the established conversation".to_vec(),
    ))
    .await
    .unwrap();
    db.save(StoredCredential {
        session_id: b"session id of the credential".to_vec(),
        credential: hex::decode(BASIC_CREDENTIAL_HEX).unwrap(),
        created_at: 1_700_000_000,
        ciphersuite: 1,
        public_key: b"public key of the credential".to_vec(),
        private_key: b"private key of the credential".to_vec(),
    })
    .await
    .unwrap();
    db.save(StoredEncryptionKeyPair {
        pk: b"public half of an encryption keypair".to_vec(),
        sk: b"secret half of an encryption keypair".to_vec(),
    })
    .await
    .unwrap();
    db.save(StoredEpochEncryptionKeypair {
        id: epoch_keypair_id(),
        keypairs: b"serialized epoch encryption keypairs".to_vec(),
    })
    .await
    .unwrap();
    db.save(StoredHpkePrivateKey {
        pk: b"public half of an hpke keypair".to_vec(),
        sk: b"secret half of an hpke keypair".to_vec(),
    })
    .await
    .unwrap();
    db.save(StoredKeypackage {
        keypackage_ref: b"hash reference of a key package".to_vec(),
        keypackage: b"a serialized key package".to_vec(),
    })
    .await
    .unwrap();
    db.save(StoredPskBundle {
        psk_id: b"id of a pre-shared key".to_vec(),
        psk: b"a pre-shared key".to_vec(),
    })
    .await
    .unwrap();
    db.save(ProteusIdentity { sk: vec![0x51; 64], pk: vec![0x5b; 32] }).await.unwrap();
    db.save(ProteusPrekey::from_raw(42, b"a proteus prekey".to_vec())).await.unwrap();
    db.save(ProteusSession {
        id: "proteus session id".to_owned(),
        session: b"a serialized proteus session".to_vec(),
    })
    .await
    .unwrap();

    db.commit_transaction().await.unwrap();
    db.close().await.unwrap();

    let dump: js_sys::Function = js_sys::eval(DUMP_JS).unwrap().into();
    let promise: js_sys::Promise = dump.call1(&JsValue::NULL, &JsValue::from_str(name)).unwrap().into();
    let json = JsFuture::from(promise).await.unwrap().as_string().unwrap();
    panic!("FIXTURE_BEGIN\n{{\"generated_by\": \"v10.1.0\", \"database_key\": \"{DATABASE_KEY_HEX}\",{}\nFIXTURE_END", &json[1..]);
}
