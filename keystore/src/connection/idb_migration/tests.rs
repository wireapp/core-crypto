//! The legacy IndexedDB import, exercised end to end.
//!
//! Nothing else runs [`maybe_migrate`]: the legacy module's own tests stop at the final IndexedDB version, and
//! every other test of the new connection starts from an empty database. This is the only place the two halves
//! meet, and so the only place which can notice that an importer writes a shape the target schema does not have.

use std::{cell::RefCell, rc::Rc, sync::Arc};

use idb::{Factory, TransactionMode};
use js_sys::{Array, Object, Reflect, Uint8Array};
use openmls::prelude::{Credential as MlsCredential, TlsSerializeTrait as _};
use rand::distr::{Alphanumeric, SampleString as _};
use rusqlite::Connection;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;
use x509_cert::der::{Decode as _, DecodePem as _, Encode as _};

use super::*;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusIdentity;
use crate::{
    CryptoKeystoreResult, Sha256Hash,
    ancillary::ConversationIdRef,
    connection::{
        Database,
        idb_migration::legacy::connection::{
            Database as LegacyDatabase, KeystoreDatabaseConnection,
            platform::wasm::migrations::{TARGET_VERSION, open_at},
            storage::{WasmEncryptedStorage, WasmStorageWrapper},
        },
        os_unknown,
    },
    entities::{
        ConsumerData, MlsPendingMessage, PersistedMlsGroup, StoredCredential, StoredCredentialPk,
        StoredEpochEncryptionKeypair, StoredEpochEncryptionKeypairPkRef, StoredKeyPackage, X509Crl,
        X509IntermediateCert, X509TrustAnchor,
    },
    traits::FetchFromDatabase as _,
};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// The row seeded into each legacy object store.
///
/// The values are deliberately distinct per entity so that a row which lands in the wrong table, or under the
/// wrong key, cannot pass for the right one. Where a later migration parses a value, the value is real: the
/// credential deserializes as an MLS credential, the trust anchor as a DER certificate, and the epoch keypair
/// id as the `(conversation_id, own_leaf_index, epoch)` tuple V34 splits it into. Group state is opaque bytes,
/// since the keystore has no crypto provider with which to build an actual group; see [`seed::GROUP_STATE`].
mod seed {
    pub(super) const CONSUMER_DATA: &[u8] = b"consumer data kept across the import";

    /// A self-signed Ed25519 root, so that V28 can parse it and fingerprint its public key.
    pub(super) const TRUST_ANCHOR_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBgzCCATWgAwIBAgIUeN2a19U9hEAnnXPaKGG8/IBnN3EwBQYDK2VwMDcxFTAT
BgNVBAMMDFRlc3QgUm9vdCBDQTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYT
AlVTMB4XDTI2MDgwNjEyNDI0MFoXDTM2MDgwMzEyNDI0MFowNzEVMBMGA1UEAwwM
VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCVVMwKjAF
BgMrZXADIQCcdQkyHFLytpptb0OsLfDq2GhNmIf2EYRih5jeT1SKvaNTMFEwHQYD
VR0OBBYEFIHxxlwJp4caZR40MyYvQHFuKKdWMB8GA1UdIwQYMBaAFIHxxlwJp4ca
ZR40MyYvQHFuKKdWMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA5Ssdm0IaTfSc
lQjd5t/n3C5DLK70tXC7x6Qpdhn57cNqtjxVQnL7R7yr8ZHCps1+XuZgpaEbVx//
r9IJmL6kDQ==
-----END CERTIFICATE-----
";
    pub(super) const CRL_DISTRIBUTION_POINT: &str = "https://example.com/crl";
    pub(super) const CRL: &[u8] = b"a DER certificate list";
    pub(super) const INTERMEDIATE_SKI_AKI: &str = "ski+aki";
    pub(super) const INTERMEDIATE_CERT: &[u8] = b"a DER intermediate certificate";

    pub(super) const GROUP_ID: &[u8] = b"an established conversation";
    /// Opaque, not a real `MlsGroup`. The import copies it verbatim, which is all this test asserts of it.
    ///
    /// V39 deserializes group state and drops rows it cannot read, so the group family is checked at the V22
    /// checkpoint only, never through the fully migrated database.
    pub(super) const GROUP_STATE: &[u8] = b"serialized state of the established conversation";
    pub(super) const GROUP_PARENT_ID: &[u8] = b"parent of the established conversation";
    pub(super) const BUFFERED_COMMIT: &[u8] = b"a commit buffered for the established conversation";

    pub(super) const PENDING_GROUP_ID: &[u8] = b"a conversation joined by external commit";
    pub(super) const PENDING_GROUP_STATE: &[u8] = b"serialized state of the pending conversation";
    pub(super) const PENDING_GROUP_CFG: &[u8] = b"custom configuration of the pending conversation";
    pub(super) const PENDING_MESSAGE: &[u8] = b"a message which arrived before the pending join was merged";

    pub(super) const CREDENTIAL_SESSION_ID: &[u8] = b"session id of the credential";
    pub(super) const CREDENTIAL_PUBLIC_KEY: &[u8] = b"public key of the credential";
    pub(super) const CREDENTIAL_PRIVATE_KEY: &[u8] = b"private key of the credential";
    pub(super) const CREDENTIAL_CREATED_AT: u64 = 1_700_000_000;
    pub(super) const CREDENTIAL_CIPHERSUITE: u16 = 1;

    pub(super) const ENCRYPTION_PK: &[u8] = b"public half of an encryption keypair";
    pub(super) const ENCRYPTION_SK: &[u8] = b"secret half of an encryption keypair";
    pub(super) const HPKE_PK: &[u8] = b"public half of an hpke keypair";
    pub(super) const HPKE_SK: &[u8] = b"secret half of an hpke keypair";
    pub(super) const PSK_ID: &[u8] = b"id of a pre-shared key";
    pub(super) const PSK: &[u8] = b"a pre-shared key";
    pub(super) const KEY_PACKAGE_REF: &[u8] = b"hash reference of a key package";
    pub(super) const KEY_PACKAGE: &[u8] = b"a serialized key package";

    pub(super) const EPOCH_KEYPAIR_OWN_LEAF_INDEX: u32 = 3;
    pub(super) const EPOCH_KEYPAIR_EPOCH: u64 = 7;
    pub(super) const EPOCH_KEYPAIRS: &[u8] = b"serialized epoch encryption keypairs";

    pub(super) const PROTEUS_IDENTITY_SK: [u8; 64] = [0x51; 64];
    pub(super) const PROTEUS_IDENTITY_PK: [u8; 32] = [0x5b; 32];
    pub(super) const PROTEUS_PREKEY_ID: u16 = 42;
    pub(super) const PROTEUS_PREKEY: &[u8] = b"a proteus prekey";
    pub(super) const PROTEUS_SESSION_ID: &str = "proteus session id";
    pub(super) const PROTEUS_SESSION: &[u8] = b"a serialized proteus session";
}

fn trust_anchor_der() -> Vec<u8> {
    x509_cert::Certificate::from_pem(seed::TRUST_ANCHOR_PEM)
        .expect("the seed certificate is valid PEM")
        .to_der()
        .expect("a parsed certificate re-encodes")
}

fn basic_credential() -> Vec<u8> {
    MlsCredential::new_basic(seed::CREDENTIAL_SESSION_ID.to_vec())
        .tls_serialize_detached()
        .expect("a basic credential serializes")
}

fn basic_credential_type() -> u16 {
    MlsCredential::new_basic(Vec::new()).credential_type().into()
}

/// The pre-V34 primary key of an epoch keypair: conversation id, then own leaf index, then epoch, both big-endian.
fn epoch_keypair_id() -> Vec<u8> {
    let mut id = seed::GROUP_ID.to_vec();
    id.extend_from_slice(&seed::EPOCH_KEYPAIR_OWN_LEAF_INDEX.to_be_bytes());
    id.extend_from_slice(&seed::EPOCH_KEYPAIR_EPOCH.to_be_bytes());
    id
}

/// A legacy entity, populated with its row from [`seed`].
///
/// Every entity in `for_each_imported_legacy_entity!` must implement this, or [`seed_every_imported_entity`]
/// does not compile. That is the point: an entity the import copies but this test does not seed is an entity
/// whose import is untested.
trait Seed {
    fn seed() -> Self;
}

impl Seed for LegacyConsumerData {
    fn seed() -> Self {
        Self {
            content: seed::CONSUMER_DATA.to_vec(),
        }
    }
}

impl Seed for E2eiAcmeCA {
    fn seed() -> Self {
        Self {
            content: trust_anchor_der(),
        }
    }
}

impl Seed for E2eiCrl {
    fn seed() -> Self {
        Self {
            distribution_point: seed::CRL_DISTRIBUTION_POINT.to_owned(),
            content: seed::CRL.to_vec(),
        }
    }
}

impl Seed for E2eiIntermediateCert {
    fn seed() -> Self {
        Self {
            ski_aki_pair: seed::INTERMEDIATE_SKI_AKI.to_owned(),
            content: seed::INTERMEDIATE_CERT.to_vec(),
        }
    }
}

impl Seed for LegacyMlsPendingMessage {
    fn seed() -> Self {
        Self {
            conversation_id: seed::PENDING_GROUP_ID.to_vec(),
            message: seed::PENDING_MESSAGE.to_vec(),
        }
    }
}

impl Seed for LegacyPersistedMlsGroup {
    fn seed() -> Self {
        Self {
            id: seed::GROUP_ID.to_vec(),
            state: seed::GROUP_STATE.to_vec(),
            parent_id: Some(seed::GROUP_PARENT_ID.to_vec()),
        }
    }
}

impl Seed for StoredBufferedCommit {
    fn seed() -> Self {
        Self::new(seed::GROUP_ID.to_vec(), seed::BUFFERED_COMMIT.to_vec())
    }
}

impl Seed for StoredCredentialV36 {
    fn seed() -> Self {
        Self {
            public_key: seed::CREDENTIAL_PUBLIC_KEY.to_vec(),
            session_id: seed::CREDENTIAL_SESSION_ID.to_vec(),
            credential: basic_credential(),
            created_at: seed::CREDENTIAL_CREATED_AT,
            ciphersuite: seed::CREDENTIAL_CIPHERSUITE,
            private_key: seed::CREDENTIAL_PRIVATE_KEY.to_vec(),
        }
    }
}

impl Seed for StoredEncryptionKeyPair {
    fn seed() -> Self {
        Self {
            pk: seed::ENCRYPTION_PK.to_vec(),
            sk: seed::ENCRYPTION_SK.to_vec(),
        }
    }
}

impl Seed for V33StoredEpochEncryptionKeypair {
    fn seed() -> Self {
        Self {
            id: epoch_keypair_id(),
            keypairs: seed::EPOCH_KEYPAIRS.to_vec(),
        }
    }
}

impl Seed for StoredHpkePrivateKey {
    fn seed() -> Self {
        Self {
            pk: seed::HPKE_PK.to_vec(),
            sk: seed::HPKE_SK.to_vec(),
        }
    }
}

impl Seed for StoredKeypackage {
    fn seed() -> Self {
        Self {
            keypackage_ref: seed::KEY_PACKAGE_REF.to_vec(),
            keypackage: seed::KEY_PACKAGE.to_vec(),
        }
    }
}

impl Seed for StoredPskBundle {
    fn seed() -> Self {
        Self {
            psk_id: seed::PSK_ID.to_vec(),
            psk: seed::PSK.to_vec(),
        }
    }
}

#[cfg(feature = "proteus-keystore")]
impl Seed for LegacyProteusIdentity {
    fn seed() -> Self {
        Self {
            sk: seed::PROTEUS_IDENTITY_SK.to_vec(),
            pk: seed::PROTEUS_IDENTITY_PK.to_vec(),
        }
    }
}

#[cfg(feature = "proteus-keystore")]
impl Seed for ProteusPrekey {
    fn seed() -> Self {
        Self::from_raw(seed::PROTEUS_PREKEY_ID, seed::PROTEUS_PREKEY.to_vec())
    }
}

#[cfg(feature = "proteus-keystore")]
impl Seed for ProteusSession {
    fn seed() -> Self {
        Self {
            id: seed::PROTEUS_SESSION_ID.to_owned(),
            session: seed::PROTEUS_SESSION.to_vec(),
        }
    }
}

impl Seed for IdbPersistedMlsPendingGroup {
    fn seed() -> Self {
        Self {
            id: seed::PENDING_GROUP_ID.into(),
            state: seed::PENDING_GROUP_STATE.to_vec(),
            parent_id: None,
            custom_configuration: seed::PENDING_GROUP_CFG.to_vec(),
        }
    }
}

/// Create a legacy IndexedDB database at its final version, holding one row in every object store.
///
/// Rows are written through the legacy entities' own write path, exactly as the last IndexedDB-backed release
/// wrote them, so this covers the import's SQL against the schema it targets. It does not cover drift in the
/// legacy entities' serialized shape: those entities both write and read here, so they agree with themselves
/// by construction. Pinning the shape old clients actually wrote needs a captured fixture.
async fn seed_legacy_database(name: &str, key: &DatabaseKey) {
    let idb = open_at(name, key, TARGET_VERSION).await;
    let conn =
        KeystoreDatabaseConnection::from_inner(WasmEncryptedStorage::new(key, WasmStorageWrapper::Persistent(idb)));

    LegacyDatabase::migration_transaction(conn, async |tx| {
        // The pending group is copied by hand by the import, so it is listed by hand here.
        tx.save(&IdbPersistedMlsPendingGroup::seed()).await?;

        macro_rules! seed_every_imported_entity {
            ($( $(#[$attribute:meta])* $entity:ty ),* $(,)?) => {
                $(
                    $(#[$attribute])*
                    {
                        tx.save(&<$entity as Seed>::seed()).await?;
                    }
                )*
            };
        }
        for_each_imported_legacy_entity!(seed_every_imported_entity);

        Ok(())
    })
    .await
    .expect("seeding the legacy database");
}

/// Assert that every seeded row arrived in the schema the import targets, before any later migration touches it.
///
/// This checkpoint is what the import itself is responsible for, and the only point at which the group family
/// can be checked at all; see [`seed::GROUP_STATE`].
fn assert_imported_at_v22(conn: &Connection) {
    let user_version: i64 = conn.query_one("PRAGMA user_version", [], |row| row.get(0)).unwrap();
    assert_eq!(
        user_version, 22,
        "the import must land at the schema version matching the final IDB version"
    );

    // Every query below expects exactly one row: `query_one` fails on zero rows and on more than one.

    let content: Vec<u8> = conn
        .query_one("SELECT content FROM consumer_data", [], |row| row.get(0))
        .expect("consumer_data holds the imported row");
    assert_eq!(content, seed::CONSUMER_DATA);

    let content: Vec<u8> = conn
        .query_one("SELECT content FROM e2ei_acme_ca", [], |row| row.get(0))
        .expect("e2ei_acme_ca holds the imported row");
    assert_eq!(content, trust_anchor_der());

    let (dp, content): (String, Vec<u8>) = conn
        .query_one("SELECT distribution_point, content FROM e2ei_crls", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("e2ei_crls holds the imported row");
    assert_eq!(dp, seed::CRL_DISTRIBUTION_POINT);
    assert_eq!(content, seed::CRL);

    let (ski_aki, content): (String, Vec<u8>) = conn
        .query_one("SELECT ski_aki_pair, content FROM e2ei_intermediate_certs", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("e2ei_intermediate_certs holds the imported row");
    assert_eq!(ski_aki, seed::INTERMEDIATE_SKI_AKI);
    assert_eq!(content, seed::INTERMEDIATE_CERT);

    // V22 predates V31, so the conversation id is still in the column named `id`
    let (id, message): (Vec<u8>, Vec<u8>) = conn
        .query_one("SELECT id, message FROM mls_pending_messages", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("mls_pending_messages holds the imported row");
    assert_eq!(id, seed::PENDING_GROUP_ID);
    assert_eq!(message, seed::PENDING_MESSAGE);

    let (id, state, parent_id): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = conn
        .query_one("SELECT id, state, parent_id FROM mls_groups", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("mls_groups holds the imported row");
    assert_eq!(id, seed::GROUP_ID);
    assert_eq!(state, seed::GROUP_STATE);
    assert_eq!(parent_id.as_deref(), Some(seed::GROUP_PARENT_ID));

    let (id, state): (Vec<u8>, Vec<u8>) = conn
        .query_one("SELECT id, state FROM mls_pending_groups", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("mls_pending_groups holds the imported row");
    assert_eq!(id, seed::PENDING_GROUP_ID);
    assert_eq!(state, seed::PENDING_GROUP_STATE);

    let (id, commit): (Vec<u8>, Vec<u8>) = conn
        .query_one(
            "SELECT conversation_id, commit_data FROM mls_buffered_commits",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("mls_buffered_commits holds the imported row");
    assert_eq!(id, seed::GROUP_ID);
    assert_eq!(commit, seed::BUFFERED_COMMIT);

    let (hash, public_key, session_id, credential, created_at, ciphersuite, private_key): (
        Sha256Hash,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        u64,
        u16,
        Vec<u8>,
    ) = conn
        .query_one(
            "SELECT public_key_sha256, public_key, session_id, credential, unixepoch(created_at), ciphersuite, \
             private_key FROM mls_credentials",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .expect("mls_credentials holds the imported row");
    assert_eq!(hash, Sha256Hash::hash_from(seed::CREDENTIAL_PUBLIC_KEY));
    assert_eq!(public_key, seed::CREDENTIAL_PUBLIC_KEY);
    assert_eq!(session_id, seed::CREDENTIAL_SESSION_ID);
    assert_eq!(credential, basic_credential());
    assert_eq!(created_at, seed::CREDENTIAL_CREATED_AT);
    assert_eq!(ciphersuite, seed::CREDENTIAL_CIPHERSUITE);
    assert_eq!(private_key, seed::CREDENTIAL_PRIVATE_KEY);

    for (table, pk, sk) in [
        ("mls_encryption_keypairs", seed::ENCRYPTION_PK, seed::ENCRYPTION_SK),
        ("mls_hpke_private_keys", seed::HPKE_PK, seed::HPKE_SK),
    ] {
        let (hash, stored_pk, stored_sk): (Sha256Hash, Vec<u8>, Vec<u8>) = conn
            .query_one(&format!("SELECT pk_sha256, pk, sk FROM {table}"), [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap_or_else(|err| panic!("{table} holds the imported row: {err}"));
        assert_eq!(hash, Sha256Hash::hash_from(pk), "{table}");
        assert_eq!(stored_pk, pk, "{table}");
        assert_eq!(stored_sk, sk, "{table}");
    }

    let (hash, psk_id, psk): (Sha256Hash, Vec<u8>, Vec<u8>) = conn
        .query_one("SELECT id_sha256, psk_id, psk FROM mls_psk_bundles", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("mls_psk_bundles holds the imported row");
    assert_eq!(hash, Sha256Hash::hash_from(seed::PSK_ID));
    assert_eq!(psk_id, seed::PSK_ID);
    assert_eq!(psk, seed::PSK);

    // V22 predates the V26 spelling change
    let (key_package_ref, key_package): (Vec<u8>, Vec<u8>) = conn
        .query_one("SELECT keypackage_ref, keypackage FROM mls_keypackages", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("mls_keypackages holds the imported row");
    assert_eq!(key_package_ref, seed::KEY_PACKAGE_REF);
    assert_eq!(key_package, seed::KEY_PACKAGE);

    // V22 predates V34, so the composite key is still packed into `id`
    let (id, keypairs): (Vec<u8>, Vec<u8>) = conn
        .query_one("SELECT id, keypairs FROM mls_epoch_encryption_keypairs", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("mls_epoch_encryption_keypairs holds the imported row");
    assert_eq!(id, epoch_keypair_id());
    assert_eq!(keypairs, seed::EPOCH_KEYPAIRS);

    #[cfg(feature = "proteus-keystore")]
    {
        let (sk, pk): (Vec<u8>, Vec<u8>) = conn
            .query_one("SELECT sk, pk FROM proteus_identities", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("proteus_identities holds the imported row");
        assert_eq!(sk, seed::PROTEUS_IDENTITY_SK);
        assert_eq!(pk, seed::PROTEUS_IDENTITY_PK);

        let (id, prekey): (u16, Vec<u8>) = conn
            .query_one("SELECT id, key FROM proteus_prekeys", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("proteus_prekeys holds the imported row");
        assert_eq!(id, seed::PROTEUS_PREKEY_ID);
        assert_eq!(prekey, seed::PROTEUS_PREKEY);

        let (id, session): (String, Vec<u8>) = conn
            .query_one("SELECT id, session FROM proteus_sessions", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("proteus_sessions holds the imported row");
        assert_eq!(id, seed::PROTEUS_SESSION_ID);
        assert_eq!(session, seed::PROTEUS_SESSION);
    }
}

/// Assert that the imported rows are reachable through the fully migrated database's own API.
///
/// The V22 checkpoint proves the import wrote what it should; this proves what it wrote is what the rest of
/// the crate expects to find, after every migration between V22 and the present has had its say.
async fn assert_imported_and_migrated(db: &Database, credential_created_at: u64) {
    let consumer_data = db
        .get_unique::<ConsumerData>()
        .await
        .unwrap()
        .expect("consumer data survives the import");
    assert_eq!(consumer_data.content, seed::CONSUMER_DATA);

    let trust_anchors = db.load_all::<X509TrustAnchor>().await.unwrap();
    assert_eq!(trust_anchors.len(), 1, "the acme ca becomes the one trust anchor");
    assert_eq!(trust_anchors[0].content, trust_anchor_der());

    let crl = db
        .get_borrowed::<X509Crl>(seed::CRL_DISTRIBUTION_POINT)
        .await
        .unwrap()
        .expect("the crl survives the import");
    assert_eq!(crl.content, seed::CRL);

    let intermediate = db
        .get_borrowed::<X509IntermediateCert>(seed::INTERMEDIATE_SKI_AKI)
        .await
        .unwrap()
        .expect("the intermediate certificate survives the import");
    assert_eq!(intermediate.content, seed::INTERMEDIATE_CERT);

    let pending_messages = db
        .search::<MlsPendingMessage, _>(ConversationIdRef::new(seed::PENDING_GROUP_ID))
        .await
        .unwrap();
    assert_eq!(pending_messages.len(), 1, "the pending message survives the import");
    assert_eq!(pending_messages[0].message, seed::PENDING_MESSAGE);

    let credential = db
        .get::<StoredCredential>(&StoredCredentialPk::new(
            Sha256Hash::hash_from(seed::CREDENTIAL_PUBLIC_KEY),
            basic_credential_type(),
        ))
        .await
        .unwrap()
        .expect("the credential survives the import and is reachable by its post-V37 key");
    assert_eq!(credential.session_id, seed::CREDENTIAL_SESSION_ID);
    assert_eq!(credential.credential, basic_credential());
    assert_eq!(credential.created_at, credential_created_at);
    assert_eq!(credential.ciphersuite, seed::CREDENTIAL_CIPHERSUITE);
    assert_eq!(credential.public_key, seed::CREDENTIAL_PUBLIC_KEY);
    assert_eq!(credential.private_key, seed::CREDENTIAL_PRIVATE_KEY);

    let encryption_keypair = db
        .get_borrowed::<StoredEncryptionKeyPair>(seed::ENCRYPTION_PK)
        .await
        .unwrap()
        .expect("the encryption keypair survives the import");
    assert_eq!(encryption_keypair.sk, seed::ENCRYPTION_SK);

    let hpke_private_key = db
        .get_borrowed::<StoredHpkePrivateKey>(seed::HPKE_PK)
        .await
        .unwrap()
        .expect("the hpke private key survives the import");
    assert_eq!(hpke_private_key.sk, seed::HPKE_SK);

    let psk_bundle = db
        .get_borrowed::<StoredPskBundle>(seed::PSK_ID)
        .await
        .unwrap()
        .expect("the psk bundle survives the import");
    assert_eq!(psk_bundle.psk, seed::PSK);

    let key_package = db
        .get_borrowed::<StoredKeyPackage>(seed::KEY_PACKAGE_REF)
        .await
        .unwrap()
        .expect("the key package survives the import");
    assert_eq!(key_package.key_package, seed::KEY_PACKAGE);

    let epoch_keypair = db
        .get_borrowed::<StoredEpochEncryptionKeypair>(StoredEpochEncryptionKeypairPkRef::new(
            seed::GROUP_ID,
            seed::EPOCH_KEYPAIR_OWN_LEAF_INDEX,
            seed::EPOCH_KEYPAIR_EPOCH,
        ))
        .await
        .unwrap()
        .expect("the epoch keypair survives the import and V34 splits its key correctly");
    assert_eq!(epoch_keypair.keypairs, seed::EPOCH_KEYPAIRS);

    #[cfg(feature = "proteus-keystore")]
    {
        let identity = db
            .get::<ProteusIdentity>(&())
            .await
            .unwrap()
            .expect("the proteus identity survives the import");
        assert_eq!(identity.sk, seed::PROTEUS_IDENTITY_SK);
        assert_eq!(identity.pk, seed::PROTEUS_IDENTITY_PK);

        let prekey = db
            .get::<ProteusPrekey>(&seed::PROTEUS_PREKEY_ID)
            .await
            .unwrap()
            .expect("the proteus prekey survives the import");
        assert_eq!(prekey.prekey, seed::PROTEUS_PREKEY);

        let session = db
            .get_borrowed::<ProteusSession>(seed::PROTEUS_SESSION_ID)
            .await
            .unwrap()
            .expect("the proteus session survives the import");
        assert_eq!(session.session, seed::PROTEUS_SESSION);
    }
}

/// A legacy IndexedDB database holding one row in every object store is imported in full.
///
/// This follows the production path piece by piece so that the import's own output can be inspected: the
/// connection is opened exactly as `Database::open` opens it, which runs the import, then the V22 schema is
/// checked directly, then the same connection is initialised as `Database::open` would have initialised it,
/// and the result is checked through the public API.
#[wasm_bindgen_test]
async fn imports_every_legacy_entity() {
    let name = format!("corecrypto.{}.test", Alphanumeric.sample_string(&mut rand::rng(), 12));
    let key = DatabaseKey::generate();
    let factory = Factory::new().expect("factory");
    factory.delete(&name).expect("delete request").await.expect("wiping db");

    seed_legacy_database(&name, &key).await;
    assert!(
        legacy_idb_exists(&name).await,
        "the seeded legacy database must exist for this test to mean anything"
    );

    // this is what `Database::open` does first, and it is where the import runs
    let (conn, fs) = os_unknown::open(&name, &key)
        .await
        .expect("opening the new database over an existing legacy database imports it");
    assert_imported_at_v22(&conn);

    // and this is the rest of `Database::open`
    let db = Database::init(conn, Box::new(fs), MigrationTarget::Latest).expect("migrating the imported data");
    assert_imported_and_migrated(&db, seed::CREDENTIAL_CREATED_AT).await;

    assert!(
        !legacy_idb_exists(&name).await,
        "the legacy database must be deleted once its data has been imported"
    );

    db.wipe().await.expect("wiping the new database");
}

/// Opening a second time neither re-imports nor disturbs what the first import produced.
#[wasm_bindgen_test]
async fn a_second_open_after_import_is_a_no_op() {
    let name = format!("corecrypto.{}.test", Alphanumeric.sample_string(&mut rand::rng(), 12));
    let key = DatabaseKey::generate();
    let factory = Factory::new().expect("factory");
    factory.delete(&name).expect("delete request").await.expect("wiping db");

    seed_legacy_database(&name, &key).await;

    let db = Database::open(&name, &key)
        .await
        .expect("the first open imports the legacy database");
    Arc::into_inner(db)
        .expect("no other reference to the database")
        .close()
        .await
        .expect("closing after the import");

    let db = Database::open(&name, &key)
        .await
        .expect("the second open finds an already-migrated database");
    assert_imported_and_migrated(&db, seed::CREDENTIAL_CREATED_AT).await;

    Arc::into_inner(db)
        .expect("no other reference to the database")
        .wipe()
        .await
        .expect("wiping the new database");
}

/// The IndexedDB contents of a keystore written by v9.3.4.
///
/// The v9 series wrote IndexedDB schema version 5, so restoring this exercises the legacy chain's v6 to v11 steps
/// on real rows before the import runs. The keystore was populated through that release's public API, so every row
/// is one a real client could have written; see `fixtures/README.md` and the constants in
/// `fixtures/generate-legacy-idb-v9.3.4.rs`, which [`captured`] mirrors. Bytes are tagged as `{"$u8": "<hex>"}`,
/// since JSON cannot otherwise tell a `Uint8Array` from an array of numbers, and IndexedDB keys of the two kinds do
/// not compare equal.
///
/// This is the only thing which pins what old clients actually wrote: the legacy entities in this crate both
/// write and read, so they always agree with themselves, and [`imports_every_legacy_entity`] cannot notice
/// when their serialized shape drifts away from the data in the field.
const LEGACY_FIXTURE_V9_3_4: &str = include_str!("fixtures/legacy-idb-v9.3.4.json");

/// The IndexedDB contents of a keystore written by v10.1.0, the last release whose wasm keystore wrote IndexedDB.
///
/// Captured by saving the same rows as [`seed`] through that release's public API; see `fixtures/README.md`. It is
/// kept alongside the v9.3.4 capture because the two generations keyed some rows differently, and each capture
/// catches what the other cannot.
const LEGACY_FIXTURE_V10_1_0: &str = include_str!("fixtures/legacy-idb-v10.1.0.json");

/// What the generator put into the captured keystore; these must match `fixtures/generate-legacy-idb-v9.3.4.rs`.
mod captured {
    pub(super) const CLIENT_ID: &[u8] = b"alice-legacy-fixture@wire.com:0a1b2c3d";
    pub(super) const ESTABLISHED_CONVERSATION_ID: &[u8] = b"legacy-fixture-established-conversation";
    pub(super) const PENDING_CONVERSATION_ID: &[u8] = b"legacy-fixture-pending-conversation";
    pub(super) const CIPHERSUITE: u16 = 1;
    pub(super) const PROTEUS_PREKEY_ID: u16 = 7;
    pub(super) const PROTEUS_SESSION_ID: &str = "legacy-fixture-proteus-session-with-bob";
    pub(super) const CONSUMER_DATA: &[u8] = b"consumer data kept across the import";
    pub(super) const CRL_DISTRIBUTION_POINT: &str = "https://example.com/legacy-fixture.crl";
    pub(super) const ROOT_CA_COMMON_NAME: &str = "Legacy Fixture Root CA";
    pub(super) const INTERMEDIATE_CA_COMMON_NAME: &str = "Legacy Fixture Intermediate CA";
}

fn fixture(json: &str) -> serde_json::Value {
    serde_json::from_str(json).expect("the fixture is valid JSON")
}

/// How many rows the capture holds in `store`, for stores whose rows the import must carry across one for one.
fn captured_row_count(json: &str, store: &str) -> usize {
    fixture(json)["stores"][store]
        .as_array()
        .unwrap_or_else(|| panic!("the fixture has a store named {store}"))
        .len()
}

/// Rebuild a JavaScript value from its tagged JSON encoding.
fn fixture_value_to_js(value: &serde_json::Value) -> JsValue {
    match value {
        serde_json::Value::Null => JsValue::NULL,
        serde_json::Value::Bool(b) => JsValue::from_bool(*b),
        serde_json::Value::Number(n) => JsValue::from_f64(n.as_f64().expect("fixture numbers are finite")),
        serde_json::Value::String(s) => JsValue::from_str(s),
        serde_json::Value::Array(items) => items.iter().map(fixture_value_to_js).collect::<Array>().into(),
        serde_json::Value::Object(fields) => {
            if let Some(serde_json::Value::String(hex)) = fields.get("$u8")
                && fields.len() == 1
            {
                let bytes = hex::decode(hex).expect("fixture bytes are hex");
                return Uint8Array::from(bytes.as_slice()).into();
            }
            let object = Object::new();
            for (name, field) in fields {
                Reflect::set(&object, &JsValue::from_str(name), &fixture_value_to_js(field))
                    .expect("setting a property on a fresh object");
            }
            object.into()
        }
    }
}

/// Recreate the captured legacy database under `name`, at the schema version it was captured at, and return its
/// encryption key.
async fn restore_legacy_fixture(name: &str, json: &str) -> DatabaseKey {
    let fixture = fixture(json);
    let key = DatabaseKey::try_from(
        hex::decode(fixture["database_key"].as_str().expect("fixture records its key")).expect("key is hex"),
    )
    .expect("key has the right length");
    let version = fixture["version"].as_u64().expect("fixture records its version") as u32;
    let stores = fixture["stores"].as_object().expect("fixture records its stores");

    // the current legacy builders create the object stores; only the rows come from the capture
    let idb = open_at(name, &key, version).await;
    for (store_name, rows) in stores {
        let rows = rows.as_array().expect("a store is a list of rows");
        if rows.is_empty() {
            continue;
        }
        let transaction = idb
            .transaction(&[store_name.as_str()], TransactionMode::ReadWrite)
            .unwrap_or_else(|err| panic!("the current legacy schema has no object store {store_name}: {err}"));
        let store = transaction.object_store(store_name).unwrap();
        for row in rows {
            let key = fixture_value_to_js(&row["key"]);
            let value = fixture_value_to_js(&row["value"]);
            store
                .put(&value, Some(&key))
                .unwrap()
                .await
                .unwrap_or_else(|err| panic!("restoring a row into {store_name}: {err}"));
        }
        transaction.commit().unwrap().await.unwrap();
    }
    idb.close();

    key
}

/// The common name of a DER certificate, so that a certificate can be recognised without embedding its bytes.
fn certificate_common_name(der: &[u8]) -> String {
    let certificate = x509_cert::Certificate::from_der(der).expect("the stored certificate is DER");
    certificate.tbs_certificate().subject().to_string()
}

/// A database captured from a v9.3.4 client is upgraded through the legacy chain and imported in full.
///
/// [`imports_every_legacy_entity`] proves the import handles what the legacy entities write today. This proves
/// the whole path handles what an old client actually wrote, from IndexedDB schema version 5 through the legacy
/// upgrade steps, the import, and every SQL migration after it. Because the rows are real, the group family can
/// be checked through the fully migrated database here, which the seeded tests cannot do.
#[wasm_bindgen_test]
async fn imports_a_database_captured_from_v9_3_4() {
    let name = format!("corecrypto.{}.test", Alphanumeric.sample_string(&mut rand::rng(), 12));
    let factory = Factory::new().expect("factory");
    factory.delete(&name).expect("delete request").await.expect("wiping db");

    let key = restore_legacy_fixture(&name, LEGACY_FIXTURE_V9_3_4).await;
    assert!(
        legacy_idb_exists(&name).await,
        "the restored legacy database must exist for this test to mean anything"
    );

    let db = Database::open(&name, &key)
        .await
        .expect("opening the new database over the captured legacy database upgrades and imports it");

    // the credential and its keypair, merged by the v6 step and given a ciphersuite by the v7 step
    let credentials = db.load_all::<StoredCredential>().await.unwrap();
    assert_eq!(
        credentials.len(),
        1,
        "the one credential survives the v6 and v7 credential steps"
    );
    let credential = &credentials[0];
    assert_eq!(credential.session_id, captured::CLIENT_ID);
    assert_eq!(credential.ciphersuite, captured::CIPHERSUITE);
    assert_eq!(credential.credential_type, basic_credential_type());
    assert!(
        !credential.private_key.is_empty(),
        "the private key comes from the merged signature keypair"
    );

    // the established conversation, with its columns backfilled from real state by V39
    let established = db
        .get_borrowed::<PersistedMlsGroup>(ConversationIdRef::new(captured::ESTABLISHED_CONVERSATION_ID))
        .await
        .unwrap()
        .expect("the established conversation survives every migration");
    assert!(!established.is_pending);
    assert!(established.epoch >= 1, "adding a member advanced the epoch");
    assert_eq!(established.ciphersuite, captured::CIPHERSUITE);
    assert_eq!(established.credential_id, Sha256Hash::hash_from(&credential.public_key));
    assert_eq!(established.credential_type, credential.credential_type);

    // the conversation being joined by external commit, which V39 keeps so that the join can be recovered
    let pending = db
        .get_borrowed::<PersistedMlsGroup>(ConversationIdRef::new(captured::PENDING_CONVERSATION_ID))
        .await
        .unwrap()
        .expect("the pending external join survives every migration");
    assert!(pending.is_pending);
    assert_eq!(pending.credential_id, Sha256Hash::hash_from(&credential.public_key));

    let pending_messages = db
        .search::<MlsPendingMessage, _>(ConversationIdRef::new(captured::PENDING_CONVERSATION_ID))
        .await
        .unwrap();
    assert_eq!(
        pending_messages.len(),
        1,
        "the message buffered for the pending join survives"
    );

    // keying material, copied one for one
    let epoch_keypairs = db.load_all::<StoredEpochEncryptionKeypair>().await.unwrap();
    assert_eq!(
        epoch_keypairs.len(),
        captured_row_count(LEGACY_FIXTURE_V9_3_4, "mls_epoch_encryption_keypairs")
    );
    // the client generated epoch keypairs both for the conversation it created and for the one it is joining
    assert!(
        epoch_keypairs.iter().all(|keypair| {
            [captured::ESTABLISHED_CONVERSATION_ID, captured::PENDING_CONVERSATION_ID]
                .contains(&keypair.conversation_id.bytes())
        }),
        "V34 splits each epoch keypair's key into the conversation it belongs to"
    );
    assert!(
        epoch_keypairs
            .iter()
            .any(|keypair| keypair.conversation_id.bytes() == captured::ESTABLISHED_CONVERSATION_ID),
        "the established conversation has an epoch keypair"
    );
    assert_eq!(
        db.count::<StoredEncryptionKeyPair>().await.unwrap() as usize,
        captured_row_count(LEGACY_FIXTURE_V9_3_4, "mls_encryption_keypairs")
    );
    assert_eq!(
        db.count::<StoredHpkePrivateKey>().await.unwrap() as usize,
        captured_row_count(LEGACY_FIXTURE_V9_3_4, "mls_hpke_private_keys")
    );
    assert_eq!(
        db.count::<StoredKeyPackage>().await.unwrap() as usize,
        captured_row_count(LEGACY_FIXTURE_V9_3_4, "mls_keypackages")
    );

    // the PKI environment
    let trust_anchors = db.load_all::<X509TrustAnchor>().await.unwrap();
    assert_eq!(trust_anchors.len(), 1);
    assert!(certificate_common_name(&trust_anchors[0].content).contains(captured::ROOT_CA_COMMON_NAME));
    let intermediates = db.load_all::<X509IntermediateCert>().await.unwrap();
    assert_eq!(intermediates.len(), 1);
    assert!(certificate_common_name(&intermediates[0].content).contains(captured::INTERMEDIATE_CA_COMMON_NAME));
    let crl = db
        .get_borrowed::<X509Crl>(captured::CRL_DISTRIBUTION_POINT)
        .await
        .unwrap()
        .expect("the crl survives the import");
    x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(&crl.content)
        .expect("the stored crl is DER");

    let consumer_data = db
        .get_unique::<ConsumerData>()
        .await
        .unwrap()
        .expect("consumer data survives the import");
    assert_eq!(consumer_data.content, captured::CONSUMER_DATA);

    #[cfg(feature = "proteus-keystore")]
    {
        db.get::<ProteusIdentity>(&())
            .await
            .unwrap()
            .expect("the proteus identity survives the import");
        assert_eq!(
            db.count::<ProteusPrekey>().await.unwrap() as usize,
            captured_row_count(LEGACY_FIXTURE_V9_3_4, "proteus_prekeys")
        );
        db.get::<ProteusPrekey>(&captured::PROTEUS_PREKEY_ID)
            .await
            .unwrap()
            .expect("the proteus prekey survives the import");
        db.get_borrowed::<ProteusSession>(captured::PROTEUS_SESSION_ID)
            .await
            .unwrap()
            .expect("the proteus session survives the import");
    }

    assert!(
        !legacy_idb_exists(&name).await,
        "the legacy database must be deleted once its data has been imported"
    );

    Arc::into_inner(db)
        .expect("no other reference to the database")
        .wipe()
        .await
        .expect("wiping the new database");
}

/// A database captured from v10.1.0, the last IndexedDB-writing release, is imported in full.
///
/// Its rows are the ones [`seed`] describes, so the shared assertions apply; the credential's `created_at` is
/// read from the capture because that release stamped it at save time.
#[wasm_bindgen_test]
async fn imports_a_database_captured_from_v10_1_0() {
    let name = format!("corecrypto.{}.test", Alphanumeric.sample_string(&mut rand::rng(), 12));
    let factory = Factory::new().expect("factory");
    factory.delete(&name).expect("delete request").await.expect("wiping db");

    let key = restore_legacy_fixture(&name, LEGACY_FIXTURE_V10_1_0).await;
    let credential_created_at = fixture(LEGACY_FIXTURE_V10_1_0)["stores"]["mls_credentials"][0]["value"]["created_at"]
        .as_u64()
        .expect("the captured credential carries its creation time in the clear");

    let db = Database::open(&name, &key)
        .await
        .expect("opening the new database over the captured legacy database imports it");
    assert_imported_and_migrated(&db, credential_created_at).await;

    assert!(
        !legacy_idb_exists(&name).await,
        "the legacy database must be deleted once its data has been imported"
    );

    Arc::into_inner(db)
        .expect("no other reference to the database")
        .wipe()
        .await
        .expect("wiping the new database");
}

/// The key under which [`plant_corrupt_pending_message`] stores its row.
const CORRUPT_ROW_KEY: &[u8] = b"a row the import cannot read";

/// Put a pending message whose ciphertext does not authenticate into an existing legacy database.
///
/// This is the failure a real database can present: the row is well formed, so it is only when the import
/// tries to decrypt it that anything goes wrong. It is written with the raw IndexedDB API rather than through
/// a legacy entity, since the legacy write path cannot produce a row it would not itself accept.
async fn plant_corrupt_pending_message(name: &str) {
    let idb = Factory::new()
        .unwrap()
        .open(name, None)
        .unwrap()
        .await
        .expect("the legacy database exists");
    let transaction = idb
        .transaction(&["mls_pending_messages"], TransactionMode::ReadWrite)
        .unwrap();
    let store = transaction.object_store("mls_pending_messages").unwrap();

    let row = Object::new();
    Reflect::set(
        &row,
        &JsValue::from_str("foreign_id"),
        &Uint8Array::from(seed::PENDING_GROUP_ID).into(),
    )
    .unwrap();
    // long enough to carry a nonce, so that this fails on authentication rather than on length
    Reflect::set(
        &row,
        &JsValue::from_str("message"),
        &Uint8Array::from([0xff; 48].as_slice()).into(),
    )
    .unwrap();

    store
        .put(&row.into(), Some(&Uint8Array::from(CORRUPT_ROW_KEY).into()))
        .unwrap()
        .await
        .expect("planting the corrupt row");
    transaction.commit().unwrap().await.unwrap();
    idb.close();
}

/// Remove the row planted by [`plant_corrupt_pending_message`], as a user or a support tool might.
async fn remove_corrupt_pending_message(name: &str) {
    let idb = Factory::new()
        .unwrap()
        .open(name, None)
        .unwrap()
        .await
        .expect("the legacy database exists");
    let transaction = idb
        .transaction(&["mls_pending_messages"], TransactionMode::ReadWrite)
        .unwrap();
    transaction
        .object_store("mls_pending_messages")
        .unwrap()
        .delete(JsValue::from(Uint8Array::from(CORRUPT_ROW_KEY)))
        .unwrap()
        .await
        .expect("removing the corrupt row");
    transaction.commit().unwrap().await.unwrap();
    idb.close();
}

/// A failed import leaves the legacy database in place and is attempted again on the next open.
///
/// Opening over a legacy database creates the new database and then imports into it. If the import fails
/// partway, what must not happen is for the next open to find the new database, conclude that the import
/// already ran, and hand back an empty keystore while the legacy data sits unread. The import has to be
/// retried until it succeeds, and once the cause of the failure is gone it has to succeed.
#[wasm_bindgen_test]
async fn a_failed_import_is_retried_on_the_next_open() {
    let name = format!("corecrypto.{}.test", Alphanumeric.sample_string(&mut rand::rng(), 12));
    let key = DatabaseKey::generate();
    let factory = Factory::new().expect("factory");
    factory.delete(&name).expect("delete request").await.expect("wiping db");

    seed_legacy_database(&name, &key).await;
    plant_corrupt_pending_message(&name).await;

    let first = Database::open(&name, &key).await;
    assert!(
        first.is_err(),
        "an import which cannot read a row must fail rather than skip it"
    );
    drop(first);
    assert!(
        legacy_idb_exists(&name).await,
        "the legacy database must survive a failed import"
    );

    // nothing has changed, so the import must fail again rather than be skipped
    let second = Database::open(&name, &key).await;
    assert!(
        second.is_err(),
        "a retry must attempt the import again, not open the half-created database as if the import had run"
    );
    drop(second);
    assert!(
        legacy_idb_exists(&name).await,
        "the legacy database must survive a second failed import"
    );

    // with the cause gone, the retry imports everything
    remove_corrupt_pending_message(&name).await;
    let db = Database::open(&name, &key)
        .await
        .expect("once the import can read every row, opening succeeds");
    assert_imported_and_migrated(&db, seed::CREDENTIAL_CREATED_AT).await;
    assert!(
        !legacy_idb_exists(&name).await,
        "the legacy database must be deleted once its data has been imported"
    );

    Arc::into_inner(db)
        .expect("no other reference to the database")
        .wipe()
        .await
        .expect("wiping the new database");
}

/// The IndexedDB database in which the relaxed-idb VFS persists every SQLite database's pages.
///
/// This is the VFS name; relaxed-idb reuses it for its IndexedDB database, and keeps the pages of every file in a
/// single object store named `blocks`.
const VFS_INDEXEDDB_NAME: &str = "core-crypto";

/// Hold a readwrite transaction on the VFS's block store open until released.
///
/// IndexedDB runs readwrite transactions with overlapping scope one at a time, in creation order, so for as long
/// as this one is alive nothing the VFS queues can reach IndexedDB. An idle transaction commits on its own, so
/// this keeps it alive by issuing one request after another until released.
///
/// Returns `{ release, finished }`: a function which lets the transaction end, and a promise for its end.
const HOLD_BLOCK_STORE_JS: &str = r#"(function (name) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction("blocks", "readwrite");
      const store = tx.objectStore("blocks");
      let held = true;
      const spin = () => {
        if (!held) return;
        store.count().onsuccess = spin;
      };
      spin();
      const finished = new Promise((done) => {
        tx.oncomplete = () => { db.close(); done(null); };
        tx.onabort = () => { db.close(); done(null); };
      });
      resolve({ release: () => { held = false; }, finished });
    };
  });
})"#;

const SLEEP_JS: &str = "(ms) => new Promise((resolve) => setTimeout(resolve, ms))";

async fn sleep_ms(ms: u32) {
    let sleep: js_sys::Function = js_sys::eval(SLEEP_JS).unwrap().into();
    let promise: js_sys::Promise = sleep
        .call1(&JsValue::NULL, &JsValue::from_f64(ms.into()))
        .unwrap()
        .into();
    wasm_bindgen_futures::JsFuture::from(promise).await.unwrap();
}

/// A held write transaction on the VFS's block store; see [`HOLD_BLOCK_STORE_JS`].
struct BlockStoreHold {
    release: js_sys::Function,
    finished: js_sys::Promise,
}

impl BlockStoreHold {
    async fn take() -> Self {
        let hold: js_sys::Function = js_sys::eval(HOLD_BLOCK_STORE_JS).unwrap().into();
        let promise: js_sys::Promise = hold
            .call1(&JsValue::NULL, &JsValue::from_str(VFS_INDEXEDDB_NAME))
            .unwrap()
            .into();
        let handle = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .expect("holding the block store");
        Self {
            release: Reflect::get(&handle, &JsValue::from_str("release")).unwrap().into(),
            finished: Reflect::get(&handle, &JsValue::from_str("finished")).unwrap().into(),
        }
    }

    async fn release(self) {
        self.release.call0(&JsValue::NULL).unwrap();
        wasm_bindgen_futures::JsFuture::from(self.finished)
            .await
            .expect("the held transaction ends");
    }
}

/// The legacy database is only deleted once the imported data has reached IndexedDB.
///
/// The VFS is relaxed about durability: a SQLite commit only queues the write of its pages to IndexedDB, and the
/// commit returns before that write lands. The import deletes the legacy database right after its commit. If the
/// page is unloaded in between, the new database has not been persisted and the legacy one is gone, and the user
/// has lost everything. So an open which imports must not finish, and must not delete the legacy database, until
/// the pages it wrote are durable.
///
/// This test makes IndexedDB unable to accept the pages for a while, by holding a write transaction on the VFS's
/// block store, and checks that the open waits. No crash is needed: the window is a matter of ordering, and the
/// hold makes the ordering observable.
#[wasm_bindgen_test]
async fn the_legacy_database_outlives_the_import_until_the_import_is_durable() {
    let name = format!("corecrypto.{}.test", Alphanumeric.sample_string(&mut rand::rng(), 12));
    let key = DatabaseKey::generate();
    let factory = Factory::new().expect("factory");
    factory.delete(&name).expect("delete request").await.expect("wiping db");

    seed_legacy_database(&name, &key).await;
    // make sure the VFS, and so its IndexedDB database, exists before anything is held on it
    Arc::into_inner(
        Database::open(&format!("{name}-warmup"), &key)
            .await
            .expect("installing the vfs"),
    )
    .unwrap()
    .wipe()
    .await
    .expect("wiping the warmup database");

    let hold = BlockStoreHold::take().await;

    // run the open in the background, so that its progress can be observed rather than awaited
    let outcome: Rc<RefCell<Option<CryptoKeystoreResult<Arc<Database>>>>> = Rc::new(RefCell::new(None));
    wasm_bindgen_futures::spawn_local({
        let (name, key, outcome) = (name.clone(), key.clone(), outcome.clone());
        async move {
            let result = Database::open(&name, &key).await;
            *outcome.borrow_mut() = Some(result);
        }
    });

    // long enough that an open which does not wait for durability has certainly finished
    sleep_ms(1_500).await;
    assert!(
        outcome.borrow().is_none(),
        "the open finished while its pages could not have reached IndexedDB, so it did not wait for durability"
    );
    assert!(
        legacy_idb_exists(&name).await,
        "the legacy database must not be deleted before the imported data is durable"
    );

    hold.release().await;
    while outcome.borrow().is_none() {
        sleep_ms(50).await;
    }
    let db = outcome
        .borrow_mut()
        .take()
        .unwrap()
        .expect("once IndexedDB accepts writes again, the open completes");

    assert_imported_and_migrated(&db, seed::CREDENTIAL_CREATED_AT).await;
    assert!(
        !legacy_idb_exists(&name).await,
        "the legacy database is deleted once its data has been imported durably"
    );

    Arc::into_inner(db)
        .expect("no other reference to the database")
        .wipe()
        .await
        .expect("wiping the new database");
}
