//! The legacy IndexedDB import, exercised end to end.
//!
//! Nothing else runs [`maybe_migrate`]: the legacy module's own tests stop at the final IndexedDB version, and
//! every other test of the new connection starts from an empty database. This is the only place the two halves
//! meet, and so the only place which can notice that an importer writes a shape the target schema does not have.

use std::sync::Arc;

use idb::Factory;
use openmls::prelude::{Credential as MlsCredential, TlsSerializeTrait as _};
use rand::distr::{Alphanumeric, SampleString as _};
use rusqlite::Connection;
use wasm_bindgen_test::wasm_bindgen_test;
use x509_cert::der::{DecodePem as _, Encode as _};

use super::*;
use crate::{
    Sha256Hash,
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
        StoredCredential, StoredCredentialPk, StoredEpochEncryptionKeypair, StoredEpochEncryptionKeypairPkRef,
        StoredKeyPackage, X509Crl, X509IntermediateCert, X509TrustAnchor,
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

impl Seed for ConsumerData {
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

impl Seed for MlsPendingMessage {
    fn seed() -> Self {
        Self {
            conversation_id: seed::PENDING_GROUP_ID.into(),
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
impl Seed for ProteusIdentity {
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
async fn assert_imported_and_migrated(db: &Database) {
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
    assert_eq!(credential.created_at, seed::CREDENTIAL_CREATED_AT);
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
    assert_imported_and_migrated(&db).await;

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
    assert_imported_and_migrated(&db).await;

    Arc::into_inner(db)
        .expect("no other reference to the database")
        .wipe()
        .await
        .expect("wiping the new database");
}
