mod meta_migrations;

use refinery::Target;
use rusqlite::functions::FunctionFlags;

use crate::{CryptoKeystoreResult, DatabaseKey};

refinery::embed_migrations!("src/connection/migrations");

#[derive(Default)]
pub(crate) enum MigrationTarget {
    #[default]
    Latest,
    Version(u16),
}

pub(super) fn run_migrations(conn: &mut rusqlite::Connection, target: MigrationTarget) -> CryptoKeystoreResult<()> {
    conn.create_scalar_function("sha256_blob", 1, FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
        let input_blob = ctx.get::<Vec<u8>>(0)?;
        Ok(crate::sha256(&input_blob))
    })?;

    let mut runner = migrations::runner();
    let Some(latest_migration_version) = runner
        .get_migrations()
        .iter()
        .map(|migration| migration.version())
        .max()
    else {
        // No migrations means nothing to do.
        return Ok(());
    };

    let target_version = match target {
        MigrationTarget::Latest => latest_migration_version,
        MigrationTarget::Version(target_argument) => (latest_migration_version).min(target_argument as i32),
    };

    for version in 1..=target_version {
        runner = runner.set_target(Target::Version(version));
        let report = runner.run(conn).map_err(Box::new)?;

        let Some(updated_version) = report.applied_migrations().iter().map(|m| m.version()).max() else {
            continue;
        };

        // If the version has been updated by the runner, first run the meta migration, then update the schema
        // version.
        run_meta_migration(updated_version, conn)?;
        conn.pragma_update(None, "user_version", updated_version)?;
    }

    Ok(())
}

/// Add a new match arm here if you want to run a meta migration (i.e., addtional work implemented in rust)
/// after a regular SQL migration.
fn run_meta_migration(sql_migration_version: i32, conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    match sql_migration_version {
        meta_migrations::v16::VERSION => meta_migrations::v16::meta_migration(conn),
        meta_migrations::v18::VERSION => meta_migrations::v18::meta_migration(conn),
        meta_migrations::v19::VERSION => meta_migrations::v19::meta_migration(conn),
        meta_migrations::v28::VERSION => meta_migrations::v28::meta_migration(conn),
        meta_migrations::v31::VERSION => meta_migrations::v31::meta_migration(conn),
        meta_migrations::v34::VERSION => meta_migrations::v34::meta_migration(conn),
        _ => Ok(()),
    }
}

/// Migrate a database encrypted with a string key to the new raw-bytes [`DatabaseKey`].
///
/// This is intended to be called only once, when migrating from CoreCrypto 5.x to 6.x, before
/// opening the database via [`super::Database::open`].
pub async fn migrate_db_key_type_to_bytes(
    path: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CryptoKeystoreResult<()> {
    // On WASM the legacy data lives in an IndexedDB database. This rekeys that legacy store in place,
    // re-encrypting every entity from the old string-derived cipher to the new bytes key. The
    // subsequent [`super::Database::open`] then copies the data into the unified rusqlite database.
    #[cfg(target_os = "unknown")]
    {
        super::idb_migration::migrate_legacy_idb_key_type_to_bytes(path, old_key, new_key).await
    }

    // On native platforms we implement the migration directly.
    #[cfg(not(target_os = "unknown"))]
    {
        use crate::CryptoKeystoreError;

        let mut conn = rusqlite::Connection::open(path)?;

        conn.pragma_update(None, "key", old_key)?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(target_os = "ios")]
        super::ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

        /// This is the latest schema version our test db dump is compatible with.
        const MAX_SUPPORTED_SCHEMA_VERSION: u8 = 15;

        let version = conn.query_row("PRAGMA user_version;", [], |row| row.get::<_, i32>(0))?;
        if version >= MAX_SUPPORTED_SCHEMA_VERSION as i32 {
            return Err(CryptoKeystoreError::MigrationFailed(
                "key type migration from string to bytes can and should only be done once and on database versions
                    corresponding to a core crypto version <= 9."
                    .to_string(),
            ));
        }

        // Enable WAL journaling mode
        conn.pragma_update(None, "journal_mode", "wal")?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        // Now update the database to the latest compatible schema version. The other, following migrations
        // will be run when the database is opened regularly.
        run_migrations(&mut conn, MigrationTarget::Version(MAX_SUPPORTED_SCHEMA_VERSION as u16))?;

        // Rekey the database.
        super::encryption::rekey(&mut conn, new_key)
    }
}

#[cfg(all(test, not(target_os = "unknown")))]
pub(crate) mod test {
    use std::io::Write;

    use openmls::prelude::Ciphersuite;
    use tempfile::NamedTempFile;
    use x509_cert::der::{DecodePem as _, Encode as _};

    use crate::{
        Sha256Hash,
        connection::{Database, DatabaseKey, migrate_db_key_type_to_bytes, migrations::MigrationTarget},
        entities::{
            MlsPendingMessage, StoredCredential, StoredEncryptionKeyPair, StoredHpkePrivateKey, StoredPskBundle,
        },
        traits::{Entity, EntityGetBorrowed as _, PrimaryKey as _},
    };

    pub(crate) const DB: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crypto-ffi/bindings/jvm/src/test/resources/db-v10002003.sqlite"
    ));
    pub(crate) const OLD_KEY: &str = "secret";

    /// Seed a fresh database at `schema_version`, then reopen it migrated all the way to latest.
    ///
    /// The inner database is dropped before reopening, so that the reopen actually runs the
    /// migrations under test against the seeded rows.
    async fn seed_then_migrate(
        path: &str,
        key: &DatabaseKey,
        schema_version: u16,
        seed: impl FnOnce(&rusqlite::Connection),
    ) -> std::sync::Arc<Database> {
        {
            let db = Database::open_at_schema_version(path, key, MigrationTarget::Version(schema_version))
                .await
                .expect("opening the database at the pre-migration schema version");
            let conn = db.conn().await;
            seed(&conn);
        }
        Database::open(path, key).await.expect("reopening fully migrated")
    }

    /// The storage class and length of a stored key, so that a failure says *why* it failed.
    ///
    /// A correctly backfilled key reads as `("blob", 32)`; a hex-encoded one as `("text", 64)`.
    fn stored_key_encoding(conn: &rusqlite::Connection, table: &str, column: &str) -> (String, i64) {
        conn.query_row(
            &format!("SELECT typeof({column}), length({column}) FROM {table}"),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("reading back the stored key")
    }

    /// A temporary database path, kept alive by the returned file handle.
    fn temp_db() -> (NamedTempFile, DatabaseKey) {
        (NamedTempFile::new().unwrap(), DatabaseKey::generate())
    }

    // a close replica of the JVM test in `GeneralTest.kt`, but way more debuggable
    #[test]
    fn can_migrate_key_type_to_bytes() {
        let mut db_file = NamedTempFile::new().unwrap();
        db_file.write_all(DB).unwrap();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");

        let new_key = DatabaseKey::generate();
        smol::block_on(migrate_db_key_type_to_bytes(path, OLD_KEY, &new_key)).unwrap();

        let _db = smol::block_on(Database::open(path, &new_key)).unwrap();
    }

    #[test]
    fn deduplicating_credentials() {
        let mut db_file = NamedTempFile::new().unwrap();
        db_file.write_all(DB).unwrap();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");

        let new_key = DatabaseKey::generate();
        smol::block_on(migrate_db_key_type_to_bytes(path, OLD_KEY, &new_key)).unwrap();

        smol::block_on(async {
            let db = Database::open_at_schema_version(path, &new_key, MigrationTarget::Version(18))
                .await
                .unwrap();

            let conn = db.conn().await;
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT
                        session_id,
                        credential,
                        unixepoch(created_at) AS created_at,
                        ciphersuite,
                        public_key,
                        private_key
                     FROM {credential_table}",
                    credential_table = "mls_credentials_new",
                ))
                .expect("preparing statement");

            let credential = stmt
                .query_one([], |row| {
                    Ok(StoredCredential {
                        session_id: row.get("session_id")?,
                        credential: row.get("credential")?,
                        created_at: row.get("created_at")?,
                        ciphersuite: row.get("ciphersuite")?,
                        public_key: row.get("public_key")?,
                        private_key: row.get("private_key")?,
                    })
                })
                .expect("credential from row");

            // Ciphersuites need to be ambiguous w.r.t their signature scheme to be a relevant duplicate
            conn.execute(
                "UPDATE mls_credentials_new SET ciphersuite = ?1",
                [Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16],
            )
            .expect("updating ciphersuite");

            // Create a duplicate from this credential
            conn.execute(
                "INSERT INTO mls_credentials_new (
                        session_id,
                        credential,
                        created_at,
                        ciphersuite,
                        public_key,
                        private_key
                    )
                    VALUES (?1, ?2, datetime(?3, 'unixepoch'), ?4, ?5, ?6)",
                (
                    credential.session_id.clone(),
                    credential.credential.clone(),
                    credential.created_at,
                    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 as u16,
                    credential.public_key.clone(),
                    credential.private_key.clone(),
                ),
            )
            .expect("inserting duplicate");

            let count = conn
                .query_row("SELECT COUNT(*) FROM mls_credentials_new", [], |row| {
                    row.get::<_, i32>(0)
                })
                .unwrap();

            assert_eq!(count, 2);

            drop(stmt);
            drop(conn);
            drop(db);

            let db = Database::open(path, &new_key).await.unwrap();
            let deduplicated_credentials =
                StoredCredential::load_all(&*db.conn().await).expect("deduplicated credentials");

            let deduplicated_count = deduplicated_credentials.len();

            let deduplicated_credential = deduplicated_credentials.first().expect("first credential");

            assert_eq!(deduplicated_count, 1);

            // In case of equal occurence, the credential with the numerically lower ciphersuite is kept.
            assert_eq!(
                deduplicated_credential.ciphersuite,
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16
            );
        });
    }

    #[test]
    fn migrate_to_multiple_trust_anchors() {
        let test_pem = "-----BEGIN CERTIFICATE-----
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
"
        .to_string();

        let cert = x509_cert::Certificate::from_pem(test_pem).expect("Certificate from pem");
        let db_file = NamedTempFile::new().unwrap();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");

        let new_key = DatabaseKey::generate();

        smol::block_on(async {
            let db = Database::open_at_schema_version(path, &new_key, MigrationTarget::Version(27))
                .await
                .unwrap();

            let conn = db.conn().await;
            let content = cert.to_der().expect("DER from certificate");
            conn.execute(
                "INSERT INTO e2ei_acme_ca (id, content) VALUES (?1, ?2)",
                rusqlite::params![0, content],
            )
            .unwrap();

            let count: i32 = conn
                .query_row("SELECT COUNT(*) FROM e2ei_acme_ca", [], |row| row.get(0))
                .unwrap();

            assert_eq!(count, 1);

            drop(conn);
            drop(db);

            // Open at the new version, triggering v28 -> v29 migration
            let db = Database::open_at_schema_version(path, &new_key, MigrationTarget::Version(29))
                .await
                .unwrap();

            let conn = db.conn().await;

            let (fingerprint, migrated_content): (Vec<u8>, Vec<u8>) = conn
                .query_row("SELECT fingerprint, content FROM x509_trust_anchor", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap();

            assert_eq!(migrated_content, content);

            let expected = cert
                .tbs_certificate
                .subject_public_key_info
                .fingerprint_bytes()
                .unwrap();

            assert_eq!(fingerprint, expected);
        });
    }

    /// A pending message which predates V31 is reachable by primary key once V31 has run.
    ///
    /// V31 backfills `hash_sha256` in SQL while [`MlsPendingMessage`] computes it in Rust. Those two
    /// have to agree on both the hash and its storage encoding, or migrated rows become unreachable
    /// by every primary-key operation: `get`, `delete`, and the transaction cache alike.
    #[test]
    fn v31_backfills_primary_keys_which_the_entity_can_use() {
        const CONVERSATION_ID: &[u8] = b"a conversation predating the migration";
        const MESSAGE: &[u8] = b"a message buffered before the migration ran";

        let db_file = NamedTempFile::new().unwrap();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");
        let key = DatabaseKey::generate();

        smol::block_on(async {
            // write a pending message the way the schema looked before V31
            {
                let db = Database::open_at_schema_version(path, &key, MigrationTarget::Version(30))
                    .await
                    .unwrap();
                let conn = db.conn().await;
                // The pre-V31 table still carries V7's foreign key onto `mls_pending_groups`, so the
                // parent row has to exist before the message can be inserted here. V31 drops that
                // constraint; see `v31_migrates_a_pending_message_whose_conversation_is_not_a_pending_group`
                // for the case which the constraint used to make impossible.
                conn.execute(
                    "INSERT INTO mls_pending_groups (id, state, cfg) VALUES (?, ?, ?)",
                    (CONVERSATION_ID, b"group state", b"custom configuration"),
                )
                .expect("inserting the pending group the message refers to");
                conn.execute(
                    "INSERT INTO mls_pending_messages (id, message) VALUES (?, ?)",
                    (CONVERSATION_ID, MESSAGE),
                )
                .expect("inserting a pre-migration pending message");
            }

            // reopening runs V31, which must backfill a primary key the entity agrees with
            let db = Database::open(path, &key).await.unwrap();
            let conn = db.conn().await;

            let migrated = MlsPendingMessage::load_all(&conn).expect("loading migrated pending messages");
            assert_eq!(migrated.len(), 1, "the migration must not lose the pending message");
            let migrated = migrated.into_iter().next().unwrap();
            assert_eq!(migrated.conversation_id.bytes(), CONVERSATION_ID);
            assert_eq!(migrated.message, MESSAGE);

            // spelled out rather than taken from `primary_key()`, so that this pins the derivation
            // for both the entity and the migration rather than just mirroring one of them
            let expected_key = Sha256Hash::hash_from_many([
                (CONVERSATION_ID.len() as u64).to_be_bytes().as_slice(),
                CONVERSATION_ID,
                MESSAGE,
            ]);
            assert_eq!(
                migrated.primary_key(),
                expected_key,
                "the entity must derive its primary key from the same inputs the migration hashed"
            );

            assert!(
                MlsPendingMessage::get(&conn, &expected_key)
                    .expect("getting the migrated pending message by primary key")
                    .is_some(),
                "the primary key V31 wrote must be byte-identical to the one the entity binds when querying"
            );
        });
    }

    /// V31 migrates a pending message whose conversation has no `mls_pending_groups` row.
    ///
    /// This is the state V31's backfill would have rejected had it recreated V7's foreign key: an
    /// `INSERT ... SELECT` into a constrained table fails on the first orphan row, and a migration which
    /// fails leaves the database unopenable. Such rows are reachable in practice, because
    /// [`migrate_db_key_type_to_bytes`] runs the early migrations with `foreign_keys` off and the legacy
    /// IndexedDB import writes buffered messages before the pending groups they refer to.
    ///
    /// The seed plants one the same way, by turning foreign keys off for the insert. There is no other way
    /// to create a row which the pre-V31 schema forbids, which is the point: what the schema forbade is
    /// exactly what the code above it was trying to store.
    #[test]
    fn v31_migrates_a_pending_message_whose_conversation_is_not_a_pending_group() {
        const CONVERSATION_ID: &[u8] = b"an established conversation, absent from mls_pending_groups";
        const MESSAGE: &[u8] = b"a message from epoch n + 1, buffered before the migration ran";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 30, |conn| {
                conn.pragma_update(None, "foreign_keys", "OFF")
                    .expect("disabling foreign keys so that the orphan row can be planted at all");
                conn.execute(
                    "INSERT INTO mls_pending_messages (id, message) VALUES (?, ?)",
                    (CONVERSATION_ID, MESSAGE),
                )
                .expect("inserting a pending message whose conversation is not a pending group");
            })
            .await;
            let conn = db.conn().await;

            let migrated = MlsPendingMessage::load_all(&conn).expect("loading migrated pending messages");
            assert_eq!(
                migrated.len(),
                1,
                "V31 must carry an orphan pending message across, not drop it or fail the migration"
            );
            let migrated = migrated.into_iter().next().unwrap();
            assert_eq!(migrated.conversation_id.bytes(), CONVERSATION_ID);
            assert_eq!(migrated.message, MESSAGE);
        });
    }

    // The tests below all cover the same defect and its repair, one entity at a time.
    //
    // `sha256_blob` is named for its input, not its output: it returns `crate::sha256`, which is a
    // 64-character hex string. Every migration which backfills a sha256 key column therefore writes
    // TEXT, while `impl ToSql for Sha256Hash` binds the 32 raw digest bytes. SQLite never compares a
    // blob equal to text, so a row such a migration wrote cannot be found by the code which owns it:
    // the data survives `load_all` but is invisible to `get` and `delete`, and so to the transaction
    // cache as well.
    //
    // V31 avoids this in its own backfill by wrapping it in `unhex(...)`. V12 and V20 shipped
    // without it, so the V31 meta migration rewrites what they left behind.

    /// The V31 meta migration repairs `mls_encryption_keypairs.pk_sha256` keys backfilled by V12.
    #[test]
    fn v31_meta_migration_repairs_v12_encryption_keypair_keys() {
        const PK: &[u8] = b"an encryption public key predating V12";
        const SK: &[u8] = b"the secret key which belongs with it";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 11, |conn| {
                conn.execute("INSERT INTO mls_encryption_keypairs (pk, sk) VALUES (?, ?)", (PK, SK))
                    .expect("inserting a pre-V12 encryption keypair");
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(
                StoredEncryptionKeyPair::count(&conn).unwrap(),
                1,
                "the migration must not lose the keypair"
            );

            let encoding = stored_key_encoding(&conn, "mls_encryption_keypairs", "pk_sha256");
            assert!(
                StoredEncryptionKeyPair::get_borrowed(&conn, PK).unwrap().is_some(),
                "a migrated keypair must be gettable by its public key, but `pk_sha256` is stored as \
                 {encoding:?} while `Sha256Hash` binds 32 raw bytes"
            );
        });
    }

    /// The V31 meta migration repairs `mls_hpke_private_keys.pk_sha256` keys backfilled by V12.
    #[test]
    fn v31_meta_migration_repairs_v12_hpke_private_key_keys() {
        const PK: &[u8] = b"an HPKE public key predating V12";
        const SK: &[u8] = b"the secret key which belongs with it";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 11, |conn| {
                conn.execute("INSERT INTO mls_hpke_private_keys (pk, sk) VALUES (?, ?)", (PK, SK))
                    .expect("inserting a pre-V12 HPKE private key");
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(
                StoredHpkePrivateKey::count(&conn).unwrap(),
                1,
                "the migration must not lose the private key"
            );

            let encoding = stored_key_encoding(&conn, "mls_hpke_private_keys", "pk_sha256");
            assert!(
                StoredHpkePrivateKey::get_borrowed(&conn, PK).unwrap().is_some(),
                "a migrated HPKE private key must be gettable by its public key, but `pk_sha256` is stored \
                 as {encoding:?} while `Sha256Hash` binds 32 raw bytes"
            );
        });
    }

    /// The V31 meta migration repairs `mls_psk_bundles.id_sha256` keys backfilled by V12.
    #[test]
    fn v31_meta_migration_repairs_v12_psk_bundle_keys() {
        const PSK_ID: &[u8] = b"a psk id predating V12";
        const PSK: &[u8] = b"the pre-shared key itself";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 11, |conn| {
                conn.execute("INSERT INTO mls_psk_bundles (psk_id, psk) VALUES (?, ?)", (PSK_ID, PSK))
                    .expect("inserting a pre-V12 psk bundle");
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(
                StoredPskBundle::count(&conn).unwrap(),
                1,
                "the migration must not lose the psk bundle"
            );

            let encoding = stored_key_encoding(&conn, "mls_psk_bundles", "id_sha256");
            assert!(
                StoredPskBundle::get_borrowed(&conn, PSK_ID).unwrap().is_some(),
                "a migrated psk bundle must be gettable by its psk id, but `id_sha256` is stored as \
                 {encoding:?} while `Sha256Hash` binds 32 raw bytes"
            );
        });
    }

    /// The V31 meta migration repairs `mls_credentials.public_key_sha256` keys backfilled by V20.
    #[test]
    fn v31_meta_migration_repairs_v20_credential_keys() {
        const PUBLIC_KEY: &[u8] = b"a credential public key predating V20";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 19, |conn| {
                conn.execute(
                    "INSERT INTO mls_credentials (session_id, credential, ciphersuite, public_key, private_key) \
                     VALUES (?, ?, ?, ?, ?)",
                    (
                        b"a session id".as_slice(),
                        b"the credential".as_slice(),
                        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16,
                        PUBLIC_KEY,
                        b"the private key".as_slice(),
                    ),
                )
                .expect("inserting a pre-V20 credential");
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(
                StoredCredential::count(&conn).unwrap(),
                1,
                "the migration must not lose the credential"
            );

            let encoding = stored_key_encoding(&conn, "mls_credentials", "public_key_sha256");
            assert!(
                StoredCredential::get(&conn, &Sha256Hash::hash_from(PUBLIC_KEY))
                    .unwrap()
                    .is_some(),
                "a migrated credential must be gettable by the hash of its public key, but \
                 `public_key_sha256` is stored as {encoding:?} while `Sha256Hash` binds 32 raw bytes"
            );
        });
    }

    /// A hex key which collides with a key already stored as bytes is dropped, not rewritten.
    ///
    /// This is the state any long-lived database is actually in: V12 left a hex-keyed row behind,
    /// and because that row was invisible to `get`, the code went on to save the same key again —
    /// correctly, as bytes. The byte-keyed row is therefore the live one, and rewriting the hex row
    /// would both resurrect stale data and violate the column's uniqueness constraint.
    #[test]
    fn v31_meta_migration_drops_hex_keys_superseded_by_byte_keys() {
        const PK: &[u8] = b"a public key saved once before V12 and once after";
        const STALE_SK: &[u8] = b"the secret key stored alongside the hex-keyed row";
        const LIVE_SK: &[u8] = b"the secret key stored alongside the byte-keyed row";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let hash = Sha256Hash::hash_from(PK);

            // Seed after V12 has already run, so both encodings can be planted side by side. They
            // coexist because the uniqueness constraint sees a text and a blob as distinct values.
            let db = seed_then_migrate(path, &key, 30, |conn| {
                conn.execute(
                    "INSERT INTO mls_encryption_keypairs (pk_sha256, pk, sk) VALUES (?, ?, ?)",
                    (hash.to_string(), PK, STALE_SK),
                )
                .expect("inserting the hex-keyed row V12 would have left behind");
                conn.execute(
                    "INSERT INTO mls_encryption_keypairs (pk_sha256, pk, sk) VALUES (?, ?, ?)",
                    (hash, PK, LIVE_SK),
                )
                .expect("inserting the byte-keyed row the entity would have written since");
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(
                StoredEncryptionKeyPair::count(&conn).unwrap(),
                1,
                "the superseded hex-keyed row must be dropped rather than rewritten"
            );

            let survivor = StoredEncryptionKeyPair::get_borrowed(&conn, PK)
                .unwrap()
                .expect("the byte-keyed row must survive and stay gettable");
            assert_eq!(
                survivor.sk, LIVE_SK,
                "the surviving row must be the byte-keyed one, not the stale hex-keyed one"
            );
        });
    }

    /// No hex-encoded key survives a full migration of a real legacy database.
    ///
    /// The tests above each plant a single row by hand. This one runs the meta migration over the
    /// bundled v10002003 dump, which carries real keypairs and credentials in the quantities and
    /// shapes an actual upgrading client would present.
    #[test]
    fn v31_meta_migration_leaves_no_hex_keys_in_a_real_legacy_database() {
        let mut db_file = NamedTempFile::new().unwrap();
        db_file.write_all(DB).unwrap();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");

        let new_key = DatabaseKey::generate();
        smol::block_on(migrate_db_key_type_to_bytes(path, OLD_KEY, &new_key)).unwrap();

        smol::block_on(async {
            let db = Database::open(path, &new_key).await.unwrap();
            let conn = db.conn().await;

            let mut rows_checked = 0;
            for (table, column) in [
                ("mls_encryption_keypairs", "pk_sha256"),
                ("mls_hpke_private_keys", "pk_sha256"),
                ("mls_psk_bundles", "id_sha256"),
                ("mls_credentials", "public_key_sha256"),
            ] {
                let (total, as_text) = conn
                    .query_row(
                        &format!("SELECT count(*), coalesce(sum(typeof({column}) = 'text'), 0) FROM {table}"),
                        [],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .expect("counting stored key encodings");

                assert_eq!(
                    as_text, 0,
                    "{table}.{column} still stores {as_text} of {total} keys as hex text"
                );
                rows_checked += total;
            }

            assert!(
                rows_checked > 0,
                "the bundled database carried no keys at all, so this test proved nothing"
            );

            // and the repaired keys are not merely blobs, but the exact blobs the entity queries with
            let public_key: Vec<u8> = conn
                .query_row("SELECT pk FROM mls_encryption_keypairs LIMIT 1", [], |row| row.get(0))
                .expect("reading a migrated public key");
            assert!(
                StoredEncryptionKeyPair::get(&conn, &public_key).unwrap().is_some(),
                "a keypair from the real legacy database must be gettable by its public key"
            );
        });
    }
}
