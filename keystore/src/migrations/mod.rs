pub(crate) mod historical;
mod meta_migrations;
#[cfg(test)]
pub(crate) mod test_helpers;

use refinery::Target;
use rusqlite::{Connection, functions::FunctionFlags};

use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

refinery::embed_migrations!("src/migrations");

const COMPOSITE_SCHEMA: &str = include_str!("composite-schema.sql");

/// The `user_version` pragma; CONST here to guard against typos
const USER_VERSION: &str = "user_version";

fn get_user_version(conn: &Connection) -> CryptoKeystoreResult<i32> {
    conn.pragma_query_value(None, USER_VERSION, |row| row.get(0))
        .map_err(Into::into)
}

fn set_user_version(conn: &Connection, version: i32) -> CryptoKeystoreResult<()> {
    conn.pragma_update(None, USER_VERSION, version).map_err(Into::into)
}

#[derive(Default)]
pub(crate) enum MigrationTarget {
    /// Perform all migrations
    #[default]
    Latest,
    /// Perform all migrations up to the specified version
    Version(u16),
    /// Execute the composite schema, producing the final form of the database without going through each individual
    /// migration.
    Composite,
}

pub(crate) fn run_migrations(conn: &mut rusqlite::Connection, target: MigrationTarget) -> CryptoKeystoreResult<()> {
    conn.create_scalar_function("sha256_blob", 1, FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
        let input_blob = ctx.get::<Vec<u8>>(0)?;
        Ok(crate::sha256(&input_blob))
    })?;

    // Wihout `set_grouped(true)`, refinery commits a migration and its history row in separate transactions. If the
    // migration crashes in between, the next open re-applies the migration and fails. We target one version at a
    // time, so grouping ties each migration to its history row.
    let mut runner = migrations::runner().set_grouped(true);
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
        MigrationTarget::Composite => {
            conn.execute_batch(COMPOSITE_SCHEMA)?;
            set_user_version(conn, latest_migration_version)?;
            return Ok(());
        }
    };

    // Adjust the schema history only if it already exists.
    let has_refinery_schema_history = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'refinery_schema_history')",
        [],
        |row| row.get::<_, bool>(0),
    )?;

    // These versions are known to have differences which affect the checksum but not the database shape when the
    // migration has been completed.
    // Ensure Refinery sees the checksum of the embedded migration when it validates the history.
    const BROKEN_MIGRATION_FILE_VERSIONS: &[i32] = &[16, 31];
    if has_refinery_schema_history {
        for &version in BROKEN_MIGRATION_FILE_VERSIONS {
            let expected_checksum = runner
                .get_migrations()
                .iter()
                .find(|migration| migration.version() == version)
                .expect("relevant versions are embedded")
                .checksum()
                .to_string();

            conn.execute(
                "UPDATE refinery_schema_history SET checksum = ?1 WHERE version = ?2",
                (expected_checksum, version),
            )?;
        }
    }

    // Contrary to its documentation, `get_last_applied_migration` errors out when there are no applied migrations.
    let newest_applied_version = has_refinery_schema_history
        .then(|| runner.get_last_applied_migration(conn))
        .transpose()
        .map_err(Box::new)?
        .flatten()
        .map(|migration| migration.version())
        .unwrap_or_default();

    // Where to resume. `user_version` names the version whose SQL migration and meta migration both
    // completed, so normally we pick up just after it.
    //
    // However, we used to have ios unconditionally setting `user_version` to 2.
    // In that case, `newest_applied_version` will probably be substantially higher than `user_version + 1`.
    // We still don't want to redo work, but we have to account for the possibility that
    // there's a meta-migration which hasn't yet applied, so we re-apply that version; refinery ensures
    // that the actual migration is a noop, and we get to try for a meta-migration.
    //
    // This is a specific instance of a more general rule: it's only ever safe to apply a meta-migration if
    // we have just now completed the migration previous to it. We need to take care not to ever attempt it in
    // any other case.
    let user_version = get_user_version(conn)?;

    // A database carrying a migration this build has never heard of was written by a newer CoreCrypto,
    // and this build would store data its schema cannot represent. Refinery performs this check itself,
    // but only when it is asked to apply something, and an up-to-date database never enters the loop
    // below. Compare against what this build knows, not against `target_version`, which callers may
    // deliberately set lower than the newest embedded migration.
    if user_version.max(newest_applied_version) > latest_migration_version {
        return Err(CryptoKeystoreError::DatabaseFromTheFuture);
    }

    // Migrations which rebuild a table that other tables reference. With foreign keys on, dropping the old table
    // would cascade into every table referencing it, so those would all have to be rebuilt too. With them off, the
    // references just point at whichever table holds the name once the migration is done.
    //
    // Nothing checks the copied rows while foreign keys are off, so such a migration has to keep every reference
    // valid by construction, and its test should assert that `PRAGMA foreign_key_check` comes back empty.
    //
    // The pragma is a no-op inside a transaction, and refinery runs each migration in one, so it can't be set from
    // the migration's own SQL.
    const WITHOUT_FOREIGN_KEYS: &[i32] = &[50];

    let resume_from = (user_version + 1).max(newest_applied_version);
    for version in resume_from..=target_version {
        runner = runner.set_target(Target::Version(version));

        let report = if WITHOUT_FOREIGN_KEYS.contains(&version) {
            // Restore whatever the caller had rather than assuming it was on.
            let foreign_keys: bool = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
            conn.pragma_update(None, "foreign_keys", false)?;
            let report = runner.run(conn);
            // Restore before looking at the result, so a failed migration doesn't leave foreign keys off.
            conn.pragma_update(None, "foreign_keys", foreign_keys)?;
            report
        } else {
            runner.run(conn)
        }
        .map_err(Box::new)?;

        debug_assert!(
            report.applied_migrations().len() < 2,
            "either 0 or 1 migration was applied per iteration in this loop"
        );
        // There are two cases where we apply 0 migrations:
        //
        // 1. The sql migration succeeded, but the following meta-migration failed for some reason, causing
        //    `user_version` not to be set for that migration.
        // 2. We iterated based on `newest_applied_version` instead of `user_version`, repeating the final previously
        //    applied migration, just in case there's a meta-migration waiting for us.
        debug_assert!(
            report
                .applied_migrations()
                .first()
                .is_none_or(|migration| migration.version() == version),
            "the applied migration version matches the current version step"
        );

        // Run the meta migration, then advance `user_version`, atomically. This runs whether or not the
        // runner applied anything just now: a SQL migration which is applied while `user_version` still
        // lags behind it is one whose meta migration was interrupted, and it has to be retried.
        run_meta_migration(version, conn)?;
    }

    Ok(())
}

/// Run a meta-migration (i.e., additional work implemented in rust) after a regular SQL migration.
///
/// This is the dispatch for a meta-migration; every meta-migration must have a match arm here, or it will not run.
///
/// This also manages the transaction each meta-migration runs within. If a meta-migration exists, it happens within
/// the transaction defined here.
///
/// This _also_ manages setting the user version on every migration whether or not a meta-migration exists.
/// That doesn't feel like great factoring, but this is where the transaction is, and we depend on the property that
/// we only set `user_version` when _both_ a sql migration and its subsequent meta-migration (if any) have both
/// successfully completed.
fn run_meta_migration(version: i32, conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;
    match version {
        meta_migrations::v16::VERSION => meta_migrations::v16::meta_migration(&tx)?,
        meta_migrations::v18::VERSION => meta_migrations::v18::meta_migration(&tx)?,
        meta_migrations::v19::VERSION => meta_migrations::v19::meta_migration(&tx)?,
        meta_migrations::v28::VERSION => meta_migrations::v28::meta_migration(&tx)?,
        meta_migrations::v31::VERSION => meta_migrations::v31::meta_migration(&tx)?,
        meta_migrations::v34::VERSION => meta_migrations::v34::meta_migration(&tx)?,
        meta_migrations::v37::VERSION => meta_migrations::v37::meta_migration(&tx)?,
        meta_migrations::v39::VERSION => meta_migrations::v39::meta_migration(&tx)?,
        meta_migrations::v45::VERSION => meta_migrations::v45::meta_migration(&tx)?,
        meta_migrations::v49::VERSION => meta_migrations::v49::meta_migration(&tx)?,
        meta_migrations::v51::VERSION => meta_migrations::v51::meta_migration(&tx)?,
        _ => {}
    }

    set_user_version(&tx, version)?;
    tx.commit().map_err(Into::into)
}

/// Migrate a database encrypted with a string key to the new raw-bytes [`DatabaseKey`].
///
/// This is intended to be called only once, when migrating from CoreCrypto 5.x to 6.x, before
/// opening the database via [`crate::Database::open`].
pub async fn migrate_db_key_type_to_bytes(
    path: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CryptoKeystoreResult<()> {
    // On WASM the legacy data lives in an IndexedDB database. This rekeys that legacy store in place,
    // re-encrypting every entity from the old string-derived cipher to the new bytes key. The
    // subsequent [`crate::Database::open`] then copies the data into the unified rusqlite database.
    #[cfg(target_os = "unknown")]
    {
        crate::connection::idb_migration::migrate_legacy_idb_key_type_to_bytes(path, old_key, new_key).await
    }

    // On native platforms we implement the migration directly.
    #[cfg(not(target_os = "unknown"))]
    {
        use crate::{CryptoKeystoreError, connection};

        let mut conn = rusqlite::Connection::open(path)?;
        let transaction_lock = connection::TransactionLock::new(conn.path().unwrap_or_default())?;
        let _guard = transaction_lock.acquire().await?;

        conn.pragma_update(None, "key", old_key)?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(target_os = "ios")]
        connection::ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

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
        connection::encryption::rekey(&mut conn, new_key)
    }
}

#[cfg(all(test, not(target_os = "unknown")))]
mod test {
    use std::io::Write;

    use openmls::prelude::{Ciphersuite, Credential as MlsCredential, TlsSerializeTrait as _};
    use tempfile::NamedTempFile;
    use x509_cert::der::{DecodePem as _, Encode as _};

    use crate::{
        DatabaseKey, Sha256Hash,
        connection::{Database, migrate_db_key_type_to_bytes},
        entities::{StoredCredential, StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredPskBundle},
        migrations::{
            MigrationTarget,
            test_helpers::{
                DB, OLD_KEY, pending_messages, seed_then_migrate, seed_then_migrate_to, stored_key_encoding, temp_db,
            },
        },
        traits::{Entity, EntityGetBorrowed as _},
    };

    // A self-signed P256 certificate for client `7f3a9c2e-5b1d-4e8a-9c6f-2d4b8e1a3f5c:a1b2c3d4e5f60718@wire.com`
    const CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBwzCCAWigAwIBAgIULao7a4zzIWQnsf+x3AATPKxNz9MwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFYWxpY2UwIBcNMjYxMDAyMDkxMzMyWhgPMjEyNjA5MDgwOTEz
MzJaMBAxDjAMBgNVBAMMBWFsaWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
jVFOhKBLgunDycNREMhL/HNqEVu4q233k4OLVEfSV7cxWEiObENMRUqdR3QnRKfk
xZcUf/LTfGEhM9ZITludV6OBnTCBmjAdBgNVHQ4EFgQUInHZBtKavuhbjGkbsEJN
TXgPgDYwHwYDVR0jBBgwFoAUInHZBtKavuhbjGkbsEJNTXgPgDYwDwYDVR0TAQH/
BAUwAwEB/zBHBgNVHREEQDA+hjx3aXJlYXBwOi8vZnpxY0xsc2RUb3FjYnkxTGpo
b19YQSUyMWExYjJjM2Q0ZTVmNjA3MThAd2lyZS5jb20wCgYIKoZIzj0EAwIDSQAw
RgIhAPzHW4tb1ABKVdVaCD/FyEAAo/iKXYrIY7Sb/u1A6zEzAiEAvXkFu46HchDj
IskA0GpmFaPAdfTnoxFfKzGoH+P3RqM=
-----END CERTIFICATE-----
";
    const PRIVATE_KEY_HEX: &str = "6f5653a1cd645f9a8ca45e8dc724f5adb5117cd1ce0ec3cd1a11745e9c0a0a08";
    const CLIENT_ID: &[u8] = b"7f3a9c2e-5b1d-4e8a-9c6f-2d4b8e1a3f5c:a1b2c3d4e5f60718@wire.com";

    #[test]
    fn released_migration_checksums_are_unchanged() {
        // Refinery hashes the migration name, version, and SQL, including whitespace and comments.
        // Don't update existing, already released entries to accommodate an edit: add a new migration instead. Append a
        // checksum whenever a migration is added. Running this test after addiing a new migration file will
        // output the expected tuple.
        //
        // Escape hatch: if an existing migration:
        // 1. is broken in a way that could cause it to fail to apply (i.e. new constraints without appropriate guards
        //    on migration insertion)
        // 2. can be fixed without changing the shape of the database (i.e. by adding new guards on migration insertion)
        //
        // then it is ok to update the checksum here and also add that migration to the special-case list in
        // `BROKEN_MIGRATION_FILE_VERSIONS`.
        const RELEASED_CHECKSUMS: &[(i32, u64)] = &[
            (1, 13981446244764045850),
            (2, 10014296231349852013),
            (3, 10809117100344207944),
            (4, 14920516941281032742),
            (5, 12966312308626130346),
            (6, 8044509004432369903),
            (7, 17729748238669772100),
            (8, 3048540027269991615),
            (9, 7039584946400084759),
            (10, 16156164571533126355),
            (11, 13404488064808444530),
            (12, 6597288508644970480),
            (13, 5731883127003238395),
            (14, 10748374302670893447),
            (15, 2169875193630311763),
            (16, 2746928252018864774),
            (17, 12233330215929448823),
            (18, 7775189113825083442),
            (19, 7443032372885862401),
            (20, 9998984195998664656),
            (21, 7013639425315607404),
            (22, 3158904360480291309),
            (23, 17323643733849745028),
            (24, 17262053458201743073),
            (25, 9314203443172137842),
            (26, 3313040238731256416),
            (27, 9023891923424599773),
            (28, 9800077133815304595),
            (29, 4026373323163068147),
            (30, 4359295101874567444),
            (31, 1341948504623982187),
            (32, 8623467557464580542),
            (33, 4190965026202622936),
            (34, 6226054801151536100),
            (35, 9726380046663748763),
            (36, 10350838762062966646),
            (37, 18095597181196471627),
            (38, 15137075953368231210),
            (39, 6765673326148585052),
            (40, 313685348854489679),
            (41, 1379398854216841256),
            (42, 3642602498038214093),
            (43, 7019178301151360528),
            (44, 9343802733246156539),
            (45, 11852759019974572996),
            (46, 5473226583050100681),
            (47, 11056727624062448257),
            (48, 15131338238207930367),
            (49, 1202272748319186004),
            (50, 4292486588344934490),
            (51, 6769583600770212455),
            (52, 17645429909226378086),
        ];

        let runner = super::migrations::runner();

        let migrations = {
            let mut m = runner.get_migrations().clone();
            m.sort_by_key(refinery::Migration::version);
            m
        };

        // sanity checks on the migrations
        assert_eq!(
            migrations.first().map(|migration| migration.version()),
            Some(1),
            "first migration is version 1"
        );
        assert!(
            migrations
                .array_windows()
                .all(|[left, right]| right.version() == left.version() + 1),
            "migration versions must be sequential"
        );

        // from this point we collect and display as many failures as possible before aborting
        let mut pending_failure = false;
        match RELEASED_CHECKSUMS.len().cmp(&migrations.len()) {
            std::cmp::Ordering::Greater => {
                pending_failure = true;
                for &(version, _) in &RELEASED_CHECKSUMS[migrations.len()..] {
                    eprintln!("expected version {version} but it was not found by the migrations runner");
                }
            }
            std::cmp::Ordering::Less => {
                pending_failure = true;
                for migration in &migrations[RELEASED_CHECKSUMS.len()..] {
                    let version = migration.version();
                    let name = migration.name();
                    let checksum = migration.checksum();
                    eprintln!("migration V{version}__{name} not pinned; add `({version}, {checksum})`");
                }
            }
            std::cmp::Ordering::Equal => {}
        }

        // in addition to extra migrations we check for version mismatch
        for ((expect_version, expect_checksum), migration) in RELEASED_CHECKSUMS.iter().copied().zip(migrations.iter())
        {
            if expect_version != migration.version() {
                pending_failure = true;
                eprintln!(
                    "{expect_version} != {}; ensure pinned checksum versions increase sequentially",
                    migration.version()
                );
            }
            if expect_checksum != migration.checksum() {
                pending_failure = true;
                eprintln!(
                    "V{expect_version}: checksum {expect_checksum} (expected) != {} (found)",
                    migration.checksum()
                );
                eprintln!("  instead of changing the old migration, add a new one");
            }
        }

        assert!(
            !pending_failure,
            "pinned RELEASED_CHECKSUMS did not match the discovered migrations"
        );
    }

    #[test]
    fn repairs_divergent_v16_checksum_before_running_migrations() {
        let (db_file, key) = temp_db();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");

        smol::block_on(async {
            let db = Database::open_at_schema_version(path, &key, MigrationTarget::Version(16))
                .await
                .expect("opening the database at V16");
            let conn = db.conn().await;
            let expected_checksum: String = conn
                .query_row(
                    "SELECT checksum FROM refinery_schema_history WHERE version = 16",
                    [],
                    |row| row.get(0),
                )
                .expect("reading the V16 checksum");
            let divergent_checksum = (expected_checksum.parse::<u64>().unwrap().wrapping_add(1)).to_string();

            conn.execute(
                "UPDATE refinery_schema_history SET checksum = ?1 WHERE version = 16",
                [&divergent_checksum],
            )
            .expect("replacing the V16 checksum");

            Database::open(path, &key)
                .await
                .expect("reopening and migrating the database");
        });
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

    /// A v9 client which completed E2EI enrollment keeps its X509 credential through the migration chain.
    ///
    /// In v9, E2EI activation reused the basic credential's signature key for the new X509 credential, and
    /// stored the keypair again, all under the same client id. The basic credential may be dropped, as v9
    /// enrollment was a replacement of the basic credential, but the X509 credential must survive.
    #[test]
    fn e2ei_enrolled_v9_client_keeps_its_x509_credential() {
        use openmls::prelude::{CredentialType, SignatureScheme};
        use openmls_basic_credential::SignatureKeyPair;

        let certificate = x509_cert::Certificate::from_pem(CERTIFICATE_PEM).unwrap();
        let public_key = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let private_key = hex::decode(PRIVATE_KEY_HEX).unwrap();
        let keypair = SignatureKeyPair::from_raw(
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            private_key.clone(),
            public_key.clone(),
        )
        .tls_serialize_detached()
        .unwrap();

        let basic_credential = MlsCredential::new_basic(CLIENT_ID.to_vec())
            .tls_serialize_detached()
            .unwrap();
        let x509_credential = MlsCredential::new_x509(vec![certificate.to_der().unwrap()])
            .unwrap()
            .tls_serialize_detached()
            .unwrap();

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 15, |conn| {
                // Each v9 `save_identity` call stored a credential and its keypair: once when the basic
                // credential was created, and again when E2EI activation saved the X509 credential.
                for (credential, created_at) in [(&basic_credential, 1_700_000_000), (&x509_credential, 1_700_000_100)]
                {
                    conn.execute(
                        "INSERT INTO mls_credentials (id, credential, created_at) \
                         VALUES (?1, ?2, datetime(?3, 'unixepoch'))",
                        (CLIENT_ID, credential, created_at),
                    )
                    .expect("inserting a v9 credential");
                    conn.execute(
                        "INSERT INTO mls_signature_keypairs (signature_scheme, pk, keypair, credential_id) \
                         VALUES (?1, ?2, ?3, ?4)",
                        (
                            SignatureScheme::ECDSA_SECP256R1_SHA256 as u16,
                            &public_key,
                            &keypair,
                            CLIENT_ID,
                        ),
                    )
                    .expect("inserting a v9 signature keypair");
                }
            })
            .await;
            let conn = db.conn().await;

            let stored = StoredCredential::get(
                &conn,
                &crate::entities::StoredCredentialPk::new(
                    Sha256Hash::hash_from(&public_key),
                    CredentialType::X509.into(),
                    certificate
                        .tbs_certificate()
                        .validity()
                        .not_before
                        .to_unix_duration()
                        .as_secs(),
                ),
            )
            .unwrap()
            .expect("the X509 credential must survive the migrations");

            assert_eq!(stored.credential, x509_credential);
            assert_eq!(stored.session_id, CLIENT_ID);
            assert_eq!(stored.private_key, private_key);
            assert_eq!(
                stored.ciphersuite,
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 as u16
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
                .tbs_certificate()
                .subject_public_key_info()
                .fingerprint_bytes()
                .unwrap();

            assert_eq!(fingerprint, expected);
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
    ///
    /// The test stops at V31. V44 deliberately drops a message like this one if its conversation is absent
    /// from `mls_groups`, because by then nothing can reach it.
    #[test]
    fn v31_migrates_a_pending_message_whose_conversation_is_not_a_pending_group() {
        const CONVERSATION_ID: &[u8] = b"an established conversation, absent from mls_pending_groups";
        const MESSAGE: &[u8] = b"a message from epoch n + 1, buffered before the migration ran";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate_to(path, &key, 30, MigrationTarget::Version(31), |conn| {
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

            assert_eq!(
                pending_messages(&conn),
                [(CONVERSATION_ID.to_vec(), MESSAGE.to_vec())],
                "V31 must carry an orphan pending message across, not drop it or fail the migration"
            );
        });
    }

    /// V31 collapses pre-existing duplicate pending messages instead of failing the migration.
    ///
    /// Before V31 the table had no uniqueness constraint at all, and `MlsPendingMessage::save` was a
    /// plain `INSERT`, so buffering the same message for the same conversation twice — the DS resending
    /// it, or the same commit being processed twice — stored it twice. V31 derives the new primary key
    /// by hashing exactly those two columns, so any such pair collides, and the backfill is a single
    /// `INSERT ... SELECT`: one collision aborts the whole migration and leaves the database unopenable.
    ///
    /// Dropping the extra copy is the right outcome. The rows are byte-identical, so nothing is lost,
    /// and post-V31 the entity treats a repeated save as a no-op for the same reason.
    #[test]
    fn v31_drops_duplicate_pending_messages_rather_than_failing() {
        const CONVERSATION_ID: &[u8] = b"a conversation which buffered the same message twice";
        const DUPLICATED_MESSAGE: &[u8] = b"a message buffered twice before the migration ran";
        const DISTINCT_MESSAGE: &[u8] = b"a different message from the same conversation";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate_to(path, &key, 30, MigrationTarget::Version(31), |conn| {
                // V7's foreign key is still in force at this version, so the parent row has to exist.
                conn.execute(
                    "INSERT INTO mls_pending_groups (id, state, cfg) VALUES (?, ?, ?)",
                    (CONVERSATION_ID, b"group state", b"custom configuration"),
                )
                .expect("inserting the pending group the messages refer to");
                for message in [DUPLICATED_MESSAGE, DUPLICATED_MESSAGE, DISTINCT_MESSAGE] {
                    conn.execute(
                        "INSERT INTO mls_pending_messages (id, message) VALUES (?, ?)",
                        (CONVERSATION_ID, message),
                    )
                    .expect("the pre-V31 table has no uniqueness constraint, so this always succeeds");
                }
            })
            .await;
            let conn = db.conn().await;

            let mut expected =
                [DISTINCT_MESSAGE, DUPLICATED_MESSAGE].map(|message| (CONVERSATION_ID.to_vec(), message.to_vec()));
            expected.sort_by(|(_, a), (_, b)| a.cmp(b));
            assert_eq!(
                pending_messages(&conn),
                expected,
                "V31 must keep one copy of the duplicated message and the distinct one, and lose neither"
            );
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
    ///
    /// V46 folds the private keys into `mls_key_packages` and drops this table, so the test stops at
    /// V45 and checks the table directly, binding the key the way the entity did while the table
    /// existed.
    #[test]
    fn v31_meta_migration_repairs_v12_hpke_private_key_keys() {
        const PK: &[u8] = b"an HPKE public key predating V12";
        const SK: &[u8] = b"the secret key which belongs with it";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate_to(path, &key, 11, MigrationTarget::Version(45), |conn| {
                conn.execute("INSERT INTO mls_hpke_private_keys (pk, sk) VALUES (?, ?)", (PK, SK))
                    .expect("inserting a pre-V12 HPKE private key");
            })
            .await;
            let conn = db.conn().await;

            let count: u32 = conn
                .query_row("SELECT count(*) FROM mls_hpke_private_keys", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1, "the migration must not lose the private key");

            let encoding = stored_key_encoding(&conn, "mls_hpke_private_keys", "pk_sha256");
            let found: bool = conn
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM mls_hpke_private_keys WHERE pk_sha256 = ?)",
                    [Sha256Hash::hash_from(PK)],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                found,
                "a migrated HPKE private key must be findable by the hash of its public key, but `pk_sha256` is \
                 stored as {encoding:?} while `Sha256Hash` binds 32 raw bytes"
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
        let credential = MlsCredential::new_basic(b"a session id".to_vec())
            .tls_serialize_detached()
            .unwrap();
        let credential_type = u16::from(MlsCredential::new_basic(Vec::new()).credential_type());

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 19, |conn| {
                conn.execute(
                    "INSERT INTO mls_credentials (session_id, credential, ciphersuite, public_key, private_key) \
                     VALUES (?, ?, ?, ?, ?)",
                    (
                        b"a session id".as_slice(),
                        credential.as_slice(),
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
                StoredCredential::get(
                    &conn,
                    &crate::entities::StoredCredentialPk::new(
                        Sha256Hash::hash_from(PUBLIC_KEY),
                        credential_type,
                        StoredCredential::NOT_BEFORE_WITHOUT_CERTIFICATE,
                    ),
                )
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
            // V46 folds `mls_hpke_private_keys` into `mls_key_packages` and drops it, so stop at V45 to
            // check every table V31 repaired.
            let db = Database::open_at_schema_version(path, &new_key, MigrationTarget::Version(45))
                .await
                .unwrap();
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

    /// V39 unifies `mls_groups`/`mls_pending_groups`, but can't populate `epoch`, `ciphersuite`,
    /// `own_leaf_index`, `credential_id`, or `credential_type` in SQL: those values only exist
    /// inside the postcard-serialized `MlsGroup` in `state`. The v39 meta migration backfills them
    /// by deserializing `state` in Rust; this test pins that backfill against an independent parse
    /// of the same `state` blob, using the one real group the bundled legacy dump carries.
    #[test]
    fn v39_meta_migration_backfills_group_columns_from_state() {
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

            struct BackfilledGroupRow {
                state: Vec<u8>,
                epoch: Option<i64>,
                ciphersuite: Option<u16>,
                own_leaf_index: Option<u32>,
                credential_id: Option<Vec<u8>>,
                credential_type: Option<u16>,
                is_pending: bool,
            }

            let BackfilledGroupRow {
                state,
                epoch,
                ciphersuite,
                own_leaf_index,
                credential_id,
                credential_type,
                is_pending,
            } = conn
                .query_row(
                    "SELECT state, epoch, ciphersuite, own_leaf_index, credential_id, credential_type, is_pending FROM mls_groups",
                    [],
                    |row| {
                        Ok(BackfilledGroupRow {
                            state: row.get(0)?,
                            epoch: row.get(1)?,
                            ciphersuite: row.get(2)?,
                            own_leaf_index: row.get(3)?,
                            credential_id: row.get(4)?,
                            credential_type: row.get(5)?,
                            is_pending: row.get(6)?,
                        })
                    },
                )
                .expect("the bundled database carries exactly one real mls group");

            assert!(
                !is_pending,
                "a row copied from mls_groups, not mls_pending_groups, must not be marked pending"
            );

            // parsed independently of the meta migration's own implementation, so this pins the
            // backfill against the state blob rather than against itself
            let group =
                crate::deser::<openmls::group::MlsGroup>(&state).expect("the bundled group's state must deserialize");

            assert_eq!(epoch, Some(group.epoch().as_u64() as i64));
            assert_eq!(ciphersuite, Some(group.ciphersuite() as u16));
            assert_eq!(own_leaf_index, Some(group.own_leaf_index().u32()));

            let own_leaf = group.own_leaf().expect("the bundled group must have an own leaf node");
            let expected_credential_id = Sha256Hash::hash_from(own_leaf.signature_key().as_slice());
            let expected_credential_type: u16 = own_leaf.credential().credential_type().into();
            assert_eq!(credential_id, Some(expected_credential_id.as_ref().to_vec()));
            assert_eq!(credential_type, Some(expected_credential_type));

            // and the backfilled (credential_id, credential_type) pair must actually resolve to a
            // stored credential, since that's the whole point of the columns
            let credential_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM mls_credentials WHERE public_key_sha256 = ? AND credential_type = ?)",
                    rusqlite::params![expected_credential_id, expected_credential_type],
                    |row| row.get(0),
                )
                .expect("checking for the credential");
            assert!(
                credential_exists,
                "(credential_id, credential_type) must reference a credential which is actually in mls_credentials"
            );
        });
    }

    /// V41 carries a live conversation's epoch keypairs across the table rebuild and leaves orphaned
    /// ones behind.
    ///
    /// Until V41 nothing reliably deleted an `epoch_encryption_keypairs` row, so a keystore which has wiped
    /// an active conversation still holds that conversation's HPKE private keys. V41's foreign key stops
    /// more of them accumulating; the `WHERE conversation_id IN (SELECT id FROM mls_groups)` on its copy
    /// is what disposes of the ones already there, because a row the new constraint cannot accept must
    /// not be carried into the rebuilt table.
    ///
    /// The live conversation is seeded with two rows at different leaf indices. Only one of them can be
    /// the conversation's current leaf, so this also pins that the filter selects by conversation rather
    /// than by the full primary key: key material we still need is kept wherever it sits in the table.
    #[test]
    fn v41_keeps_a_live_conversations_epoch_keypairs_and_discards_orphaned_ones() {
        const LIVE_CONVERSATION: &[u8] = b"a conversation which still exists when V41 runs";
        const WIPED_CONVERSATION: &[u8] = b"a conversation wiped while nothing cleaned up after it";
        const CREDENTIAL_ID: &[u8] = b"the credential the live conversation was created with";
        const CREDENTIAL_TYPE: u16 = 1;

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 40, |conn| {
                // V40 made `mls_groups.credential_id` a foreign key onto `mls_credentials`, so the
                // credential has to exist before the conversation which refers to it.
                conn.execute(
                    "INSERT INTO mls_credentials
                        (public_key_sha256, credential_type, public_key, session_id, credential, ciphersuite,
                         private_key)
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        CREDENTIAL_ID,
                        CREDENTIAL_TYPE,
                        b"public key".as_slice(),
                        b"session id".as_slice(),
                        b"credential".as_slice(),
                        1,
                        b"private key".as_slice(),
                    ),
                )
                .expect("inserting the credential the live conversation refers to");
                conn.execute(
                    "INSERT INTO mls_groups
                        (id, state, epoch, ciphersuite, credential_id, credential_type, own_leaf_index, is_pending)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        LIVE_CONVERSATION,
                        b"group state".as_slice(),
                        2,
                        1,
                        CREDENTIAL_ID,
                        CREDENTIAL_TYPE,
                        3,
                        false,
                    ),
                )
                .expect("inserting the live conversation");

                // The pre-V41 table has no foreign key, so the wiped conversation's row inserts just as
                // readily as the live conversation's.
                for (conversation_id, own_leaf_index, epoch, keypairs) in [
                    (
                        LIVE_CONVERSATION,
                        3,
                        2,
                        b"keypairs at the live conversation's current leaf".as_slice(),
                    ),
                    (
                        LIVE_CONVERSATION,
                        0,
                        1,
                        b"keypairs left at a leaf index we have since moved off".as_slice(),
                    ),
                    (
                        WIPED_CONVERSATION,
                        0,
                        1,
                        b"keypairs of a conversation the user asked us to destroy".as_slice(),
                    ),
                ] {
                    conn.execute(
                        "INSERT INTO epoch_encryption_keypairs (conversation_id, own_leaf_index, epoch, keypairs)
                         VALUES (?, ?, ?, ?)",
                        (conversation_id, own_leaf_index, epoch, keypairs),
                    )
                    .expect("inserting an epoch keypair row");
                }
            })
            .await;
            let conn = db.conn().await;

            let mut migrated = StoredEpochEncryptionKeypair::load_all(&conn).expect("loading migrated keypairs");
            migrated.sort_by_key(|keypair| keypair.epoch);
            let migrated = migrated
                .iter()
                .map(|keypair| {
                    (
                        keypair.conversation_id.bytes(),
                        keypair.own_leaf_idx,
                        keypair.epoch,
                        keypair.keypairs.as_slice(),
                    )
                })
                .collect::<Vec<_>>();

            assert_eq!(
                migrated,
                [
                    (
                        LIVE_CONVERSATION,
                        0,
                        1,
                        b"keypairs left at a leaf index we have since moved off".as_slice()
                    ),
                    (
                        LIVE_CONVERSATION,
                        3,
                        2,
                        b"keypairs at the live conversation's current leaf".as_slice()
                    ),
                ],
                "V41 must carry every row of a live conversation across intact, and keep nothing belonging \
                 to a conversation which no longer has a group"
            );
        });
    }

    /// V45, its meta migration, and V46 together move each key package's key material into its own row, and make
    /// that row cascade from its credential.
    ///
    /// This runs over the bundled v10002003 dump, whose key packages are real, with a few rows altered at V44 to
    /// exercise each case the meta migration handles. Every expected value is derived here by parsing the key
    /// packages independently, not by trusting the columns under test.
    #[test]
    fn v45_through_v46_move_key_package_key_material_into_mls_key_packages() {
        use std::collections::HashMap;

        use openmls::prelude::KeyPackage;

        const UNPARSEABLE_REF: &[u8] = b"ref of a key package which does not deserialize";
        const UNPARSEABLE_KEY_PACKAGE: &[u8] = b"not a serialized key package";
        const UNRELATED_LEAF_PK: &[u8] = b"public half of a leaf key no key package owns";
        const UNRELATED_LEAF_SK: &[u8] = b"secret half of a leaf key no key package owns";

        fn parse(key_package: &[u8]) -> KeyPackage {
            crate::deser(key_package).expect("the bundled key packages deserialize")
        }
        fn credential_of(key_package: &KeyPackage) -> (Sha256Hash, u16) {
            let leaf_node = key_package.leaf_node();
            (
                Sha256Hash::hash_from(leaf_node.signature_key().as_slice()),
                leaf_node.credential().credential_type().into(),
            )
        }
        fn init_key_hash(key_package: &KeyPackage) -> Sha256Hash {
            Sha256Hash::hash_from(key_package.hpke_init_key().as_slice())
        }
        fn leaf_key_hash(key_package: &KeyPackage) -> Sha256Hash {
            Sha256Hash::hash_from(key_package.leaf_node().encryption_key().as_slice())
        }
        fn leaf_keypair_exists(conn: &rusqlite::Connection, leaf_key_hash: Sha256Hash) -> bool {
            conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM mls_encryption_keypairs WHERE pk_sha256 = ?)",
                [leaf_key_hash],
                |row| row.get(0),
            )
            .unwrap()
        }

        let mut db_file = NamedTempFile::new().unwrap();
        db_file.write_all(DB).unwrap();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");
        let key = DatabaseKey::generate();
        smol::block_on(migrate_db_key_type_to_bytes(path, OLD_KEY, &key)).unwrap();

        smol::block_on(async {
            // Before V45: record what each key package should end up with, then alter a few rows.
            let (original_count, init_private_keys, missing_init_key, missing_credential, missing_leaf_keypair) = {
                let db = Database::open_at_schema_version(path, &key, MigrationTarget::Version(44))
                    .await
                    .unwrap();
                let conn = db.conn().await;

                let key_packages: Vec<(Vec<u8>, Vec<u8>)> = conn
                    .prepare("SELECT key_package_ref, key_package FROM mls_key_packages ORDER BY key_package_ref")
                    .unwrap()
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                assert!(
                    key_packages.len() > 3,
                    "the bundled database needs a few key packages to spare for the altered rows"
                );

                let init_private_keys: HashMap<Vec<u8>, Vec<u8>> = conn
                    .prepare("SELECT pk_sha256, sk FROM mls_hpke_private_keys")
                    .unwrap()
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();

                // a key package which no longer deserializes
                conn.execute(
                    "INSERT INTO mls_key_packages (key_package_ref, key_package) VALUES (?, ?)",
                    (UNPARSEABLE_REF, UNPARSEABLE_KEY_PACKAGE),
                )
                .unwrap();

                // a key package whose init private key has gone missing
                let (missing_init_key_ref, key_package) = &key_packages[0];
                let missing_init_key = parse(key_package);
                conn.execute(
                    "DELETE FROM mls_hpke_private_keys WHERE pk_sha256 = ?",
                    [init_key_hash(&missing_init_key)],
                )
                .unwrap();

                // A key package whose credential the keystore never held. Rewriting its signature key in place
                // leaves it deserializable, because nothing on the way checks the signature.
                let (missing_credential_ref, key_package) = &key_packages[1];
                let original = parse(key_package);
                let signature_key = original.leaf_node().signature_key().as_slice();
                let mut occurrences = key_package
                    .windows(signature_key.len())
                    .enumerate()
                    .filter(|(_, window)| *window == signature_key)
                    .map(|(position, _)| position);
                let position = occurrences
                    .next()
                    .expect("the signature key is in the serialized key package");
                assert!(
                    occurrences.next().is_none(),
                    "the signature key must appear exactly once to be rewritten safely"
                );
                let mut altered = key_package.clone();
                for byte in &mut altered[position..position + signature_key.len()] {
                    *byte ^= 0xff;
                }
                let missing_credential = parse(&altered);
                assert_ne!(credential_of(&missing_credential), credential_of(&original));
                assert_eq!(leaf_key_hash(&missing_credential), leaf_key_hash(&original));
                conn.execute(
                    "UPDATE mls_key_packages SET key_package = ? WHERE key_package_ref = ?",
                    (&altered, missing_credential_ref),
                )
                .unwrap();

                // a key package whose leaf keypair has gone missing
                let (missing_leaf_keypair_ref, key_package) = &key_packages[2];
                conn.execute(
                    "DELETE FROM mls_encryption_keypairs WHERE pk_sha256 = ?",
                    [leaf_key_hash(&parse(key_package))],
                )
                .unwrap();

                // a leaf keypair no key package owns, standing in for the leaf key of a pending group update
                conn.execute(
                    "INSERT INTO mls_encryption_keypairs (pk_sha256, pk, sk) VALUES (?, ?, ?)",
                    (
                        Sha256Hash::hash_from(UNRELATED_LEAF_PK),
                        UNRELATED_LEAF_PK,
                        UNRELATED_LEAF_SK,
                    ),
                )
                .unwrap();

                (
                    key_packages.len(),
                    init_private_keys,
                    (missing_init_key_ref.clone(), missing_init_key),
                    (missing_credential_ref.clone(), missing_credential),
                    missing_leaf_keypair_ref.clone(),
                )
            };

            let db = Database::open_at_schema_version(path, &key, MigrationTarget::Version(46))
                .await
                .unwrap();
            let conn = db.conn().await;

            let hpke_table_exists: bool = conn
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mls_hpke_private_keys')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(!hpke_table_exists, "V46 retires `mls_hpke_private_keys`");

            struct MigratedKeyPackage {
                key_package_ref: Vec<u8>,
                key_package: Vec<u8>,
                credential_id: Sha256Hash,
                credential_type: u16,
                hpke_init_public_key_hash: Sha256Hash,
                hpke_init_private_key: Vec<u8>,
                leaf_encryption_key_hash: Sha256Hash,
            }
            let migrated: Vec<MigratedKeyPackage> = conn
                .prepare(
                    "SELECT key_package_ref, key_package, credential_id, credential_type,
                        hpke_init_public_key_hash, hpke_init_private_key, leaf_encryption_key_hash
                    FROM mls_key_packages",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok(MigratedKeyPackage {
                        key_package_ref: row.get(0)?,
                        key_package: row.get(1)?,
                        credential_id: row.get(2)?,
                        credential_type: row.get(3)?,
                        hpke_init_public_key_hash: row.get(4)?,
                        hpke_init_private_key: row.get(5)?,
                        leaf_encryption_key_hash: row.get(6)?,
                    })
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();

            let has_ref = |key_package_ref: &[u8]| migrated.iter().any(|row| row.key_package_ref == key_package_ref);
            assert!(
                !has_ref(UNPARSEABLE_REF),
                "a key package which does not deserialize is dropped"
            );
            assert!(
                !has_ref(&missing_init_key.0),
                "a key package without its init private key is dropped"
            );
            assert!(
                !has_ref(&missing_credential.0),
                "a key package without its credential is dropped"
            );
            assert!(
                has_ref(&missing_leaf_keypair),
                "a missing leaf keypair alone is not reason enough to drop a key package"
            );
            assert_eq!(migrated.len(), original_count - 2, "every other key package survives");

            for row in &migrated {
                let key_package = parse(&row.key_package);
                assert_eq!(
                    (row.credential_id, row.credential_type),
                    credential_of(&key_package),
                    "the credential columns name the key package's own credential"
                );
                assert_eq!(row.hpke_init_public_key_hash, init_key_hash(&key_package));
                assert_eq!(row.leaf_encryption_key_hash, leaf_key_hash(&key_package));
                assert_eq!(
                    Some(&row.hpke_init_private_key),
                    init_private_keys.get(init_key_hash(&key_package).as_ref()),
                    "the init private key is carried over from `mls_hpke_private_keys`"
                );
            }

            // A dropped key package takes its leaf keypair with it, while a leaf keypair which belongs to no
            // key package is left alone.
            assert!(!leaf_keypair_exists(&conn, leaf_key_hash(&missing_init_key.1)));
            assert!(!leaf_keypair_exists(&conn, leaf_key_hash(&missing_credential.1)));
            assert!(leaf_keypair_exists(&conn, Sha256Hash::hash_from(UNRELATED_LEAF_PK)));

            // Deleting the credential now takes its key packages, and their leaf keypairs, with it. The bundled
            // conversation still uses that credential, which restricts deleting it, so the conversation goes first.
            conn.execute("DELETE FROM mls_groups", []).unwrap();
            conn.execute("DELETE FROM mls_credentials", []).unwrap();
            let remaining_key_packages: u32 = conn
                .query_row("SELECT count(*) FROM mls_key_packages", [], |row| row.get(0))
                .unwrap();
            assert_eq!(remaining_key_packages, 0, "key packages cascade from their credential");
            let remaining_leaf_keypairs: Vec<Vec<u8>> = conn
                .prepare("SELECT pk FROM mls_encryption_keypairs")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(
                remaining_leaf_keypairs,
                [UNRELATED_LEAF_PK],
                "every key package's leaf keypair goes with it, and nothing else does"
            );
        });
    }

    const BASIC: u16 = 1;
    const X509: u16 = 2;

    /// Every foreign key violation in the database, as `(child table, child rowid, parent table)`.
    ///
    /// This errors with "foreign key mismatch" if a foreign key targets columns which are neither the
    /// parent's primary key nor covered by a unique index.
    fn foreign_key_violations(conn: &rusqlite::Connection) -> Vec<(String, Option<i64>, String)> {
        conn.prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .expect("checking foreign keys")
    }

    fn row_count(conn: &rusqlite::Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .unwrap()
    }

    /// `created_at` of every credential with this public key and type, in seconds since the epoch.
    fn credential_created_at(conn: &rusqlite::Connection, public_key: &[u8], credential_type: u16) -> Vec<u64> {
        conn.prepare(
            "SELECT unixepoch(created_at) FROM mls_credentials \
             WHERE public_key_sha256 = ?1 AND credential_type = ?2 ORDER BY created_at",
        )
        .unwrap()
        .query_map((Sha256Hash::hash_from(public_key), credential_type), |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// `not_before`, the last primary key column, of every credential with this public key and type.
    fn credential_not_before(conn: &rusqlite::Connection, public_key: &[u8], credential_type: u16) -> Vec<u64> {
        conn.prepare(
            "SELECT not_before FROM mls_credentials \
             WHERE public_key_sha256 = ?1 AND credential_type = ?2 ORDER BY not_before",
        )
        .unwrap()
        .query_map((Sha256Hash::hash_from(public_key), credential_type), |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Insert a credential into the schema as of V48.
    fn insert_v48_credential(
        conn: &rusqlite::Connection,
        public_key: &[u8],
        credential_type: u16,
        credential: &[u8],
        created_at: u64,
    ) {
        conn.execute(
            "INSERT INTO mls_credentials \
             (public_key_sha256, credential_type, public_key, session_id, credential, created_at, ciphersuite, private_key) \
             VALUES (?1, ?2, ?3, ?4, ?5, datetime(?6, 'unixepoch'), ?7, ?8)",
            rusqlite::params![
                Sha256Hash::hash_from(public_key),
                credential_type,
                public_key,
                CLIENT_ID,
                credential,
                created_at,
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 as u16,
                b"a private key".as_slice(),
            ],
        )
        .expect("inserting a V48 credential");
    }

    /// Every table with a foreign key onto `mls_credentials` must reference its whole primary key.
    ///
    /// SQLite only accepts a foreign key whose parent columns are the primary key or carry a unique
    /// index. A foreign key left on `(public_key_sha256, credential_type)` once `created_at` joins the
    /// primary key is not rejected when the schema is created, only later, when a write touches it.
    #[test]
    fn credential_foreign_keys_reference_the_full_primary_key() {
        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = Database::open_at_schema_version(path, &key, MigrationTarget::Latest)
                .await
                .unwrap();
            let conn = db.conn().await;

            let mut primary_key: Vec<String> = conn
                .prepare("SELECT name FROM pragma_table_info('mls_credentials') WHERE pk > 0")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            primary_key.sort();

            let referencing: Vec<(String, i64, String)> = conn
                .prepare(
                    "SELECT m.name, fk.id, fk.\"to\" \
                     FROM sqlite_master AS m, pragma_foreign_key_list(m.name) AS fk \
                     WHERE m.type = 'table' AND fk.\"table\" = 'mls_credentials'",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();

            let mut by_foreign_key = std::collections::BTreeMap::<(String, i64), Vec<String>>::new();
            for (table, id, column) in referencing {
                by_foreign_key.entry((table, id)).or_default().push(column);
            }
            assert!(
                by_foreign_key.keys().any(|(table, _)| table == "mls_groups")
                    && by_foreign_key.keys().any(|(table, _)| table == "mls_key_packages"),
                "groups and key packages must both reference their credential, found {by_foreign_key:?}"
            );
            for ((table, _), mut columns) in by_foreign_key {
                columns.sort();
                assert_eq!(
                    columns, primary_key,
                    "{table}'s foreign key onto mls_credentials must cover its whole primary key"
                );
            }
        });
    }

    /// An X509 credential is keyed by its leaf certificate's `not_before`, which the migration has to
    /// read from the certificate itself: releases before v11.0.0 stored the insertion time in
    /// `created_at` instead. The migration also has to correct `created_at`, which is the
    /// credential's earliest validity. A credential ref built from it would otherwise point at a key
    /// no row has. Anything referencing the credential must still resolve to it afterwards.
    #[test]
    fn x509_credential_is_keyed_by_the_certificate_not_before() {
        const INSERTION_TIME: u64 = 1_700_000_100;
        const CONVERSATION_ID: &[u8] = b"a conversation using the X509 credential";
        const KEY_PACKAGE_REF: &[u8] = b"a key package generated from the X509 credential";

        let certificate = x509_cert::Certificate::from_pem(CERTIFICATE_PEM).unwrap();
        let not_before = certificate
            .tbs_certificate()
            .validity()
            .not_before
            .to_unix_duration()
            .as_secs();
        assert_ne!(
            not_before, INSERTION_TIME,
            "the key must visibly come from the certificate, not from created_at"
        );
        let public_key = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let x509_credential = MlsCredential::new_x509(vec![certificate.to_der().unwrap()])
            .unwrap()
            .tls_serialize_detached()
            .unwrap();

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 48, |conn| {
                insert_v48_credential(conn, &public_key, X509, &x509_credential, INSERTION_TIME);
                conn.execute(
                    "INSERT INTO mls_groups \
                     (id, state, epoch, ciphersuite, credential_id, credential_type, own_leaf_index, is_pending) \
                     VALUES (?1, ?2, 1, ?3, ?4, ?5, 0, 0)",
                    rusqlite::params![
                        CONVERSATION_ID,
                        b"opaque group state".as_slice(),
                        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 as u16,
                        Sha256Hash::hash_from(&public_key),
                        X509,
                    ],
                )
                .expect("inserting a group");
                conn.execute(
                    "INSERT INTO mls_key_packages \
                     (key_package_ref, key_package, credential_id, credential_type, hpke_init_public_key_hash, \
                      leaf_encryption_key_hash) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        KEY_PACKAGE_REF,
                        b"opaque key package".as_slice(),
                        Sha256Hash::hash_from(&public_key),
                        X509,
                        Sha256Hash::hash_from(b"an hpke init key"),
                        Sha256Hash::hash_from(b"a leaf encryption key"),
                    ],
                )
                .expect("inserting a key package");
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(credential_not_before(&conn, &public_key, X509), [not_before]);
            assert_eq!(
                credential_created_at(&conn, &public_key, X509),
                [not_before],
                "created_at must be corrected to the certificate's not_before"
            );
            assert_eq!(row_count(&conn, "mls_groups"), 1, "the group must survive");
            assert_eq!(row_count(&conn, "mls_key_packages"), 1, "the key package must survive");
            assert_eq!(foreign_key_violations(&conn), []);
        });
    }

    /// An X509 credential whose certificate can't be parsed has no `not_before` to key it by. It was
    /// never loadable anyway, so the migration drops it rather than failing.
    #[test]
    fn migration_drops_an_x509_credential_whose_certificate_does_not_parse() {
        const PUBLIC_KEY: &[u8] = b"public key of a credential with a broken certificate";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 48, |conn| {
                insert_v48_credential(conn, PUBLIC_KEY, X509, b"not a serialized credential", 1_700_000_000);
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(credential_created_at(&conn, PUBLIC_KEY, X509), [] as [u64; 0]);
        });
    }

    /// A group whose X509 credential can't be parsed can't be loaded either: there is no credential
    /// to sign with. As in V39, the migration drops such a group along with the credential instead of
    /// failing, and whatever hangs off either of them goes too. Nothing else is touched.
    #[test]
    fn migration_drops_groups_using_an_x509_credential_whose_certificate_does_not_parse() {
        const BROKEN_PUBLIC_KEY: &[u8] = b"public key of a credential with a broken certificate";
        const BROKEN_CONVERSATION: &[u8] = b"a conversation using the broken credential";
        const BROKEN_KEY_PACKAGE: &[u8] = b"a key package generated from the broken credential";
        const HEALTHY_PUBLIC_KEY: &[u8] = b"public key of a basic credential";
        const HEALTHY_CONVERSATION: &[u8] = b"a conversation using the basic credential";

        fn insert_group(conn: &rusqlite::Connection, id: &[u8], public_key: &[u8], credential_type: u16) {
            conn.execute(
                "INSERT INTO mls_groups \
                 (id, state, epoch, ciphersuite, credential_id, credential_type, own_leaf_index, is_pending) \
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, 0, 0)",
                rusqlite::params![
                    id,
                    b"opaque group state".as_slice(),
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 as u16,
                    Sha256Hash::hash_from(public_key),
                    credential_type,
                ],
            )
            .expect("inserting a group");
            conn.execute(
                "INSERT INTO mls_buffered_commits (conversation_id, commit_data) VALUES (?1, ?2)",
                (id, b"a buffered commit".as_slice()),
            )
            .expect("inserting a buffered commit");
        }

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate_to(path, &key, 48, MigrationTarget::Version(50), |conn| {
                insert_v48_credential(
                    conn,
                    BROKEN_PUBLIC_KEY,
                    X509,
                    b"not a serialized credential",
                    1_700_000_000,
                );
                insert_group(conn, BROKEN_CONVERSATION, BROKEN_PUBLIC_KEY, X509);
                conn.execute(
                    "INSERT INTO mls_key_packages \
                     (key_package_ref, key_package, credential_id, credential_type, hpke_init_public_key_hash, \
                      leaf_encryption_key_hash) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        BROKEN_KEY_PACKAGE,
                        b"opaque key package".as_slice(),
                        Sha256Hash::hash_from(BROKEN_PUBLIC_KEY),
                        X509,
                        Sha256Hash::hash_from(b"an hpke init key"),
                        Sha256Hash::hash_from(b"a leaf encryption key"),
                    ],
                )
                .expect("inserting a key package");

                insert_v48_credential(conn, HEALTHY_PUBLIC_KEY, BASIC, b"a basic credential", 1_700_000_000);
                insert_group(conn, HEALTHY_CONVERSATION, HEALTHY_PUBLIC_KEY, BASIC);
            })
            .await;
            let conn = db.conn().await;

            let ids = |table: &str, column: &str| -> Vec<Vec<u8>> {
                conn.prepare(&format!("SELECT {column} FROM {table}"))
                    .unwrap()
                    .query_map([], |row| row.get(0))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap()
            };
            assert_eq!(credential_created_at(&conn, BROKEN_PUBLIC_KEY, X509), [] as [u64; 0]);
            assert_eq!(ids("mls_groups", "id"), [HEALTHY_CONVERSATION]);
            assert_eq!(ids("mls_buffered_commits", "conversation_id"), [HEALTHY_CONVERSATION]);
            assert_eq!(row_count(&conn, "mls_key_packages"), 0);
            assert_eq!(credential_created_at(&conn, HEALTHY_PUBLIC_KEY, BASIC), [1_700_000_000]);
            assert_eq!(foreign_key_violations(&conn), []);
        });
    }

    /// A basic credential has no certificate, so its `created_at` is all there is. The migration must
    /// leave it, and the credential bytes, exactly as they were.
    #[test]
    fn migration_keeps_a_basic_credentials_created_at() {
        const PUBLIC_KEY: &[u8] = b"public key of a basic credential";
        const CREDENTIAL: &[u8] = b"a basic credential, never parsed by the migration";
        const CREATED_AT: u64 = 1_700_000_000;

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 48, |conn| {
                insert_v48_credential(conn, PUBLIC_KEY, BASIC, CREDENTIAL, CREATED_AT);
            })
            .await;
            let conn = db.conn().await;

            assert_eq!(credential_created_at(&conn, PUBLIC_KEY, BASIC), [CREATED_AT]);
            assert_eq!(credential_not_before(&conn, PUBLIC_KEY, BASIC), [0]);
            let credential: Vec<u8> = conn
                .query_row("SELECT credential FROM mls_credentials", [], |row| row.get(0))
                .unwrap();
            assert_eq!(credential, CREDENTIAL);
        });
    }

    /// `created_at` has always been nullable, and V48 doesn't stop a basic credential from holding a
    /// `NULL` there. The new primary key doesn't involve `created_at`, so such a credential must come
    /// through the rebuild like any other, keyed by a `not_before` of 0.
    #[test]
    fn migration_keeps_a_basic_credential_without_created_at() {
        const PUBLIC_KEY: &[u8] = b"public key of a basic credential stored without created_at";
        const CREDENTIAL: &[u8] = b"a basic credential, never parsed by the migration";

        let (db_file, key) = temp_db();
        let path = db_file.path().to_str().unwrap();

        smol::block_on(async {
            let db = seed_then_migrate(path, &key, 48, |conn| {
                insert_v48_credential(conn, PUBLIC_KEY, BASIC, CREDENTIAL, 0);
                conn.execute("UPDATE mls_credentials SET created_at = NULL", [])
                    .expect("clearing created_at");
            })
            .await;
            let conn = db.conn().await;

            let (credential, not_before): (Vec<u8>, u64) = conn
                .query_row(
                    "SELECT credential, not_before FROM mls_credentials \
                     WHERE public_key_sha256 = ?1 AND credential_type = ?2",
                    (Sha256Hash::hash_from(PUBLIC_KEY), BASIC),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("the basic credential must survive the migration");
            assert_eq!(credential, CREDENTIAL);
            assert_eq!(not_before, 0);
        });
    }

    /// Rebuilding `mls_credentials` must not touch what references it. With foreign keys on, dropping
    /// the old table would cascade onto every key package and be refused by every group, so this
    /// shows the rebuild really runs with them off and leaves every reference intact.
    ///
    /// The bundled database carries one basic credential, one group and 99 key packages using it.
    #[test]
    fn credential_rebuild_keeps_every_reference_in_a_real_database() {
        let mut db_file = NamedTempFile::new().unwrap();
        db_file.write_all(DB).unwrap();
        let path = db_file
            .path()
            .to_str()
            .expect("tmpfile path is representable in unicode");

        let new_key = DatabaseKey::generate();
        smol::block_on(migrate_db_key_type_to_bytes(path, OLD_KEY, &new_key)).unwrap();

        smol::block_on(async {
            let tables = ["mls_credentials", "mls_groups", "mls_key_packages"];
            let (before, basic_created_at): (Vec<i64>, Vec<(Vec<u8>, u64)>) = {
                let db = Database::open_at_schema_version(path, &new_key, MigrationTarget::Version(48))
                    .await
                    .unwrap();
                let conn = db.conn().await;
                let created_at = conn
                    .prepare("SELECT public_key, unixepoch(created_at) FROM mls_credentials WHERE credential_type = ?1")
                    .unwrap()
                    .query_map([BASIC], |row| Ok((row.get(0)?, row.get(1)?)))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                (tables.map(|table| row_count(&conn, table)).to_vec(), created_at)
            };
            assert!(
                before.iter().all(|&count| count > 0),
                "the bundled database must have rows in {tables:?}, found {before:?}"
            );

            let db = Database::open_at_schema_version(path, &new_key, MigrationTarget::Latest)
                .await
                .unwrap();
            let conn = db.conn().await;

            let after = tables.map(|table| row_count(&conn, table)).to_vec();
            assert_eq!(after, before, "row counts of {tables:?}");
            assert_eq!(foreign_key_violations(&conn), []);
            for (public_key, created_at) in basic_created_at {
                assert_eq!(credential_created_at(&conn, &public_key, BASIC), [created_at]);
                assert_eq!(credential_not_before(&conn, &public_key, BASIC), [0]);
            }
        });
    }

    /// The V51 meta migration moves buffered messages into the inbox, and V52 drops the tables they came from.
    ///
    /// The old tables don't record why a message waits, so V51 works it out from each message's header and the state
    /// of its group. Only the plaintext headers are parsed, so these tests build messages by hand instead of needing a
    /// crypto provider.
    mod v51_inbox {
        use openmls::prelude::ContentType;
        use rstest::rstest;

        use super::{seed_then_migrate, temp_db};
        use crate::{
            Sha256Hash,
            entities::{InboxMessage, WaitingFor},
            migrations::test_helpers::{
                EMPTY_COMMIT, private_message, private_message_with_ciphertext, public_message, targeted_message,
                transient_message,
            },
            traits::Entity as _,
        };

        const CONVERSATION_ID: &[u8] = b"a conversation which buffered a message before V51";
        const CREDENTIAL_ID: &[u8] = b"the credential the conversation was created with";
        const CREDENTIAL_TYPE: u16 = 1;
        const TARGETED_WIRE_FORMAT: u16 = 0xF001;

        /// Which of the pre-V51 tables a seeded message goes into.
        #[derive(Debug, Clone, Copy)]
        enum Table {
            PendingMessages,
            BufferedCommits,
        }

        /// Seed the conversation [`CONVERSATION_ID`] at `epoch`, and the credential it refers to.
        fn seed_conversation(conn: &rusqlite::Connection, epoch: u64, is_pending: bool) {
            conn.execute(
                "INSERT INTO mls_credentials
                    (public_key_sha256, credential_type, public_key, session_id, credential, ciphersuite, private_key)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    CREDENTIAL_ID,
                    CREDENTIAL_TYPE,
                    b"public key".as_slice(),
                    b"session id".as_slice(),
                    b"credential".as_slice(),
                    1,
                    b"private key".as_slice(),
                ),
            )
            .expect("inserting the credential the conversation refers to");
            conn.execute(
                "INSERT INTO mls_groups
                    (id, state, epoch, ciphersuite, credential_id, credential_type, own_leaf_index, is_pending)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    CONVERSATION_ID,
                    b"group state".as_slice(),
                    epoch,
                    1,
                    CREDENTIAL_ID,
                    CREDENTIAL_TYPE,
                    0,
                    is_pending,
                ),
            )
            .expect("inserting the conversation");
        }

        /// Seed `message` for [`CONVERSATION_ID`] into `table`, as the pre-V51 code wrote it.
        fn seed_message(conn: &rusqlite::Connection, table: Table, message: Option<&[u8]>) {
            match table {
                Table::PendingMessages => {
                    let message = message.expect("pending messages are never null");
                    conn.execute(
                        "INSERT INTO mls_pending_messages (hash_sha256, conversation_id, message) VALUES (?, ?, ?)",
                        (
                            Sha256Hash::hash_from_many([CONVERSATION_ID, message]),
                            CONVERSATION_ID,
                            message,
                        ),
                    )
                    .expect("inserting a pending message");
                }
                Table::BufferedCommits => {
                    conn.execute(
                        "INSERT INTO mls_buffered_commits (conversation_id, commit_data) VALUES (?, ?)",
                        (CONVERSATION_ID, message),
                    )
                    .expect("inserting a buffered commit");
                }
            }
        }

        /// Every inbox message, sorted by arrival.
        fn inbox_messages(conn: &rusqlite::Connection) -> Vec<InboxMessage> {
            let mut inbox_messages = InboxMessage::load_all(conn).expect("loading inbox messages");
            inbox_messages.sort_by_key(|inbox_message| inbox_message.arrival_sequence);
            inbox_messages
        }

        /// V51 works out why each buffered message waits, or drops a message which could never be replayed.
        ///
        /// The conversation is at epoch 3 in every case.
        ///
        /// - A pending conversation's messages all wait for the join, whatever their epoch or type.
        /// - An established conversation's pending messages wait for their epoch if it is still ahead, and are stale
        ///   otherwise.
        /// - An established conversation's buffered commit waits for a proposal if it belongs to the current epoch, and
        ///   could never apply otherwise.
        /// - A message which doesn't parse can't be replayed at all.
        #[rstest]
        #[case::future_epoch(false, Table::PendingMessages, private_message(1, 4), Some((WaitingFor::Epoch, ContentType::Application, 4)))]
        #[case::future_epoch_transient(false, Table::PendingMessages, transient_message(4), Some((WaitingFor::Epoch, ContentType::Application, 4)))]
        #[case::future_epoch_targeted(false, Table::PendingMessages, targeted_message(TARGETED_WIRE_FORMAT, 4), Some((WaitingFor::Epoch, ContentType::Application, 4)))]
        #[case::missing_proposal(false, Table::BufferedCommits, public_message(3, EMPTY_COMMIT, true), Some((WaitingFor::Proposal, ContentType::Commit, 3)))]
        #[case::pending_join_message(true, Table::PendingMessages, private_message(1, 1), Some((WaitingFor::PendingJoin, ContentType::Application, 1)))]
        #[case::pending_join_commit(true, Table::BufferedCommits, public_message(5, EMPTY_COMMIT, true), Some((WaitingFor::PendingJoin, ContentType::Commit, 5)))]
        #[case::pending_message_at_current_epoch(false, Table::PendingMessages, private_message(1, 3), None)]
        #[case::pending_message_at_past_epoch(false, Table::PendingMessages, private_message(1, 2), None)]
        #[case::buffered_commit_at_past_epoch(
            false,
            Table::BufferedCommits,
            public_message(2, EMPTY_COMMIT, true),
            None
        )]
        #[case::buffered_commit_at_future_epoch(
            false,
            Table::BufferedCommits,
            public_message(4, EMPTY_COMMIT, true),
            None
        )]
        #[case::buffered_non_commit(false, Table::BufferedCommits, private_message(1, 3), None)]
        #[case::unparseable_pending_message(false, Table::PendingMessages, b"not a message".to_vec(), None)]
        #[case::unparseable_buffered_commit(false, Table::BufferedCommits, b"not a commit".to_vec(), None)]
        fn v51_classifies_or_drops_each_buffered_message(
            #[case] is_pending: bool,
            #[case] table: Table,
            #[case] message: Vec<u8>,
            #[case] expected: Option<(WaitingFor, ContentType, u64)>,
        ) {
            let (db_file, key) = temp_db();
            let path = db_file.path().to_str().unwrap();

            smol::block_on(async {
                let db = seed_then_migrate(path, &key, 48, |conn| {
                    seed_conversation(conn, 3, is_pending);
                    seed_message(conn, table, Some(&message));
                })
                .await;
                let conn = db.conn().await;

                let migrated = inbox_messages(&conn)
                    .into_iter()
                    .map(|inbox_message| {
                        assert_eq!(inbox_message.conversation_id.bytes(), CONVERSATION_ID);
                        assert_eq!(inbox_message.message, message, "the message bytes must survive exactly");
                        (
                            inbox_message.waiting_for,
                            inbox_message.content_type,
                            inbox_message.epoch,
                        )
                    })
                    .collect::<Vec<_>>();
                assert_eq!(migrated, Vec::from_iter(expected));
            });
        }

        /// V51 drops a buffered commit with no data rather than failing.
        ///
        /// `mls_buffered_commits.commit_data` was nullable, though nothing should have written a null into it. There
        /// is nothing to replay in such a row.
        #[test]
        fn v51_drops_a_buffered_commit_without_data() {
            let (db_file, key) = temp_db();
            let path = db_file.path().to_str().unwrap();

            smol::block_on(async {
                let db = seed_then_migrate(path, &key, 48, |conn| {
                    seed_conversation(conn, 3, false);
                    seed_message(conn, Table::BufferedCommits, None);
                })
                .await;
                let conn = db.conn().await;

                assert!(inbox_messages(&conn).is_empty());
            });
        }

        /// V51 preserves the order in which buffered messages arrived.
        ///
        /// Pending messages keep the order the database held them in, and the buffered commit comes after all of
        /// them. On replay the commit sorts last regardless, being a commit, but the inbox's own order must not
        /// contradict that.
        #[test]
        fn v51_preserves_arrival_order() {
            let pending_messages = [b"first".as_slice(), b"second", b"third"]
                .map(|ciphertext| private_message_with_ciphertext(1, 4, ciphertext));
            let commit = public_message(3, EMPTY_COMMIT, true);

            let (db_file, key) = temp_db();
            let path = db_file.path().to_str().unwrap();

            smol::block_on(async {
                let db = seed_then_migrate(path, &key, 48, |conn| {
                    seed_conversation(conn, 3, false);
                    // seed the commit first, to show that the order comes from the tables, not from insertion
                    seed_message(conn, Table::BufferedCommits, Some(&commit));
                    for message in &pending_messages {
                        seed_message(conn, Table::PendingMessages, Some(message));
                    }
                })
                .await;
                let conn = db.conn().await;

                let migrated = inbox_messages(&conn)
                    .into_iter()
                    .map(|inbox_message| inbox_message.message)
                    .collect::<Vec<_>>();
                let mut expected = pending_messages.to_vec();
                expected.push(commit);
                assert_eq!(migrated, expected);
            });
        }

        /// V51 keeps one copy of a message buffered in both tables.
        ///
        /// A pending conversation can hold the same commit as a pending message and as its buffered commit. Both
        /// copies wait for the join, and the inbox holds each message once per conversation.
        #[test]
        fn v51_keeps_one_copy_of_a_message_in_both_tables() {
            let commit = public_message(3, EMPTY_COMMIT, true);

            let (db_file, key) = temp_db();
            let path = db_file.path().to_str().unwrap();

            smol::block_on(async {
                let db = seed_then_migrate(path, &key, 48, |conn| {
                    seed_conversation(conn, 3, true);
                    seed_message(conn, Table::PendingMessages, Some(&commit));
                    seed_message(conn, Table::BufferedCommits, Some(&commit));
                })
                .await;
                let conn = db.conn().await;

                let migrated = inbox_messages(&conn);
                let [inbox_message] = migrated.as_slice() else {
                    panic!("expected exactly one inbox message, found {}", migrated.len());
                };
                assert_eq!(inbox_message.message, commit);
                assert_eq!(inbox_message.waiting_for, WaitingFor::PendingJoin);
            });
        }
    }
}
