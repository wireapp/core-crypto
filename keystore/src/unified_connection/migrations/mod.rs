mod meta_migrations;

use refinery::Target;
use rusqlite::functions::FunctionFlags;

use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

refinery::embed_migrations!("src/unified_connection/migrations");

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
        conn.pragma_update(None, "schema_version", updated_version)?;
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
        _ => Ok(()),
    }
}

pub async fn migrate_db_key_type_to_bytes(
    path: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CryptoKeystoreResult<()> {
    let mut conn = rusqlite::Connection::open(path)?;

    conn.pragma_update(None, "key", old_key)?;

    // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
    #[cfg(target_os = "ios")]
    super::ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

    /// This is the latest schema version our test db dump is compatible with.
    const MAX_SUPPORTED_SCHEMA_VERSION: u8 = 15;

    let version = conn.query_row("PRAGMA schema_version;", [], |row| row.get::<_, i32>(0))?;
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

#[cfg(all(test, not(target_os = "unknown")))]
pub(crate) mod test {
    use std::io::Write;

    use openmls::prelude::Ciphersuite;
    use tempfile::NamedTempFile;

    use crate::{
        entities::StoredCredential,
        traits::UnifiedEntity,
        unified_connection::{Database, DatabaseKey, migrate_db_key_type_to_bytes, migrations::MigrationTarget},
    };

    pub(crate) const DB: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crypto-ffi/bindings/jvm/src/test/resources/db-v10002003.sqlite"
    ));
    pub(crate) const OLD_KEY: &str = "secret";

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

            let mut stmt = db
                .conn
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
            db.conn
                .execute(
                    "UPDATE mls_credentials_new SET ciphersuite = ?1",
                    [Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16],
                )
                .expect("updating ciphersuite");

            // Create a duplicate from this credential
            db.conn
                .execute(
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

            let count = db
                .conn
                .query_row("SELECT COUNT(*) FROM mls_credentials_new", [], |row| {
                    row.get::<_, i32>(0)
                })
                .unwrap();

            assert_eq!(count, 2);

            drop(stmt);
            drop(db);

            let db = Database::open(path, &new_key).await.unwrap();
            let deduplicated_credentials = StoredCredential::load_all(&db.conn).expect("deduplicated credentials");

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
}
