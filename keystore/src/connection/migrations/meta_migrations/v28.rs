use rusqlite::OptionalExtension;
use x509_cert::der::Decode;

use crate::CryptoKeystoreError;
use crate::CryptoKeystoreResult;

pub(crate) const VERSION: i32 = 28;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;

    // This used to be a unique entity so we only get the first entry if it exists
    let content: Option<Vec<u8>> = tx
        .query_row("SELECT content FROM e2ei_acme_ca", [], |row| row.get(0))
        .optional()?;

    if let Some(content) = content {
        let cert = x509_cert::Certificate::from_der(&content)
            .map_err(|e| CryptoKeystoreError::MigrationFailed(e.to_string()))?;

        // This is the primary key
        let fingerprint = cert
            .tbs_certificate
            .subject_public_key_info
            .fingerprint_bytes()
            .map_err(|e| CryptoKeystoreError::MigrationFailed(e.to_string()))?
            .to_vec();

        tx.execute(
            "INSERT INTO x509_trust_anchor (fingerprint, content) VALUES (?1, ?2)",
            rusqlite::params![fingerprint, content,],
        )?;
    }
    tx.commit()?;

    Ok(())
}
