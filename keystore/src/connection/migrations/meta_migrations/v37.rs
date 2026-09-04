use crate::{
    CryptoKeystoreResult,
    migrations::{StoredCredentialV36, credential_type_from_serialized},
    traits::PrimaryKey as _,
};

pub(crate) const VERSION: i32 = 37;

pub(crate) fn meta_migration(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
    let tx = conn.transaction()?;
    let credentials = {
        let mut statement = tx.prepare(
            "SELECT public_key, session_id, credential, unixepoch(created_at) AS created_at, ciphersuite, private_key \
             FROM mls_credentials",
        )?;
        statement
            .query_map([], |row| {
                Ok(StoredCredentialV36 {
                    public_key: row.get("public_key")?,
                    session_id: row.get("session_id")?,
                    credential: row.get("credential")?,
                    created_at: row.get("created_at")?,
                    ciphersuite: row.get("ciphersuite")?,
                    private_key: row.get("private_key")?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?
    };

    for credential in credentials {
        let public_key_sha256 = credential.primary_key();
        let credential_type = credential_type_from_serialized(&credential.credential)?;
        tx.execute(
            "INSERT INTO mls_credentials_new (
                public_key_sha256,
                credential_type,
                public_key,
                session_id,
                credential,
                created_at,
                ciphersuite,
                private_key
             ) VALUES (
                :public_key_sha256,
                :credential_type,
                :public_key,
                :session_id,
                :credential,
                datetime(:created_at, 'unixepoch'),
                :ciphersuite,
                :private_key
             )",
            rusqlite::named_params! {
                ":public_key_sha256": public_key_sha256,
                ":credential_type": credential_type,
                ":public_key": credential.public_key,
                ":session_id": credential.session_id,
                ":credential": credential.credential,
                ":created_at": credential.created_at,
                ":ciphersuite": credential.ciphersuite,
                ":private_key": credential.private_key,
            },
        )?;
    }

    tx.commit()?;
    Ok(())
}
