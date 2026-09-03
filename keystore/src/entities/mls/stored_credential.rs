use zeroize::Zeroize;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Sha256Hash, Transactionlike,
    entities::helpers::delete_helper_composite_key,
    traits::{Entity, PrimaryKey},
};

/// This type exists so that we can efficiently search for credentials by a variety of metrics at the database level.
///
/// This includes some but not all of the fields in `core_crypto::CredentialFindFilters`: those that are actually stored
/// in the database, and do not require deserializing the `credential` field.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct CredentialFindFilters<'a> {
    /// Hash of public key to search for.
    pub hash: Option<Sha256Hash>,
    /// Credential type to search for.
    pub credential_type: Option<u16>,
    /// Public key to search for
    pub public_key: Option<&'a [u8]>,
    /// Session / Client id to search for
    pub session_id: Option<&'a [u8]>,
    /// Ciphersuite to search for
    pub ciphersuite: Option<u16>,
    /// unix timestamp (seconds) of point of earliest validity to search for
    pub earliest_validity: Option<u64>,
}

/// Entity representing a persisted `Credential`
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct StoredCredential {
    /// Note: this is not a unique identifier, but the session id this credential belongs to.
    #[sensitive]
    pub session_id: Vec<u8>,
    #[sensitive]
    pub credential: Vec<u8>,
    pub created_at: u64,
    pub ciphersuite: u16,
    #[sensitive]
    pub public_key: Vec<u8>,
    pub credential_type: u16,
    #[sensitive]
    pub private_key: Vec<u8>,
}

impl StoredCredential {
    const PRIMARY_KEY_COLUMN_NAMES: [&str; 2] = ["public_key_sha256", "credential_type"];

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            session_id: row.get("session_id")?,
            credential: row.get("credential")?,
            created_at: row.get("created_at")?,
            ciphersuite: row.get("ciphersuite")?,
            public_key: row.get("public_key")?,
            credential_type: row.get("credential_type")?,
            private_key: row.get("private_key")?,
        })
    }

    /// Update `self.created_at` to the current time.
    pub fn pre_save(&mut self) -> CryptoKeystoreResult<()> {
        #[cfg(not(target_os = "unknown"))]
        use std::time::{SystemTime, UNIX_EPOCH};

        #[cfg(target_os = "unknown")]
        use web_time::{SystemTime, UNIX_EPOCH};

        self.created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::CryptoKeystoreError::TimestampError)?
            .as_secs();

        Ok(())
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, derive_more::Constructor)]
pub struct StoredCredentialPk {
    public_key_hash: Sha256Hash,
    credential_type: u16,
}

impl PrimaryKey for StoredCredential {
    type PrimaryKey = StoredCredentialPk;

    fn primary_key(&self) -> Self::PrimaryKey {
        let public_key_hash = Sha256Hash::hash_from(&self.public_key);
        StoredCredentialPk {
            public_key_hash,
            credential_type: self.credential_type,
        }
    }
}

impl crate::traits::Entity for StoredCredential {
    const TABLE_NAME: &'static str = "mls_credentials";

    fn get(conn: &rusqlite::Connection, key: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<Option<Self>> {
        use rusqlite::OptionalExtension as _;

        conn.prepare_cached(
            "SELECT session_id, credential, unixepoch(created_at) AS created_at, ciphersuite, public_key, \
                    credential_type, private_key \
             FROM mls_credentials WHERE public_key_sha256 = ? AND credential_type = ?",
        )?
        .query_row(
            rusqlite::params![key.public_key_hash, key.credential_type],
            Self::from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    fn count(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<u32> {
        crate::entities::helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut statement = conn.prepare_cached(
            "SELECT session_id, credential, unixepoch(created_at) AS created_at, ciphersuite, public_key, \
                    credential_type, private_key \
             FROM mls_credentials",
        )?;
        statement
            .query_map([], Self::from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

impl crate::traits::EntityDatabaseMutation for StoredCredential {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(
            "INSERT INTO mls_credentials \
             (public_key_sha256, credential_type, public_key, session_id, credential, created_at, ciphersuite, private_key) \
             VALUES \
             (:public_key_sha256, :credential_type, :public_key, :session_id, :credential, datetime(:created_at, 'unixepoch'), :ciphersuite, :private_key)",
        )?;
        stmt.execute(rusqlite::named_params![
            ":public_key_sha256": Sha256Hash::hash_from(&self.public_key),
            ":credential_type": self.credential_type,
            ":public_key": self.public_key,
            ":session_id": self.session_id,
            ":credential": self.credential,
            ":created_at": self.created_at,
            ":ciphersuite": self.ciphersuite,
            ":private_key": self.private_key,
        ])
        .map_err(CryptoKeystoreError::map_already_exists(StoredCredential::TABLE_NAME))?;

        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        delete_helper_composite_key::<Self, _>(
            tx,
            &Self::PRIMARY_KEY_COLUMN_NAMES,
            rusqlite::params![id.public_key_hash, id.credential_type],
        )
        .map(|count| count > 0)
    }
}

impl<'a> crate::traits::SearchableEntity<CredentialFindFilters<'a>> for StoredCredential {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        filters: &CredentialFindFilters<'a>,
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let hash = filters
            .hash
            .or_else(|| filters.public_key.map(crate::Sha256Hash::hash_from));
        if let (Some(hash), Some(credential_type)) = (hash, filters.credential_type) {
            return <Self as crate::traits::Entity>::get(conn, &StoredCredentialPk::new(hash, credential_type)).map(
                |opt| {
                    opt.into_iter()
                        .filter(|c| <Self as crate::traits::SearchableEntity<_>>::matches(c, filters))
                        .collect()
                },
            );
        }

        let mut query =
            "SELECT session_id, credential, unixepoch(created_at) AS created_at, ciphersuite, public_key, credential_type, private_key \
             FROM mls_credentials \
             WHERE (true OR :hash OR :credential_type OR :ciphersuite OR :created_at OR :session_id) "
                .to_owned();

        if hash.is_some() {
            query.push_str("AND public_key_sha256 = :hash ");
        }
        if filters.credential_type.is_some() {
            query.push_str("AND credential_type = :credential_type ");
        }
        if filters.ciphersuite.is_some() {
            query.push_str("AND ciphersuite = :ciphersuite ");
        }
        if filters.earliest_validity.is_some() {
            query.push_str("AND unixepoch(created_at) = :created_at ");
        }
        if filters.session_id.is_some() {
            query.push_str("AND session_id = :session_id ");
        }

        let mut stmt = conn.prepare(&query)?;
        stmt.query_map(
            rusqlite::named_params![
                ":hash": hash,
                ":credential_type": filters.credential_type,
                ":ciphersuite": filters.ciphersuite,
                ":created_at": filters.earliest_validity,
                ":session_id": filters.session_id,
            ],
            |row| {
                Ok(Self {
                    session_id: row.get("session_id")?,
                    credential: row.get("credential")?,
                    created_at: row.get("created_at")?,
                    ciphersuite: row.get("ciphersuite")?,
                    public_key: row.get("public_key")?,
                    credential_type: row.get("credential_type")?,
                    private_key: row.get("private_key")?,
                })
            },
        )?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
    }

    fn matches(&self, filters: &CredentialFindFilters<'a>) -> bool {
        filters
            .hash
            .is_none_or(|hash| hash == Sha256Hash::hash_from(&self.public_key))
            && filters
                .credential_type
                .is_none_or(|credential_type| credential_type == self.credential_type)
            && filters.public_key.is_none_or(|pk| pk == self.public_key)
            && filters.session_id.is_none_or(|sid| sid == self.session_id)
            && filters.ciphersuite.is_none_or(|cs| cs == self.ciphersuite)
            && filters.earliest_validity.is_none_or(|ev| ev == self.created_at)
    }
}
