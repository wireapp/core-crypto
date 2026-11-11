use openmls::prelude::{Credential as MlsCredential, MlsCredentialType};
use x509_cert::der::Decode as _;
use zeroize::Zeroize;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Sha256Hash, Transactionlike,
    ancillary::helpers,
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
    /// Unix timestamp in seconds of the leaf certificate's `not_before` for an X509 credential, and 0 for any other.
    ///
    /// Part of the primary key: it tells apart X509 credentials which certify the same signature key, and can be
    /// read from a leaf node. [`credential_not_before`] computes it from the credential.
    pub not_before: u64,
    #[sensitive]
    pub private_key: Vec<u8>,
}

impl StoredCredential {
    const PRIMARY_KEY_COLUMN_NAMES: [&str; 3] = ["public_key_sha256", "credential_type", "not_before"];

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            session_id: row.get("session_id")?,
            credential: row.get("credential")?,
            created_at: row.get("created_at")?,
            ciphersuite: row.get("ciphersuite")?,
            public_key: row.get("public_key")?,
            credential_type: row.get("credential_type")?,
            not_before: row.get("not_before")?,
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

/// The `not_before` part of a stored credential's primary key.
///
/// For an X509 credential this is the leaf certificate's `not_before`, as a unix timestamp in seconds. Any other
/// credential has no certificate, and gets 0.
pub fn credential_not_before(credential: &MlsCredential) -> CryptoKeystoreResult<u64> {
    let MlsCredentialType::X509(certificate) = credential.mls_credential() else {
        return Ok(0);
    };
    let leaf = certificate
        .certificates
        .first()
        .ok_or(CryptoKeystoreError::InvalidX509Credential(
            "the certificate chain is empty".into(),
        ))?;
    let leaf = x509_cert::Certificate::from_der(leaf.as_slice())
        .map_err(|e| CryptoKeystoreError::InvalidX509Credential(format!("decoding the leaf certificate: {e}")))?;
    Ok(leaf
        .tbs_certificate()
        .validity()
        .not_before
        .to_unix_duration()
        .as_secs())
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, derive_more::Constructor)]
pub struct StoredCredentialPk {
    pub public_key_hash: Sha256Hash,
    pub credential_type: u16,
    /// See [`StoredCredential::not_before`].
    pub not_before: u64,
}

impl StoredCredentialPk {
    /// The primary key of the stored credential holding this signature key and credential.
    ///
    /// This is how a leaf node finds its credential: both parts are in the leaf node. Fails if the credential is
    /// X509 and its leaf certificate can't be decoded.
    pub fn from_mls_credential(signature_key: &[u8], credential: &MlsCredential) -> CryptoKeystoreResult<Self> {
        Ok(Self {
            public_key_hash: Sha256Hash::hash_from(signature_key),
            credential_type: credential.credential_type().into(),
            not_before: credential_not_before(credential)?,
        })
    }
}

impl PrimaryKey for StoredCredential {
    type PrimaryKey = StoredCredentialPk;

    fn primary_key(&self) -> Self::PrimaryKey {
        let public_key_hash = Sha256Hash::hash_from(&self.public_key);
        StoredCredentialPk {
            public_key_hash,
            credential_type: self.credential_type,
            not_before: self.not_before,
        }
    }
}

impl crate::traits::Entity for StoredCredential {
    const TABLE_NAME: &'static str = "mls_credentials";

    fn get(conn: &rusqlite::Connection, key: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<Option<Self>> {
        use rusqlite::OptionalExtension as _;

        conn.prepare_cached(
            "SELECT session_id, credential, unixepoch(created_at) AS created_at, ciphersuite, public_key, \
                    credential_type, not_before, private_key \
             FROM mls_credentials WHERE public_key_sha256 = ? AND credential_type = ? AND not_before = ?",
        )?
        .query_row(
            rusqlite::params![key.public_key_hash, key.credential_type, key.not_before],
            Self::from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    fn count(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<u32> {
        crate::ancillary::helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let mut statement = conn.prepare_cached(
            "SELECT session_id, credential, unixepoch(created_at) AS created_at, ciphersuite, public_key, \
                    credential_type, not_before, private_key \
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
             (public_key_sha256, credential_type, not_before, public_key, session_id, credential, created_at, ciphersuite, private_key) \
             VALUES \
             (:public_key_sha256, :credential_type, :not_before, :public_key, :session_id, :credential, datetime(:created_at, 'unixepoch'), :ciphersuite, :private_key)",
        )?;
        stmt.execute(rusqlite::named_params![
            ":public_key_sha256": Sha256Hash::hash_from(&self.public_key),
            ":credential_type": self.credential_type,
            ":not_before": self.not_before,
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
        helpers::delete_helper_composite_key::<Self, _>(
            tx,
            &Self::PRIMARY_KEY_COLUMN_NAMES,
            rusqlite::params![id.public_key_hash, id.credential_type, id.not_before],
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
        let mut query =
            "SELECT session_id, credential, unixepoch(created_at) AS created_at, ciphersuite, public_key, credential_type, \
                    not_before, private_key \
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
            Self::from_row,
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
