use core_crypto_keystore::{
    connection::FetchFromDatabase as _,
    entities::{EntityFindParams, StoredSignatureKeypair},
};
use mls_crypto_provider::Database;
use openmls::prelude::{OpenMlsCrypto, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::{Deserialize as _, Serialize as _};

use super::{Error, Result};
use crate::{KeystoreError, MlsError, mls::session::id::ClientIdRef};

/// Load all stored keypairs from the keystore
///
/// Ensures the keypairs are sorted in order of their creation date.
pub(super) async fn load_all(database: &Database) -> Result<Vec<StoredSignatureKeypair>> {
    database
        .find_all::<StoredSignatureKeypair>(EntityFindParams::default())
        .await
        .map_err(KeystoreError::wrap("finding all mls signature keypairs"))
        .map_err(Into::into)
}

/// Generate a new keypair in-memory with the specificed signature scheme
pub(super) fn generate(crypto: impl OpenMlsCrypto, signature_scheme: SignatureScheme) -> Result<SignatureKeyPair> {
    let (private_key, public_key) = crypto
        .signature_key_gen(signature_scheme)
        .map_err(MlsError::wrap("generating signature key"))?;
    Ok(SignatureKeyPair::from_raw(signature_scheme, private_key, public_key))
}

/// Store a keypair in the keystore, attached to a particular client id
pub(super) async fn store(database: &Database, id: &ClientIdRef, keypair: &SignatureKeyPair) -> Result<()> {
    let data = keypair
        .tls_serialize_detached()
        .map_err(Error::tls_serialize("keypair"))?;

    debug_assert!(
        {
            let deserialized =
                SignatureKeyPair::tls_deserialize_exact(&data).expect("keypair deserializes without error");
            deserialized.signature_scheme() == keypair.signature_scheme()
                && deserialized.public() == keypair.public()
                && deserialized.private() == keypair.private()
        },
        "serialized keypair data must deserialize correctly"
    );

    let stored_keypair = StoredSignatureKeypair::new(
        keypair.signature_scheme(),
        keypair.public().to_owned(),
        data,
        id.as_slice().into(),
    );
    database
        .save(stored_keypair)
        .await
        .map_err(KeystoreError::wrap("storing keypairs in keystore"))?;

    Ok(())
}

/// Deserialize a [`StoredSignatureKeypair`] into a [`SignatureKeyPair`]
pub(super) fn deserialize(stored: &StoredSignatureKeypair) -> Result<SignatureKeyPair> {
    SignatureKeyPair::tls_deserialize_exact(&stored.keypair)
        .map_err(KeystoreError::wrap("deserializing keypair from keystore"))
        .map_err(Into::into)
}

/// Retrieve the first keypair from the list which matches the provided signature scheme, client id, and public key
pub(super) async fn find_matching(
    keypairs: &[StoredSignatureKeypair],
    client_id: impl AsRef<[u8]>,
    signature_scheme: SignatureScheme,
    public_key: impl AsRef<[u8]>,
) -> Result<Option<SignatureKeyPair>> {
    keypairs
        .iter()
        .filter(|stored| {
            stored.credential_id == client_id.as_ref() && stored.signature_scheme == signature_scheme as u16
        })
        .map(deserialize)
        .find(|key_pair_result| {
            key_pair_result
                .as_ref()
                .ok()
                .is_none_or(|key_pair| key_pair.public() == public_key.as_ref())
        })
        .transpose()
}
