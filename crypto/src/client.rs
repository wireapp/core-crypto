use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
    credentials::CredentialBundle,
    extensions::{Extension, KeyIdExtension},
    prelude::KeyPackageBundle,
};
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

use crate::{prelude::MemberId, CryptoError, CryptoResult, MlsError};

pub(crate) const INITIAL_KEYING_MATERIAL_COUNT: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId {
    user_id: uuid::Uuid,
    domain: String,
    client_id: u64,
}

impl ClientId {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut ret = vec![];
        ret.extend_from_slice(self.user_id.to_hyphenated_ref().to_string().as_bytes());
        ret.push(b':');
        ret.extend_from_slice(self.client_id.to_string().as_bytes());
        ret.push(b'@');
        ret.extend_from_slice(self.domain.as_bytes());

        ret
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}@{}",
            self.user_id.to_hyphenated_ref(),
            self.client_id,
            self.domain
        )
    }
}

impl std::str::FromStr for ClientId {
    type Err = CryptoError;

    // Format: user_uuid:client_id@domain
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split('@').take(2);
        let uid_cid_tuple = iter
            .next()
            .ok_or_else(|| CryptoError::MalformedIdentifier(s.to_string()))?;

        let domain = iter
            .next()
            .ok_or_else(|| CryptoError::MalformedIdentifier(s.to_string()))?
            .to_string();

        let mut iter_uid = uid_cid_tuple.split(':').take(2);
        let user_id = iter_uid
            .next()
            .ok_or_else(|| CryptoError::MalformedIdentifier(s.to_string()))?
            .parse()?;

        let client_id = iter_uid
            .next()
            .ok_or_else(|| CryptoError::MalformedIdentifier(s.to_string()))?
            .parse()?;

        Ok(Self {
            user_id,
            domain,
            client_id,
        })
    }
}

impl Into<MemberId> for ClientId {
    fn into(self) -> MemberId {
        MemberId {
            domain: self.domain,
            uuid: self.user_id,
        }
    }
}

// #[cfg(not(debug_assertions))]
// pub type ClientId = crate::identifiers::ZeroKnowledgeUuid;
// #[cfg(debug_assertions)]
// pub type ClientId = crate::identifiers::QualifiedUuid;

#[derive(Debug, Clone)]
pub struct Client {
    id: ClientId,
    credentials: CredentialBundle,
    keypackage_bundles: Vec<KeyPackageBundle>,
    ciphersuite: Ciphersuite,
}

impl Client {
    pub fn init(id: ClientId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let id_str = id.to_string();
        let (client, generated) = if let Some(signature) = backend.key_store().load_mls_identity_signature(&id_str)? {
            match Self::load(id.clone(), &signature, backend) {
                Ok(client) => (client, false),
                Err(CryptoError::ClientSignatureNotFound) => (Self::generate(id, backend)?, true),
                Err(e) => return Err(e),
            }
        } else {
            (Self::generate(id, backend)?, true)
        };

        if generated {
            backend
                .key_store()
                .save_mls_identity_signature(&id_str, client.credentials.credential().signature_key().as_slice())?;
        }

        Ok(client)
    }

    pub(crate) fn generate(id: ClientId, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let ciphersuite = Ciphersuite::new(CiphersuiteName::default()).map_err(MlsError::from)?;
        let credentials = CredentialBundle::new(
            id.as_bytes(),
            openmls::credentials::CredentialType::Basic,
            ciphersuite.signature_scheme(),
            backend,
        )
        .map_err(MlsError::from)?;

        // FIXME: Storing the credentials this way prevents from reconstructing
        // FIXME: the keypackages list belonging to this device.
        // FIXME: i.e. there's no way to tell between outside public keys & own keypackages
        backend
            .key_store()
            .store(credentials.credential().signature_key(), &credentials)
            .map_err(eyre::Report::msg)?;

        let mut client = Self {
            id,
            credentials,
            keypackage_bundles: vec![],
            ciphersuite,
        };

        client.provision_keying_material(INITIAL_KEYING_MATERIAL_COUNT, backend)?;
        Ok(client)
    }

    pub(crate) fn load<S: std::hash::Hash>(
        id: ClientId,
        signature_public_key: &S,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let ciphersuite = Ciphersuite::new(CiphersuiteName::default()).map_err(MlsError::from)?;
        let credentials: CredentialBundle = backend
            .key_store()
            .read(signature_public_key)
            .ok_or(CryptoError::ClientSignatureNotFound)?;

        Ok(Self {
            id,
            credentials,
            keypackage_bundles: vec![], // TODO: Find a way to restore the keypackage_bundles? Or not cache them at all?
            ciphersuite,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        self.credentials.credential().signature_key().as_slice()
    }

    /// This method consumes a KeyPackageBundle for the Client, hashes it and returns the hash,
    /// and if necessary regenerates a new keypackage for immediate use
    // FIXME: This shouldn't take &mut self; Maybe rework the whole thing to not used a cached view of KPBs and only interact with the keystore?
    pub fn keypackage_hash(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        if let Some(kpb) = self.keypackage_bundles.pop() {
            Ok(kpb.key_package().hash(backend).map_err(MlsError::from)?)
        } else {
            self.gen_keypackage(backend)?;
            self.keypackage_hash(backend)
        }
    }

    pub(crate) fn gen_keypackage(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        let kpb = KeyPackageBundle::new(
            &[self.ciphersuite.name()],
            &self.credentials,
            backend,
            vec![Extension::KeyPackageId(KeyIdExtension::new(&self.id.as_bytes()))],
        )
        .map_err(MlsError::from)?;

        backend
            .key_store()
            .store(&kpb.key_package().hash(backend).map_err(MlsError::from)?, &kpb)
            .map_err(eyre::Report::msg)?;

        self.keypackage_bundles.push(kpb);
        Ok(())
    }

    /// Requests `count` keying material to be present and returns
    /// a reference to it for the consumer to copy/clone.
    pub fn request_keying_material(
        &mut self,
        count: usize,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<&[KeyPackageBundle]> {
        self.provision_keying_material(count, backend)?;

        Ok(self.keypackage_bundles.as_slice())
    }

    fn provision_keying_material(&mut self, count: usize, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        if count <= self.keypackage_bundles.len() {
            return Ok(());
        }

        let count = count - self.keypackage_bundles.len();
        for _ in 0..count {
            self.gen_keypackage(backend)?;
        }

        Ok(())
    }
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Client {}

#[cfg(test)]
impl Client {
    pub fn random_generate(backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let user_uuid = uuid::Uuid::new_v4();
        let client_id = rand::random::<usize>();
        Self::generate(
            format!("{}:{client_id}@members.wire.com", user_uuid.to_hyphenated()).parse()?,
            &backend,
        )
    }

    pub fn keypackages(&self) -> Vec<&openmls::prelude::KeyPackage> {
        self.keypackage_bundles.iter().map(|kpb| kpb.key_package()).collect()
    }
}

#[cfg(test)]
mod tests {
    use mls_crypto_provider::MlsCryptoProvider;

    use super::Client;

    #[test]
    fn can_generate_client() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        assert!(Client::random_generate(&backend).is_ok());
    }

    #[test]
    fn client_never_runs_out_of_keypackages() {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        let mut client = Client::random_generate(&backend).unwrap();
        for _ in 0..100 {
            assert!(client.keypackage_hash(&backend).is_ok())
        }
    }
}
