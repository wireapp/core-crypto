mod common;

#[cfg(test)]
mod tests {
    use super::common::*;

    use openmls::{
        ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite},
        credentials::{CredentialBundle, CredentialType},
        extensions::{Extension, KeyIdExtension},
        key_packages::KeyPackageBundle,
    };
    use openmls_rust_crypto_provider::OpenMlsRustCrypto;
    use openmls_traits::{random::OpenMlsRand, OpenMlsCryptoProvider};

    #[test]
    fn can_add_read_delete_keybundle() {
        let store = setup("mls");

        let backend = OpenMlsRustCrypto::default();
        let uuid: [u8; 16] = backend.rand().random_array().unwrap();
        let ciphersuite = Ciphersuite::new(CiphersuiteName::default()).unwrap();

        let key_id = uuid::Uuid::from_bytes(uuid);

        let credentials = CredentialBundle::new(
            vec![1, 2, 3],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &backend,
        )
        .unwrap();

        let keypackage_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credentials,
            &backend,
            vec![Extension::KeyPackageId(KeyIdExtension::new(
                key_id.as_bytes(),
            ))],
        )
        .unwrap();

        keypackage_bundle.key_package().verify(&backend).unwrap();

        let key = {
            let id = keypackage_bundle.key_package().key_id().unwrap();
            uuid::Uuid::from_slice(id).unwrap()
        };

        use openmls_traits::key_store::OpenMlsKeyStore as _;
        store.store(&key, &keypackage_bundle).unwrap();
        let bundle2: KeyPackageBundle = store.read(&key).unwrap();
        assert_eq!(keypackage_bundle.leaf_secret(), bundle2.leaf_secret());
        assert_eq!(keypackage_bundle.key_package(), bundle2.key_package());
        let _ = store.delete(&key).unwrap();

        teardown(store);
    }
}
