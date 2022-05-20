use crate::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};
use openmls::prelude::{ExternalProposal, GroupEpoch, GroupId, KeyPackage, MlsMessageOut};
use tls_codec::Serialize;

impl MlsCentral {
    /// Crafts a new external Add proposal. Enables a client outside a group to request addition to this group.
    /// For Wire only, the client must belong to an user already in the group
    pub fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
        key_package: KeyPackage,
    ) -> CryptoResult<MlsMessageOut> {
        let client = self.mls_client.read().map_err(|_| CryptoError::LockPoisonError)?;

        // key to sign the message must be the same as the one of the client being added to the group
        // in our case, the new client it can only be the sender itself..
        let signature_key = key_package
            .credential()
            .signature_key()
            .tls_serialize_detached()
            .map_err(MlsError::from)?;

        // ..so, since we are the new client to add, we fetch back our credential bundle
        // containing a private key which will let us sign the message
        let credential_bundle = client.load_credential_bundle(&signature_key, &self.mls_backend)?;

        let group_id = GroupId::from_slice(&conversation_id[..]);
        ExternalProposal::new_add(
            key_package,
            None,
            group_id,
            epoch,
            &credential_bundle,
            &self.mls_backend,
        )
        .map_err(MlsError::from)
        .map_err(CryptoError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlsCentralConfiguration, MlsConversationConfiguration};
    use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};
    use tempfile::TempDir;

    mod add {
        use super::*;

        #[test]
        fn should_succeed() {
            let owner_tmp_dir = tempfile::tempdir().unwrap();
            let owner_central = MlsCentral::try_new(central_config("owner@wire.com", &owner_tmp_dir)).unwrap();
            let conversation_id = b"owner-guest".to_vec();
            owner_central
                .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                .unwrap();
            let owner_groups = owner_central.mls_groups.read().unwrap();
            let owner_group = owner_groups.get(&conversation_id).unwrap();

            let guest_tmp_dir = tempfile::tempdir().unwrap();
            let guest_central = MlsCentral::try_new(central_config("guest@wire.com", &guest_tmp_dir)).unwrap();

            let epoch = owner_group.group.read().unwrap().epoch();

            let guest_key_packages = guest_central.client_keypackages(1).unwrap();
            let guest_key_package = guest_key_packages.get(0).unwrap().key_package().to_owned();

            // Craft an external proposal from guest
            let add_message = guest_central
                .new_external_add_proposal(owner_group.id.clone(), epoch, guest_key_package)
                .unwrap();

            // Owner receives external proposal message from server
            owner_central
                .decrypt_message(conversation_id.clone(), add_message.to_bytes().unwrap().as_slice())
                .unwrap();

            // just owner
            assert_eq!(owner_group.members().unwrap().len(), 1);

            // simulate commit message reception from server
            let (_, welcome) = owner_group
                .commit_pending_proposals(&owner_central.mls_backend)
                .unwrap();

            // owner + guest
            assert_eq!(owner_group.members().unwrap().len(), 2);

            guest_central
                .process_welcome_message(welcome.unwrap(), MlsConversationConfiguration::default())
                .unwrap();

            // guest can send messages in the group
            assert!(guest_central.encrypt_message(conversation_id, b"hello owner").is_ok());
        }

        #[test]
        fn should_fail_when_sender_credential_bundle_absent() {
            let guest_tmp_dir = tempfile::tempdir().unwrap();
            let guest_central = MlsCentral::try_new(central_config("guest@wire.com", &guest_tmp_dir)).unwrap();

            let guest_key_packages = guest_central.client_keypackages(1).unwrap();
            let guest_key_package = guest_key_packages.get(0).unwrap().key_package().to_owned();

            // delete local keystore. guest has lost his private signature key it requires to sign external add proposal message
            let signature_key = guest_key_package
                .credential()
                .signature_key()
                .tls_serialize_detached()
                .unwrap();
            guest_central.mls_backend.key_store().delete(&signature_key).unwrap();

            // should fail because client private signature key lost
            let add_message =
                guest_central.new_external_add_proposal(b"group".to_vec(), GroupEpoch::from(1), guest_key_package);
            match add_message {
                Err(CryptoError::ClientSignatureNotFound) => {}
                _ => panic!(),
            }
        }
    }

    fn central_config(client_id: &str, tmp_dir: &TempDir) -> MlsCentralConfiguration {
        MlsCentralConfiguration::try_new(
            MlsCentralConfiguration::tmp_store_path(tmp_dir),
            "test".to_string(),
            client_id.to_string(),
        )
        .unwrap()
    }
}
