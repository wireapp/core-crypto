use std::sync::Arc;

use openmls::{group::QueuedProposal, prelude::group_info::VerifiableGroupInfo};

use crate::{
    RecursiveError,
    mls::{
        conversation::{Conversation, ConversationGuard, ConversationWithMls as _},
        credential::{CredentialBundle, ext::CredentialExt as _},
    },
    prelude::{ConversationId, E2eiConversationState, MlsProposalRef},
};

use super::{MessageExt as _, MlsCredentialType, MlsTransportTestExt, SessionContext, TestContext, TestError};

mod commit;
pub(crate) mod operation_guard;
mod proposal;

use operation_guard::TestOperation;

#[derive(derive_more::AsRef)]
pub struct TestConversation<'a> {
    pub(crate) case: &'a TestContext,
    #[as_ref]
    pub(crate) id: ConversationId,
    pub(crate) members: Vec<&'a SessionContext>,
    history_client: Option<SessionContext>,
    proposals: Vec<TestOperation<'a>>,
    actor_index: Option<usize>,
}

impl<'a> TestConversation<'a> {
    /// Create a new test conversation with parameters inherited from the [TestContext].
    pub async fn new(case: &'a TestContext, creator: &'a SessionContext) -> Self {
        Self::new_with_credential_type(case, creator, case.credential_type).await
    }

    /// Like [Self::new], but with the provided [MlsCredentialType].
    pub async fn new_with_credential_type(
        case: &'a TestContext,
        creator: &'a SessionContext,
        credential_type: MlsCredentialType,
    ) -> Self {
        let id = super::conversation_id();
        creator
            .transaction
            .new_conversation(&id, credential_type, case.cfg.clone())
            .await
            .unwrap();

        Self {
            case,
            id,
            members: vec![creator],
            history_client: None,
            proposals: vec![],
            actor_index: None,
        }
    }

    /// Use this if you have created a conversation before and want to create a `TestConversation` instance of that conversation.
    pub async fn new_from_existing(
        case: &'a TestContext,
        id: ConversationId,
        members: impl Into<Vec<&'a SessionContext>>,
    ) -> Self {
        let conversation = Self {
            case,
            id,
            members: members.into(),
            history_client: None,
            proposals: vec![],
            actor_index: None,
        };
        assert!(conversation.is_functional_and_contains(conversation.members()).await);
        conversation
    }

    /// The [ConversationId] the underlying conversation was created with.
    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    pub(crate) async fn export_group_info(&self) -> VerifiableGroupInfo {
        let credential = self.credential_bundle().await;
        let conversation = self.guard().await;
        let conversation = conversation.conversation().await;
        let group = conversation.group();

        let gi = group
            .export_group_info(&self.actor().session.crypto_provider, &credential.signature_key, true)
            .unwrap();
        gi.group_info().unwrap()
    }

    /// Find the actor's credential bundle used in this conversation.
    pub(crate) async fn credential_bundle(&self) -> Arc<CredentialBundle> {
        let conversation = self.guard().await;
        let conversation = conversation.conversation().await;
        conversation
            .find_current_credential_bundle(&self.actor().session)
            .await
            .expect("expecting credential bundle")
    }

    /// Count the members. Also, assert that the count is the same from the point of view of every member.
    pub async fn member_count(&self) -> usize {
        let member_count = self.members().count();

        let member_counts_match = futures_util::future::join_all(self.members().map(async |member| {
            let member_guard = self.guard_of(member).await;
            member_guard.conversation().await.members().len()
        }))
        .await
        .iter()
        .all(|count| *count == member_count);
        assert!(member_counts_match);
        member_count
    }

    /// Let a conversation member provide the member count (according to their current state).
    pub async fn members_counted_by(&self, member: &SessionContext) -> usize {
        let member_guard = self.guard_of(member).await;
        member_guard.conversation().await.members().len()
    }

    /// Check if all provided members are members, according to the state maintained in [Self].
    pub async fn are_members(&self, members_to_check: impl IntoIterator<Item = &'a SessionContext>) -> bool {
        let member_ids = futures_util::future::join_all(self.members().map(|member| member.get_client_id())).await;
        for member in members_to_check.into_iter() {
            let id = member.get_client_id().await;
            if !member_ids.contains(&id) {
                return false;
            }
        }
        true
    }

    /// Convenience method to call [Self::are_members] with a single member.
    pub async fn is_member(&self, member: &SessionContext) -> bool {
        self.are_members([member]).await
    }

    /// Check if the provided members are in the conversation and all members can talk to one another.
    pub async fn is_functional_and_contains(
        &self,
        members_to_check: impl IntoIterator<Item = &'a SessionContext>,
    ) -> bool {
        self.are_members(members_to_check).await && self.is_functional().await
    }

    /// Check if all members can talk to one another.
    pub async fn is_functional(&self) -> bool {
        let result_futures = self.members().enumerate().flat_map(|(idx, member)| {
            self.members()
                .enumerate()
                .filter(move |(other_idx, _)| idx != *other_idx)
                .map(move |(_, other_member)| self.can_talk(member, other_member))
        });

        futures_util::future::join_all(result_futures)
            .await
            .iter()
            .all(|members_can_talk| *members_can_talk)
    }

    async fn try_one_way_communicate(
        &self,
        sender: &SessionContext,
        receiver: &SessionContext,
    ) -> crate::test_utils::Result<()> {
        let mut sender_guard = sender
            .transaction
            .conversation(&self.id)
            .await
            .map_err(RecursiveError::transaction("getting conversation by id"))?;
        let mut receiver_guard = receiver
            .transaction
            .conversation(&self.id)
            .await
            .map_err(RecursiveError::transaction("getting conversation by id"))?;
        let msg = b"Hello other";
        let encrypted = sender_guard
            .encrypt_message(msg)
            .await
            .map_err(RecursiveError::mls_conversation(
                "encrypting message; sender -> receiver",
            ))?;
        let decrypted = receiver_guard
            .decrypt_message(encrypted)
            .await
            .map_err(RecursiveError::mls_conversation(
                "decrypting message; receiver <- sender",
            ))?
            .app_msg
            .ok_or(TestError::ImplementationError)?;
        assert_eq!(&msg[..], &decrypted[..]);
        Ok(())
    }

    /// Check if one member can exchange application messages with another
    pub(crate) async fn can_talk(&self, member: &SessionContext, other_member: &SessionContext) -> bool {
        self.can_one_way_communicate(member, other_member).await
            && self.can_one_way_communicate(other_member, member).await
    }

    pub(crate) async fn can_one_way_communicate(&self, sender: &SessionContext, receiver: &SessionContext) -> bool {
        self.try_one_way_communicate(sender, receiver).await.is_ok()
    }

    /// Get the current acting member, i.e., the member on whose behalf the following operation will be performed.
    /// After each operation, this will reset to the creator.
    pub fn actor(&self) -> &SessionContext {
        self.members[self.actor_index()]
    }

    fn actor_index(&self) -> usize {
        self.actor_index.unwrap_or_default()
    }

    /// Execute the next operation on bahalf of the provided member.
    /// This will reset to the conversation creator once the operation is distributed via
    /// [OperationGuard::notify_members] or finished via [OperationGuard::finish].
    pub async fn acting_as(mut self, actor: &SessionContext) -> Self {
        let actor_index = self.member_index(actor).await;
        self.actor_index = Some(actor_index);
        self
    }

    /// All members of this conversation.
    ///
    /// The creator is always the first member returned (if they're still a member).
    pub fn members(&self) -> impl Iterator<Item = &SessionContext> {
        self.members.iter().copied().chain(self.history_client.as_ref())
    }

    /// Convenience function to get the mls transport of the actor.
    pub async fn transport(&self) -> Arc<dyn MlsTransportTestExt> {
        self.actor().mls_transport().await
    }

    /// Convenience function to get the conversation guard of this conversation.
    ///
    /// The guard belongs to the current actor.
    pub async fn guard(&self) -> ConversationGuard {
        self.guard_of(self.actor()).await
    }

    /// Get the conversation guard of this conversation, from the point of view of the
    /// member.
    pub async fn guard_of(&self, member: &'a SessionContext) -> ConversationGuard {
        member.transaction.conversation(&self.id).await.unwrap()
    }

    /// The verification state of the conversation, according to the state of [Self::actor].
    pub async fn e2ei_state(&self) -> E2eiConversationState {
        self.e2ei_state_of(self.actor()).await
    }

    /// Like [Self::e2ei_state], but from the point of view of a different member.
    pub async fn e2ei_state_of(&self, member: &'a SessionContext) -> E2eiConversationState {
        self.guard_of(member).await.e2ei_conversation_state().await.unwrap()
    }

    /// Like [Self::e2ei_state], but via the`GroupInfo exported by [Self::actor].
    pub async fn e2ei_state_via_group_info(&self) -> E2eiConversationState {
        let gi = self.export_group_info().await;

        self.actor()
            .transaction
            .get_credential_in_use(gi, MlsCredentialType::X509)
            .await
            .unwrap()
    }

    pub(crate) async fn pending_proposals(&self) -> impl IntoIterator<Item = QueuedProposal> {
        let guard = self.guard().await;
        guard
            .conversation()
            .await
            .group()
            .pending_proposals()
            .cloned()
            .collect::<Vec<_>>()
    }

    /// The reference of the latest pending proposal.
    pub async fn latest_proposal_ref(&self) -> MlsProposalRef {
        assert!(self.has_pending_proposals().await);
        let guard = self.guard().await;
        guard
            .conversation()
            .await
            .group()
            .pending_proposals()
            .last()
            .unwrap()
            .proposal_reference()
            .to_owned()
            .into()
    }

    /// The pending proposal count of the actor
    pub async fn pending_proposal_count(&self) -> usize {
        self.pending_proposal_count_of(self.actor()).await
    }

    /// The pending proposal count of a specific member
    pub async fn pending_proposal_count_of(&self, member: &SessionContext) -> usize {
        let guard = self.guard_of(member).await;
        guard.conversation().await.group().pending_proposals().count()
    }

    /// Check if the conversation has pending proposals
    pub async fn has_pending_proposals(&self) -> bool {
        let guard = self.guard().await;
        guard.conversation().await.group().pending_proposals().next().is_some()
    }

    /// Check if the conversation has a pending commit
    pub async fn has_pending_commit(&self) -> bool {
        let guard = self.guard().await;
        guard.conversation().await.group().pending_commit().is_some()
    }

    async fn member_index(&self, member: &SessionContext) -> usize {
        let member_id = member.session.id().await.unwrap();

        // can't use `Iterator::position` because getting the id is async
        let mut member_idx = None;
        for (idx, member) in self.members().enumerate() {
            let joiner_id = member.session.id().await.unwrap();
            if joiner_id == member_id {
                member_idx = Some(idx);
                break;
            }
        }

        member_idx.expect("could find the member in this conversation")
    }

    /// Get the actor's HPKE public key used in this conversation
    pub(crate) async fn encryption_public_key(&self) -> Vec<u8> {
        let client_id = self.actor().get_client_id().await;
        let guard = self.guard().await;
        guard
            .conversation()
            .await
            .group()
            .members()
            .find(|k| k.credential.identity() == client_id.0.as_slice())
            .unwrap()
            .encryption_key
    }

    pub(crate) async fn verify_credential_handle_and_name(&self, new_handle: &str, new_display_name: &str) {
        let new_handle = format!("wireapp://%40{new_handle}@world.com");
        // verify the identity in..
        // the MLS group
        let cid = self.actor().get_client_id().await;
        let guard = self.guard().await;
        let group_identities = guard.get_device_identities(&[cid.clone()]).await.unwrap();
        let group_identity = group_identities.first().unwrap();
        assert_eq!(group_identity.client_id.as_bytes(), cid.0.as_slice());
        assert_eq!(
            group_identity.x509_identity.as_ref().unwrap().display_name,
            new_display_name
        );
        assert_eq!(group_identity.x509_identity.as_ref().unwrap().handle, new_handle);
        assert_eq!(group_identity.status, crate::prelude::DeviceStatus::Valid);
        assert!(!group_identity.thumbprint.is_empty());

        // the in-memory mapping
        let cb = self
            .actor()
            .session
            .find_most_recent_credential_bundle(self.case.signature_scheme(), MlsCredentialType::X509)
            .await
            .expect("x509 credential bundle");
        let cs = guard.ciphersuite().await;
        let local_identity = cb.to_mls_credential_with_key().extract_identity(cs, None).unwrap();
        assert_eq!(&local_identity.client_id.as_bytes(), &cid.0);
        assert_eq!(
            local_identity.x509_identity.as_ref().unwrap().display_name,
            new_display_name
        );
        assert_eq!(local_identity.x509_identity.as_ref().unwrap().handle, new_handle);
        assert_eq!(local_identity.status, crate::prelude::DeviceStatus::Valid);
        assert!(!local_identity.thumbprint.is_empty());

        // the keystore
        let signature_key = self
            .actor()
            .find_signature_keypair_from_keystore(cb.signature_key.public())
            .await
            .unwrap();
        let signature_key = openmls::prelude::SignaturePublicKey::from(signature_key.pk.as_slice());
        let credential = self.actor().find_credential_from_keystore(&cb).await.unwrap();
        let credential = <openmls::prelude::Credential as tls_codec::Deserialize>::tls_deserialize(
            &mut credential.credential.as_slice(),
        )
        .unwrap();
        let credential = openmls::prelude::CredentialWithKey {
            credential,
            signature_key,
        };

        assert_eq!(credential.credential.identity(), &cid.0);
        let keystore_identity = credential.extract_identity(cs, None).unwrap();
        assert_eq!(
            keystore_identity.x509_identity.as_ref().unwrap().display_name,
            new_display_name
        );
        assert_eq!(keystore_identity.x509_identity.as_ref().unwrap().handle, new_handle);
        assert_eq!(keystore_identity.status, crate::prelude::DeviceStatus::Valid);
        assert!(!keystore_identity.thumbprint.is_empty());
    }
}
