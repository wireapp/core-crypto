use openmls::prelude::group_info::VerifiableGroupInfo;

use crate::mls::conversation::ConversationWithMls as _;
use crate::mls::conversation::pending_conversation::PendingConversation;
use crate::mls::credential::CredentialBundle;
use crate::prelude::MlsCredentialType;

use super::super::SessionContext;
use super::TestConversation;
use super::operation_guard::AddGuard;
use super::operation_guard::Commit;
use super::operation_guard::OperationGuard;
use super::operation_guard::TestOperation;

impl<'a> TestConversation<'a> {
    /// Invite all sessions into this conversation and notify all members, old and new.
    /// The credential type of the invited members' key packages will be inherited from the [super::TestContext].
    pub async fn invite_notify(self, sessions: impl IntoIterator<Item = &'a SessionContext>) -> TestConversation<'a> {
        let commit_guard = self.invite(sessions).await;
        commit_guard.notify_members().await
    }

    /// Invite all sessions into this conversation.
    /// The credential type of the invited members' key packages will be inherited from the [super::TestContext].
    pub async fn invite(self, sessions: impl IntoIterator<Item = &'a SessionContext>) -> OperationGuard<'a, Commit> {
        let credential_type = self.case.credential_type;
        self.invite_with_credential_type(credential_type, sessions).await
    }

    /// Like [Self::invite_notify], but the key packages of the invited members will be of the provided credential type.
    pub async fn invite_with_credential_type_notify(
        self,
        credential_type: MlsCredentialType,
        sessions: impl IntoIterator<Item = &'a SessionContext>,
    ) -> TestConversation<'a> {
        self.invite_with_credential_type(credential_type, sessions)
            .await
            .notify_members()
            .await
    }

    /// Like [Self::invite], but the key packages of the invited members will be of the provided credential type.
    pub async fn invite_with_credential_type(
        self,
        credential_type: MlsCredentialType,
        sessions: impl IntoIterator<Item = &'a SessionContext>,
    ) -> OperationGuard<'a, Commit> {
        let new_members = sessions.into_iter().collect::<Vec<_>>();

        let key_packages = futures_util::future::join_all(
            new_members
                .iter()
                .map(|cc| cc.rand_key_package_of_type(self.case, credential_type)),
        )
        .await;
        self.guard().await.add_members(key_packages).await.unwrap();
        let commit = self.transport().await.latest_commit_bundle().await.commit;
        let actor_index = self.actor_index();
        OperationGuard::new(
            TestOperation::Add(AddGuard { new_members }),
            commit,
            self,
            [actor_index],
        )
    }

    /// Advance the epoch (by updating the actor's key material) and notify all members.
    pub async fn advance_epoch(self) -> TestConversation<'a> {
        self.update_notify().await
    }

    /// Update the actors key material and notify all members.
    pub async fn update_notify(self) -> TestConversation<'a> {
        self.update().await.notify_members().await
    }

    /// Update the actors key material.
    pub async fn update(self) -> OperationGuard<'a, Commit> {
        self.guard().await.update_key_material().await.unwrap();
        let commit = self.transport().await.latest_commit_bundle().await.commit;
        let committer_index = self.actor_index();
        OperationGuard::new(TestOperation::Update, commit, self, [committer_index])
    }

    /// Create a commit that hasn't been merged by the actor.
    /// On [OperationGuard::notify_members], the actor will receive this commit.
    pub async fn update_unmerged(self) -> OperationGuard<'a, Commit> {
        let mut conversation_guard = self.guard().await;
        let commit = conversation_guard
            .update_key_material_inner(None, None)
            .await
            .unwrap()
            .commit;
        OperationGuard::new(TestOperation::Update, commit, self, [])
    }

    /// Replace the existing credential with an x509 one and notify all members.
    pub async fn e2ei_rotate_notify(self, credential_bundle: Option<&CredentialBundle>) -> TestConversation<'a> {
        self.e2ei_rotate(credential_bundle).await.notify_members().await
    }

    /// Create an update commit with a leaf node containing x509 credentials, that hasn't been merged by the actor.
    /// On [OperationGuard::notify_members], the actor will receive this commit.
    pub async fn e2ei_rotate_unmerged(self, credential_bundle: &CredentialBundle) -> OperationGuard<'a, Commit> {
        let mut conversation_guard = self.guard().await;
        let conversation = conversation_guard.conversation().await;
        let mut leaf_node = conversation.group.own_leaf().unwrap().clone();
        drop(conversation);
        leaf_node.set_credential_with_key(credential_bundle.to_mls_credential_with_key());
        let commit = conversation_guard
            .update_key_material_inner(Some(credential_bundle), Some(leaf_node))
            .await
            .unwrap()
            .commit;

        OperationGuard::new(TestOperation::Update, commit, self, [])
    }

    /// Like [Self::e2ei_rotate_notify], but also when notifying other members, call [SessionContext::verify_sender_identity].
    pub async fn e2ei_rotate_notify_and_verify_sender(
        self,
        credential_bundle: Option<&CredentialBundle>,
    ) -> TestConversation<'a> {
        self.e2ei_rotate(credential_bundle)
            .await
            .notify_members_and_verify_sender()
            .await
    }

    /// Replace the existing credential with an x509 one.
    pub async fn e2ei_rotate(self, credential_bundle: Option<&CredentialBundle>) -> OperationGuard<'a, Commit> {
        self.guard().await.e2ei_rotate(credential_bundle).await.unwrap();
        let commit = self.transport().await.latest_commit_bundle().await.commit;
        let committer_index = self.actor_index();
        OperationGuard::new(TestOperation::Update, commit, self, [committer_index])
    }

    /// Commit all proposals pending in the actor's conversation state and notify all members.
    pub async fn commit_pending_proposals_notify(self) -> TestConversation<'a> {
        self.commit_pending_proposals().await.notify_members().await
    }

    /// Commit all proposals pending in the actor's conversation state.
    pub async fn commit_pending_proposals(self) -> OperationGuard<'a, Commit> {
        self.guard().await.commit_pending_proposals().await.unwrap();
        let commit = self.transport().await.latest_commit().await;
        let actor_index = self.actor_index();
        OperationGuard::new(
            // Committing pending proposals is equivalent to an update
            TestOperation::Update,
            commit,
            self,
            [actor_index],
        )
    }

    /// Create a commit for pending proposals that hasn't been merged by the actor.
    /// On [OperationGuard::notify_members], the actor will receive this commit.
    pub async fn commit_pending_proposals_unmerged(self) -> OperationGuard<'a, Commit> {
        let mut conversation_guard = self.guard().await;
        let commit = conversation_guard
            .commit_pending_proposals_inner()
            .await
            .unwrap()
            .expect("should have pending proposals")
            .commit;
        // Committing pending proposals is equivalent to an update
        OperationGuard::new(TestOperation::Update, commit, self, [])
    }

    /// Remove this member from this conversation.
    /// Notify all members of the conversation.
    ///
    /// Panics if you try to remove the current actor (by default, the conversation creator);
    /// Panics if you try to remove someone who is not a current member.
    pub async fn remove_notify(self, member: &'a SessionContext) -> TestConversation<'a> {
        self.remove(member).await.notify_members().await
    }

    /// Remove this member from this conversation.
    ///
    /// Panics if you try to remove the current actor (by default, the conversation creator);
    /// Panics if you try to remove someone who is not a current member.
    pub async fn remove(self, member: &'a SessionContext) -> OperationGuard<'a, Commit> {
        let member_id = member.session.id().await.unwrap();
        assert_ne!(
            member_id,
            self.actor().session.id().await.unwrap(),
            "cannot remove the actor because we're acting on the actor's behalf."
        );

        // removing the member here removes it from the creator and also produces a commit
        self.guard().await.remove_members(&[member_id]).await.unwrap();
        let commit = self.transport().await.latest_commit().await;
        let actor_index = self.actor_index();

        OperationGuard::new(TestOperation::Remove(member), commit, self, [actor_index])
    }

    /// The supplied session joins this conversation by external commit.
    /// The group info needed for this is exported from the state of the actor.
    pub async fn external_join_notify(self, joiner: &'a SessionContext) -> TestConversation<'a> {
        self.external_join(joiner).await.notify_members().await
    }

    /// Like [Self::external_join_notify], but with the provided group info instead of the actor's one.
    pub async fn external_join_via_group_info_notify(
        self,
        joiner: &'a SessionContext,
        group_info: VerifiableGroupInfo,
    ) -> TestConversation<'a> {
        self.external_join_via_group_info(joiner, group_info)
            .await
            .notify_members()
            .await
    }

    /// The supplied session joins this conversation by external commit.
    /// The group info needed for this is exported from the state of the actor.
    pub async fn external_join(self, joiner: &'a SessionContext) -> OperationGuard<'a, Commit> {
        let group_info = self.actor().get_group_info(&self.id).await;
        self.external_join_via_group_info(joiner, group_info).await
    }

    /// The supplied session joins this conversation by external commit.
    /// The group info needed for this is exported from the state of the actor.
    pub async fn external_join_via_group_info(
        self,
        joiner: &'a SessionContext,
        group_info: VerifiableGroupInfo,
    ) -> OperationGuard<'a, Commit> {
        joiner
            .transaction
            .join_by_external_commit(group_info, self.case.custom_cfg(), self.case.credential_type)
            .await
            .unwrap();
        let join_commit = joiner.mls_transport().await.latest_commit().await;

        // if this is a rejoin, make sure that the joiner doesn't receive their join commit again
        let already_notified: &[usize] = if self.is_member(joiner).await {
            &[self.member_index(joiner).await]
        } else {
            &[]
        };

        OperationGuard::new(
            TestOperation::ExternalJoin(joiner),
            join_commit,
            self,
            already_notified.iter().copied(),
        )
    }

    /// Like [Self::external_join_notify], but with "unmerged" state on the joiners session. To merge, call [PendingConversation::merge].
    pub async fn external_join_unmerged_notify(
        self,
        joiner: &'a SessionContext,
    ) -> (TestConversation<'a>, PendingConversation) {
        let group_info = self.actor().get_group_info(self.id()).await;
        let (commit_guard, pending_conversation) = self.external_join_via_group_info_unmerged(joiner, group_info).await;
        (commit_guard.notify_members().await, pending_conversation)
    }

    /// Like [Self::external_join], but with "unmerged" state on the joiners session. To merge, call [PendingConversation::merge].
    pub async fn external_join_unmerged(
        self,
        joiner: &'a SessionContext,
    ) -> (OperationGuard<'a, Commit>, PendingConversation) {
        let group_info = self.actor().get_group_info(self.id()).await;
        self.external_join_via_group_info_unmerged(joiner, group_info).await
    }

    /// The supplied session joins this conversation by external commit, but doesn't merge it yet.
    ///
    /// This does _not_ distribute the external commit to the existing members. To do that,
    /// use the [`notify_existing_members` method][CommitGuard::notify_members] of
    /// the returned item.
    pub async fn external_join_via_group_info_unmerged(
        self,
        joiner: &'a SessionContext,
        group_info: VerifiableGroupInfo,
    ) -> (OperationGuard<'a, Commit>, PendingConversation) {
        let (join_commit, _, pending_conversation) = joiner
            .transaction
            .create_external_join_commit(group_info, self.case.custom_cfg(), self.case.credential_type)
            .await
            .unwrap();

        // if this is a rejoin, make sure that the joiner doesn't receive their join commit again
        let already_notified: &[usize] = if self.is_member(joiner).await {
            &[self.member_index(joiner).await]
        } else {
            &[]
        };

        (
            OperationGuard::new(
                TestOperation::ExternalJoin(joiner),
                join_commit.commit,
                self,
                already_notified.iter().copied(),
            ),
            pending_conversation,
        )
    }

    /// Enable history sharing and instantiate a history client.
    pub async fn enable_history_sharing_notify(mut self) -> Self {
        self.actor().setup_history_observer().await;
        self.guard().await.enable_history_sharing().await.unwrap();
        let ephemeral_client = self.instantiate_history_client().await;
        self.history_client.replace(ephemeral_client);
        self.notify_about_enabled_history_sharing().await
    }

    async fn instantiate_history_client(&self) -> SessionContext {
        let history_secret = self
            .actor()
            .history_observer()
            .await
            .observed_history_clients()
            .await
            .pop()
            .expect("observed history client")
            .1;

        let ephemeral_client = crate::CoreCrypto::history_client(history_secret).await.unwrap();

        SessionContext::new_from_cc(self.case, ephemeral_client, None).await
    }

    async fn notify_about_enabled_history_sharing(self) -> Self {
        let message = self.transport().await.latest_commit().await;
        let actor_index = self.actor_index();

        let commit = OperationGuard::<Commit>::new(TestOperation::HistorySharingEnabled, message, self, [actor_index]);
        commit.notify_members().await
    }

    /// Disable history sharing and remove the history client.
    pub async fn disable_history_sharing_notify(self) -> Self {
        self.guard().await.disable_history_sharing().await.unwrap();
        let message = self.transport().await.latest_commit().await;
        let actor_index = self.actor_index();

        let commit = OperationGuard::<Commit>::new(TestOperation::HistorySharingDisabled, message, self, [actor_index]);
        commit.notify_members().await
    }
}
