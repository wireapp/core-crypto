use openmls::prelude::group_info::VerifiableGroupInfo;
use std::marker::PhantomData;

use crate::mls::conversation::pending_conversation::PendingConversation;

use super::super::SessionContext;
use super::TestConversation;
use super::operation_guard::AddGuard;
use super::operation_guard::Commit;
use super::operation_guard::OperationGuard;
use super::operation_guard::TestOperation;

impl<'a> TestConversation<'a> {
    /// Invite all sessions into this conversation and notify all members, old and new.
    pub async fn invite(self, sessions: impl IntoIterator<Item = &'a SessionContext>) -> TestConversation<'a> {
        let commit_guard = self.invite_guarded(sessions).await;
        commit_guard.notify_members().await
    }

    /// Invites all sessions into this conversation. Call [CommitGuard::notify_members] to notify other members.
    pub async fn invite_guarded(
        self,
        sessions: impl IntoIterator<Item = &'a SessionContext>,
    ) -> OperationGuard<'a, Commit> {
        let new_members = sessions.into_iter().collect::<Vec<_>>();

        let key_packages =
            futures_util::future::join_all(new_members.iter().map(|cc| cc.rand_key_package(self.case))).await;
        self.guard().await.add_members(key_packages).await.unwrap();
        let commit = self.transport().await.latest_commit_bundle().await.commit;
        let actor_index = self.actor_index();
        OperationGuard {
            conversation: self,
            operation: TestOperation::Add(AddGuard { new_members }),
            message: commit,
            _message_type: PhantomData,
            already_notified: [actor_index].into(),
        }
    }

    /// Advance the epoch (by updating the creator's key material) and notify all members.
    pub async fn advance_epoch(self) -> TestConversation<'a> {
        self.update().await
    }

    pub async fn update(self) -> TestConversation<'a> {
        self.update_guarded().await.notify_members().await
    }

    pub async fn update_guarded(self) -> OperationGuard<'a, Commit> {
        self.guard().await.update_key_material().await.unwrap();
        let commit = self.transport().await.latest_commit_bundle().await.commit;
        let committer_index = self.actor_index();
        OperationGuard {
            conversation: self,
            operation: TestOperation::Update,
            message: commit,
            _message_type: PhantomData,
            already_notified: [committer_index].into(),
        }
    }

    pub async fn commit_pending_proposals(self) -> TestConversation<'a> {
        self.commit_pending_proposals_guarded().await.notify_members().await
    }

    pub async fn commit_pending_proposals_guarded(self) -> OperationGuard<'a, Commit> {
        self.guard().await.commit_pending_proposals().await.unwrap();
        let commit = self.transport().await.latest_commit().await;
        let actor_index = self.actor_index();
        OperationGuard {
            conversation: self,
            // Comitting pending proposals is equivalent to an update
            operation: TestOperation::Update,
            message: commit,
            _message_type: PhantomData,
            already_notified: [actor_index].into(),
        }
    }

    /// See [Self::remove_guarded].
    pub async fn remove(self, member: &'a SessionContext) -> TestConversation<'a> {
        self.remove_guarded(member).await.notify_members().await
    }

    /// Remove this member from this conversation.
    ///
    /// Applies the removal to all members of the conversation.
    ///
    /// Panics if you try to remove the current actor (by default, the conversation creator);
    /// Panics if you try to remove someone who is not a current member.
    pub async fn remove_guarded(self, member: &'a SessionContext) -> OperationGuard<'a, Commit> {
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

        OperationGuard {
            conversation: self,
            operation: TestOperation::Remove(member),
            message: commit,
            _message_type: PhantomData,
            already_notified: [actor_index].into(),
        }
    }
    /// See [Self::external_join_guarded]
    pub async fn external_join(self, joiner: &'a SessionContext) -> TestConversation<'a> {
        self.external_join_guarded(joiner).await.notify_members().await
    }

    pub async fn external_join_via_group_info(
        self,
        joiner: &'a SessionContext,
        group_info: VerifiableGroupInfo,
    ) -> TestConversation<'a> {
        self.external_join_via_group_info_guarded(joiner, group_info)
            .await
            .notify_members()
            .await
    }

    /// The supplied session joins this conversation by external commit.
    ///
    /// This does _not_ distribute the external commit to the existing members. To do that,
    /// use the [`notify_existing_members` method][CommitGuard::notify_members] of
    /// the returned item.
    pub async fn external_join_guarded(self, joiner: &'a SessionContext) -> OperationGuard<'a, Commit> {
        let group_info = self.actor().get_group_info(&self.id).await;
        self.external_join_via_group_info_guarded(joiner, group_info).await
    }

    /// The supplied session joins this conversation by external commit. The group info is taken from the latest
    ///
    /// This does _not_ distribute the external commit to the existing members. To do that,
    /// use the [`notify_existing_members` method][CommitGuard::notify_members] of
    /// the returned item.
    pub async fn external_join_via_group_info_guarded(
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
        let already_notified = if self.is_member(joiner).await {
            [self.member_index(joiner).await].into()
        } else {
            [].into()
        };

        OperationGuard {
            conversation: self,
            operation: TestOperation::ExternalJoin(joiner),
            message: join_commit,
            _message_type: PhantomData,
            already_notified,
        }
    }

    pub async fn unmerged_external_join(
        self,
        joiner: &'a SessionContext,
    ) -> (TestConversation<'a>, PendingConversation) {
        let group_info = self.actor().get_group_info(self.id()).await;
        let (commit_guard, pending_conversation) = self
            .umerged_external_join_via_group_info_guarded(joiner, group_info)
            .await;
        (commit_guard.notify_members().await, pending_conversation)
    }

    pub async fn unmerged_external_join_guarded(
        self,
        joiner: &'a SessionContext,
    ) -> (OperationGuard<'a, Commit>, PendingConversation) {
        let group_info = self.actor().get_group_info(self.id()).await;
        self.umerged_external_join_via_group_info_guarded(joiner, group_info)
            .await
    }

    /// The supplied session joins this conversation by external commit, but doesn't merge it yet.
    ///
    /// This does _not_ distribute the external commit to the existing members. To do that,
    /// use the [`notify_existing_members` method][CommitGuard::notify_members] of
    /// the returned item.
    pub async fn umerged_external_join_via_group_info_guarded(
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
        let already_notified = if self.is_member(joiner).await {
            [self.member_index(joiner).await].into()
        } else {
            [].into()
        };

        (
            OperationGuard {
                conversation: self,
                operation: TestOperation::ExternalJoin(joiner),
                message: join_commit.commit,
                _message_type: PhantomData,
                already_notified,
            },
            pending_conversation,
        )
    }
}
