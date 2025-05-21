use std::sync::Arc;

use openmls::prelude::MlsMessageOut;

use crate::{
    mls::conversation::ConversationGuard,
    prelude::{ClientId, ConversationId},
};

use super::{MlsTransportTestExt, SessionContext, TestContext};

#[derive(derive_more::AsRef)]
pub struct TestConversation<'a> {
    pub(crate) case: &'a TestContext,
    #[as_ref]
    pub(crate) id: ConversationId,
    pub(crate) members: Vec<&'a SessionContext>,
}

impl<'a> TestConversation<'a> {
    pub async fn new(case: &'a TestContext, creator: &'a SessionContext) -> Self {
        let id = super::conversation_id();
        creator
            .transaction
            .new_conversation(&id, case.credential_type, case.cfg.clone())
            .await
            .unwrap();

        Self {
            case,
            id,
            members: vec![creator],
        }
    }

    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    /// Invite all sessions into this conversation and notify all members, old and new.
    pub async fn invite_and_notify(&'a mut self, sessions: impl IntoIterator<Item = &'a SessionContext>) {
        let commit_guard = self.invite(sessions).await;
        commit_guard.notify_members().await;
    }

    pub async fn invite(&'a mut self, sessions: impl IntoIterator<Item = &'a SessionContext>) -> CommitGuard<'a> {
        let new_members = sessions.into_iter().collect::<Vec<_>>();

        let key_packages =
            futures_util::future::join_all(new_members.iter().map(|cc| cc.rand_key_package(self.case))).await;
        self.guard().await.add_members(key_packages).await.unwrap();
        let welcome = self.transport().latest_commit_bundle().await.welcome.unwrap();
        let commit = self.transport().latest_commit_bundle().await.commit;
        CommitGuard {
            conversation: self,
            committed_operation: CommittedOperation::Add(AddGuard {
                committer_index: 0,
                new_members,
                welcome_message: welcome,
            }),
            commit,
        }
    }

    pub fn creator(&self) -> &SessionContext {
        self.members[0]
    }

    /// All members of this conversation.
    ///
    /// The creator is always the first member returned (if they're still a member).
    pub fn members(&self) -> impl Iterator<Item = &SessionContext> {
        self.members.iter().copied()
    }

    /// Convenience function to get the mls transport of the creator.
    pub fn transport(&self) -> Arc<dyn MlsTransportTestExt> {
        self.creator().mls_transport.clone()
    }

    /// Convenience function to get the conversation guard of this conversation.
    ///
    /// The guard belongs to the creator of the conversation.
    pub async fn guard(&self) -> ConversationGuard {
        self.creator().transaction.conversation(&self.id).await.unwrap()
    }

    /// Remove this member from this conversation.
    ///
    /// Applies the removal to all members of the conversation.
    ///
    /// Panics if you try to remove the conversation creator; use a different abstraction if you are testing that case.
    /// Panics if you try to remove someone who is not a current member.
    pub async fn remove(&mut self, member_id: &ClientId) -> &'a SessionContext {
        assert_ne!(
            &self.creator().session.id().await.unwrap(),
            member_id,
            "cannot remove the creator via this API because we're acting on the creators behalf."
        );
        // can't use `Iterator::position` because getting the id is async
        let mut joiner_idx = None;
        for (idx, joiner) in self.members.iter().enumerate() {
            let joiner_id = joiner.session.id().await.unwrap();
            if joiner_id == *member_id {
                joiner_idx = Some(idx);
                break;
            }
        }

        // if we didn't find it, return early instead of trying to apply that removal to the conversation
        let removed = joiner_idx
            .map(|idx| self.members.swap_remove(idx))
            .expect("could find the member to remove among the joiners of this conversation");

        // removing the member here removes it from the creator and also produces a commit
        self.guard()
            .await
            .remove_members(&[member_id.to_owned()])
            .await
            .unwrap();
        let commit = self.transport().latest_commit().await.to_bytes().unwrap();

        // we already removed the member from the joined members of our conversation, so chain it in
        for joiner in std::iter::once(removed).chain(self.members.iter().copied()) {
            joiner
                .transaction
                .conversation(&self.id)
                .await
                .unwrap()
                .decrypt_message(&commit)
                .await
                .unwrap();
        }

        // gone from everyone's mls state and the conversation joiners, so we're done
        removed
    }
}

/// This struct encapsulates the result of an operation that creates a commit.
///
/// To notify all existing members of the conversation, call [`Self::notify_existing_members`].
/// Otherwise, use the struct members to do things manually.
pub struct CommitGuard<'a> {
    conversation: &'a mut TestConversation<'a>,
    /// The member at this index won't be included in the list of [Self::members_to_notify]
    committed_operation: CommittedOperation<'a>,
    pub(crate) commit: MlsMessageOut,
}

struct AddGuard<'a> {
    committer_index: usize,
    new_members: Vec<&'a SessionContext>,
    welcome_message: MlsMessageOut,
}

/// Keeps state about the comitted operation that will be used when the
/// corresponding [CommitGuard] is used to (notify members)[CommitGuard::notify_members].
#[expect(clippy::large_enum_variant)]
enum CommittedOperation<'a> {
    /// The member with the provided index won't be notified, new members will be
    /// added to the member list of the test conversation
    Add(AddGuard<'a>),
    /// All existing members will be notified, the new joiner will be added to the
    /// member list of the conversation.
    ExternalJoin(&'a SessionContext),
}

impl<'a> CommitGuard<'a> {
    fn members_to_notify(&self) -> Box<dyn Iterator<Item = &'a SessionContext> + '_> {
        if let CommittedOperation::Add(AddGuard {
            committer_index: skipped_index,
            ..
        }) = self.committed_operation
        {
            Box::new(
                self.conversation
                    .members
                    .iter()
                    .enumerate()
                    .filter_map(move |(idx, member)| (idx != skipped_index).then_some(*member)),
            )
        } else {
            Box::new(self.conversation.members.iter().copied())
        }
    }

    pub async fn notify_members(self) {
        let message_bytes = self.commit.to_bytes().unwrap();
        for member in self.members_to_notify() {
            member
                .transaction
                .conversation(&self.conversation.id)
                .await
                .unwrap()
                .decrypt_message(&message_bytes)
                .await
                .unwrap();
        }

        // In case of an external join or an add operation, update the member list
        // of the test conversation.
        match self.committed_operation {
            CommittedOperation::ExternalJoin(joiner) => {
                self.conversation.members.push(joiner);
            }
            CommittedOperation::Add(AddGuard {
                new_members: invited_members,
                welcome_message,
                ..
            }) => {
                // Process welcome message on receiver side
                for new_member in invited_members.iter() {
                    new_member
                        .transaction
                        .process_welcome_message(welcome_message.clone().into(), self.conversation.case.custom_cfg())
                        .await
                        .unwrap();
                }
                // Then update the member list
                self.conversation.members.reserve(invited_members.len());
                self.conversation.members.extend(invited_members);
            }
        }
    }
}

impl<'a> TestConversation<'a> {
    /// The supplied session joins this conversation by external commit.
    ///
    /// This does _not_ distribute the external commit to the existing members. To do that,
    /// use the [`notify_existing_members` method][CommitGuard::notify_members] of
    /// the returned item.
    pub async fn external_join(&'a mut self, joiner: &'a SessionContext) -> CommitGuard<'a> {
        let group_info = self.creator().get_group_info(&self.id).await;
        joiner
            .transaction
            .join_by_external_commit(group_info, self.case.custom_cfg(), self.case.credential_type)
            .await
            .unwrap();
        let join_commit = joiner.mls_transport.latest_commit().await;

        CommitGuard {
            conversation: self,
            committed_operation: CommittedOperation::ExternalJoin(joiner),
            commit: join_commit,
        }
    }
}
