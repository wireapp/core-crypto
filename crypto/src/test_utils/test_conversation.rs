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
    pub(crate) creator: &'a SessionContext,
    pub(crate) joiners: Vec<&'a SessionContext>,
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
            creator,
            joiners: Vec::new(),
        }
    }

    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    /// Invite all sessions into this conversation.
    pub async fn invite(&mut self, sessions: impl IntoIterator<Item = &'a SessionContext>) {
        let idx_of_first_new_member = self.joiners.len();
        let sessions = sessions.into_iter();
        let (lower_bound, _) = sessions.size_hint();
        self.joiners.reserve(lower_bound);
        self.joiners.extend(sessions);

        self.creator
            .invite_all(
                self.case,
                &self.id,
                self.joiners[idx_of_first_new_member..].iter().copied(),
            )
            .await
            .expect("all invitations succeeded");
    }

    /// All members of this conversation.
    ///
    /// The creator is always the first member returned.
    pub fn members(&self) -> impl Iterator<Item = &SessionContext> {
        std::iter::once(self.creator).chain(self.joiners.iter().copied())
    }

    /// Convenience function to get the mls transport of the creator.
    pub fn transport(&self) -> Arc<dyn MlsTransportTestExt> {
        self.creator.mls_transport.clone()
    }

    /// Convenience function to get the conversation guard of this conversation.
    ///
    /// The guard belongs to the creator of the conversation.
    pub async fn guard(&self) -> ConversationGuard {
        self.creator.transaction.conversation(&self.id).await.unwrap()
    }

    /// Remove this member from this conversation.
    ///
    /// Applies the removal to all members of the conversation.
    ///
    /// Panics if you try to remove the conversation creator; use a different abstraction if you are testing that case.
    /// Panics if you try to remove someone who is not a current member.
    pub async fn remove(&mut self, member_id: &ClientId) -> &'a SessionContext {
        // can't use `Iterator::position` because getting the id is async
        let mut joiner_idx = None;
        for (idx, joiner) in self.joiners.iter().enumerate() {
            let joiner_id = joiner.session.id().await.unwrap();
            if joiner_id == *member_id {
                joiner_idx = Some(idx);
                break;
            }
        }

        // if we didn't find it, return early instead of trying to apply that removal to the conversation
        let removed = joiner_idx
            .map(|idx| self.joiners.swap_remove(idx))
            .expect("could find the member to remove among the joiners of this conversation");

        // removing the member here removes it from the creator and also produces a commit
        self.guard()
            .await
            .remove_members(&[member_id.to_owned()])
            .await
            .unwrap();
        let commit = self.transport().latest_commit().await.to_bytes().unwrap();

        // we already removed the member from the joined members of our conversation, so chain it in
        for joiner in std::iter::once(removed).chain(self.joiners.iter().copied()) {
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
    conversation: &'a TestConversation<'a>,
    pub(crate) members_to_notify: Vec<&'a SessionContext>,
    // this is dead code for now, but we expect to use it in the relatively near future
    // once we start using this in tests. At that point, remove the annotation.
    #[expect(dead_code)]
    pub(crate) committer: &'a SessionContext,
    pub(crate) commit: MlsMessageOut,
}

impl CommitGuard<'_> {
    pub async fn notify_members(self) {
        let message_bytes = self.commit.to_bytes().unwrap();
        for member in self.members_to_notify {
            member
                .transaction
                .conversation(&self.conversation.id)
                .await
                .unwrap()
                .decrypt_message(&message_bytes)
                .await
                .unwrap();
        }
    }
}

impl<'a> TestConversation<'a> {
    /// The supplied session joins this conversation by external commit.
    ///
    /// This does _not_ distribute the external commit to the existing members. To do that,
    /// use the [`notify_existing_members` method][ExternalJoinGuard::notify_existing_members] of
    /// the returned item.
    pub async fn external_join(&'a mut self, joiner: &'a SessionContext) -> CommitGuard<'a> {
        let group_info = self.creator.get_group_info(&self.id).await;
        joiner
            .transaction
            .join_by_external_commit(group_info, self.case.custom_cfg(), self.case.credential_type)
            .await
            .unwrap();
        let join_commit = joiner.mls_transport.latest_commit().await;

        let mut previous_conversation_members = Vec::with_capacity(self.joiners.len() + 1);
        previous_conversation_members.push(self.creator);
        previous_conversation_members.extend(self.joiners.iter().copied());

        self.joiners.push(joiner);

        CommitGuard {
            conversation: self,
            members_to_notify: previous_conversation_members,
            committer: joiner,
            commit: join_commit,
        }
    }
}
