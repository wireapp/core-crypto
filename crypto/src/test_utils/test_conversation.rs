use std::sync::Arc;

use openmls::prelude::MlsMessageOut;

use crate::prelude::ConversationId;

use super::{MlsTransportTestExt, SessionContext, TestContext, conversation_id};

pub struct TestConversation<'a> {
    pub(crate) case: &'a TestContext,
    pub(crate) id: ConversationId,
    pub(crate) creator: &'a SessionContext,
    pub(crate) joiners: Vec<&'a SessionContext>,
}

impl<'a> TestConversation<'a> {
    pub async fn new(case: &'a TestContext, creator: &'a SessionContext) -> Self {
        let id = conversation_id();
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
}

/// This struct encapsulates the result of a join by external commit.
///
/// To notify all existing members of the conversation, call [`Self::notify_existing_members`].
/// Otherwise, use the struct members to do things manually.
pub struct ExternalJoinGuard<'a> {
    conversation_id: &'a ConversationId,
    pub(crate) previous_conversation_members: Vec<&'a SessionContext>,
    // this is dead code for now, but we expect to use it in the relatively near future
    // once we start using this in tests. At that point, remove the annotation.
    #[expect(dead_code)]
    pub(crate) joiner: &'a SessionContext,
    pub(crate) join_commit: MlsMessageOut,
}

impl ExternalJoinGuard<'_> {
    pub async fn notify_existing_members(self) {
        let message_bytes = self.join_commit.to_bytes().unwrap();
        for member in self.previous_conversation_members {
            member
                .transaction
                .conversation(self.conversation_id)
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
    pub async fn external_join(&'a mut self, joiner: &'a SessionContext) -> ExternalJoinGuard<'a> {
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

        ExternalJoinGuard {
            conversation_id: &self.id,
            previous_conversation_members,
            joiner,
            join_commit,
        }
    }
}

impl AsRef<ConversationId> for TestConversation<'_> {
    fn as_ref(&self) -> &ConversationId {
        &self.id
    }
}
