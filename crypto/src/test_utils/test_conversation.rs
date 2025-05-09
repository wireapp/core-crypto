use crate::prelude::ConversationId;

use super::{SessionContext, TestContext, conversation_id};

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
}

impl AsRef<ConversationId> for TestConversation<'_> {
    fn as_ref(&self) -> &ConversationId {
        &self.id
    }
}
