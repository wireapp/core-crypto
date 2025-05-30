mod commit;
pub(crate) mod operation_guard;
mod proposal;

use std::sync::Arc;

use crate::{
    mls::conversation::{Conversation, ConversationGuard, ConversationWithMls as _},
    prelude::{ConversationId, E2eiConversationState, MlsProposalRef},
};

use super::{MlsCredentialType, MlsTransportTestExt, SessionContext, TestContext};

use operation_guard::TestOperation;

#[derive(derive_more::AsRef)]
pub struct TestConversation<'a> {
    pub(crate) case: &'a TestContext,
    #[as_ref]
    pub(crate) id: ConversationId,
    pub(crate) members: Vec<&'a SessionContext>,
    proposals: Vec<TestOperation<'a>>,
    actor_index: Option<usize>,
}

impl<'a> TestConversation<'a> {
    pub async fn new(case: &'a TestContext, creator: &'a SessionContext) -> Self {
        Self::new_with_credential_type(case, creator, case.credential_type).await
    }

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
            proposals: vec![],
            actor_index: None,
        };
        assert!(conversation.is_functional_with(conversation.members()).await);
        conversation
    }

    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    /// Count the members. Also, assert that the count is the same from the point of view of every member.
    pub async fn member_count(&self) -> usize {
        let member_count = self.members.len();

        let member_counts_match = futures_util::future::join_all(
            self.members()
                .map(|member| member.get_conversation_unchecked(self.id())),
        )
        .await
        .iter()
        .map(|conv| conv.members().len())
        .all(|count| count == member_count);
        assert!(member_counts_match);
        member_count
    }

    /// Let a conversation member provide the member count (according to their current state).
    pub async fn members_counted_by(&self, member: &SessionContext) -> usize {
        member.get_conversation_unchecked(self.id()).await.members().len()
    }

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

    pub async fn is_member(&self, member: &SessionContext) -> bool {
        self.are_members([member]).await
    }

    /// Check if the provided members are in the conversation and all members can talk to one another.
    pub async fn is_functional_with(&self, members_to_check: impl IntoIterator<Item = &'a SessionContext>) -> bool {
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

    pub async fn can_talk(&self, member: &SessionContext, other_member: &SessionContext) -> bool {
        member.try_talk_to(self.id(), other_member).await.is_ok()
    }

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
        self.members.iter().copied()
    }

    /// Convenience function to get the mls transport of the creator.
    pub async fn transport(&self) -> Arc<dyn MlsTransportTestExt> {
        self.actor().mls_transport().await
    }

    /// Convenience function to get the conversation guard of this conversation.
    ///
    /// The guard belongs to the creator of the conversation.
    pub async fn guard(&self) -> ConversationGuard {
        self.guard_of(self.actor()).await
    }

    /// Get the conversation guard of this conversation, from the point of view of the
    /// member.
    pub async fn guard_of(&self, member: &'a SessionContext) -> ConversationGuard {
        member.transaction.conversation(&self.id).await.unwrap()
    }

    pub async fn e2ei_state(&self) -> E2eiConversationState {
        self.e2ei_state_of(self.actor()).await
    }

    pub async fn e2ei_state_of(&self, member: &'a SessionContext) -> E2eiConversationState {
        self.guard_of(member).await.e2ei_conversation_state().await.unwrap()
    }

    pub async fn e2ei_state_via_group_info(&self) -> E2eiConversationState {
        let gi = self.actor().get_group_info(self.id()).await;

        self.actor()
            .transaction
            .get_credential_in_use(gi, MlsCredentialType::X509)
            .await
            .unwrap()
    }

    pub async fn latest_proposal_ref(&self) -> MlsProposalRef {
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

    pub async fn pending_proposal_count(&self) -> usize {
        let guard = self.guard().await;
        guard.conversation().await.group().pending_proposals().count()
    }

    pub async fn has_pending_proposals(&self) -> bool {
        let guard = self.guard().await;
        guard.conversation().await.group().pending_proposals().next().is_some()
    }

    pub async fn has_pending_commit(&self) -> bool {
        let guard = self.guard().await;
        guard.conversation().await.group().pending_commit().is_some()
    }

    async fn member_index(&self, member: &SessionContext) -> usize {
        let member_id = member.session.id().await.unwrap();

        // can't use `Iterator::position` because getting the id is async
        let mut member_idx = None;
        for (idx, member) in self.members.iter().enumerate() {
            let joiner_id = member.session.id().await.unwrap();
            if joiner_id == member_id {
                member_idx = Some(idx);
                break;
            }
        }

        member_idx.expect("could find the member to remove among the joiners of this conversation")
    }
}
