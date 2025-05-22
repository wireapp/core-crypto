use std::{marker::PhantomData, sync::Arc};

use openmls::prelude::{MlsMessageOut, group_info::VerifiableGroupInfo};

use crate::{mls::conversation::ConversationGuard, prelude::ConversationId};

use super::{MlsTransportTestExt, SessionContext, TestContext};

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
            proposals: vec![],
            actor_index: None,
        }
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
            operation: TestOperation::Add(AddGuard {
                committer_index: actor_index,
                new_members,
            }),
            message: commit,
            _message_type: PhantomData,
        }
    }

    pub async fn invite_proposal(self, session: &'a SessionContext) -> TestConversation<'a> {
        self.invite_proposal_guarded(session).await.notify_members().await
    }

    pub async fn invite_proposal_guarded(self, new_member: &'a SessionContext) -> OperationGuard<'a, Proposal> {
        let proposer = self.actor();
        let key_package = new_member.rand_key_package(self.case).await;
        let proposal = proposer
            .transaction
            .new_add_proposal(self.id(), key_package.into())
            .await
            .unwrap()
            .proposal;
        let proposer_index = self.member_index(proposer).await;
        OperationGuard {
            conversation: self,
            operation: TestOperation::Add(AddGuard {
                committer_index: proposer_index,
                new_members: vec![new_member],
            }),
            message: proposal,
            _message_type: PhantomData,
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
            operation: TestOperation::Update(committer_index),
            message: commit,
            _message_type: PhantomData,
        }
    }

    pub async fn update_proposal(self) -> TestConversation<'a> {
        self.update_proposal_guarded().await.notify_members().await
    }

    pub async fn update_proposal_guarded(self) -> OperationGuard<'a, Proposal> {
        let proposer = self.actor();
        let proposal = proposer
            .transaction
            .new_update_proposal(self.id())
            .await
            .unwrap()
            .proposal;
        let proposer_index = self.actor_index();
        OperationGuard {
            conversation: self,
            operation: TestOperation::Update(proposer_index),
            message: proposal,
            _message_type: PhantomData,
        }
    }

    pub async fn remove_proposal(self, member: &'a SessionContext) -> TestConversation<'a> {
        self.remove_proposal_guarded(member).await.notify_members().await
    }

    pub async fn remove_proposal_guarded(self, member: &'a SessionContext) -> OperationGuard<'a, Proposal> {
        let proposer = self.actor();
        let member_id = member.session.id().await.unwrap();
        let proposal = proposer
            .transaction
            .new_remove_proposal(self.id(), member_id)
            .await
            .unwrap()
            .proposal;
        let proposer_index = self.actor_index();
        OperationGuard {
            conversation: self,
            operation: TestOperation::Remove(proposer_index, member),
            message: proposal,
            _message_type: PhantomData,
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
            operation: TestOperation::Update(actor_index),
            message: commit,
            _message_type: PhantomData,
        }
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

    fn member_at_index(&self, idx: usize) -> &SessionContext {
        self.members.get(idx).expect("member list smaller than expected")
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
            operation: TestOperation::Remove(actor_index, member),
            message: commit,
            _message_type: PhantomData,
        }
    }
}

pub struct Commit;
pub struct Proposal;

/// This struct encapsulates the result of an operation that creates a commit.
///
/// To notify all existing members of the conversation, call [`Self::notify_existing_members`].
/// Otherwise, use the struct members to do things manually.
pub struct OperationGuard<'a, MessageType> {
    conversation: TestConversation<'a>,
    /// The member at this index won't be included in the list of [Self::members_to_notify]
    operation: TestOperation<'a>,
    pub(crate) message: MlsMessageOut,
    _message_type: PhantomData<MessageType>,
}

struct AddGuard<'a> {
    committer_index: usize,
    new_members: Vec<&'a SessionContext>,
}

/// Keeps state about the comitted operation that will be used when the
/// corresponding [CommitGuard] is used to (notify members)[CommitGuard::notify_members].
enum TestOperation<'a> {
    /// The member with the provided index won't be notified, new members will be
    /// added to the member list of the test conversation
    Add(AddGuard<'a>),
    /// All existing members will be notified, the new joiner will be added to the
    /// member list of the conversation.
    ExternalJoin(&'a SessionContext),
    /// The member with the provided index won't be notified
    Update(usize),
    /// The member with the provided index won't be notified, the provided [SessionContext]
    /// will be removed from the members list.
    Remove(usize, &'a SessionContext),
}

impl<'a, T> OperationGuard<'a, T> {
    pub fn conversation(&self) -> &'a TestConversation {
        &self.conversation
    }

    // Call this once you're finished with manual processing and need mutable access
    // to the [TestConversation] again.
    pub fn finish(mut self) -> TestConversation<'a> {
        self.conversation.actor_index = None;
        self.conversation
    }

    pub fn message(&self) -> MlsMessageOut {
        self.message.clone()
    }

    fn members_to_notify(&self) -> Box<dyn Iterator<Item = &'a SessionContext> + '_> {
        match self.operation {
            TestOperation::Add(AddGuard {
                committer_index: skipped_index,
                ..
            })
            | TestOperation::Remove(skipped_index, ..)
            | TestOperation::Update(skipped_index) => Box::new(
                self.conversation
                    .members
                    .iter()
                    .enumerate()
                    .filter_map(move |(idx, member)| (idx != skipped_index).then_some(*member)),
            ),
            TestOperation::ExternalJoin(_) => Box::new(self.conversation.members.iter().copied()),
        }
    }
}

impl<'a> OperationGuard<'a, Commit> {
    pub async fn notify_members(mut self) -> TestConversation<'a> {
        let message_bytes = self.message.to_bytes().unwrap();
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

        // Do the following for each proposal that is still pending and the latest commit:
        // In case of a remove, an external join or an add operation, update the member list
        // of the test conversation.
        for operation in self
            .conversation
            .proposals
            .iter()
            .chain(std::iter::once(&self.operation))
        {
            match operation {
                TestOperation::Update(_) => {}
                TestOperation::Remove(_, member) => {
                    let member_idx = self.conversation().member_index(member).await;
                    self.conversation.members.remove(member_idx);
                }
                TestOperation::ExternalJoin(joiner) => {
                    self.conversation.members.push(joiner);
                }
                TestOperation::Add(AddGuard {
                    new_members: invited_members,
                    committer_index,
                }) => {
                    let welcome_message = self
                        .conversation()
                        .member_at_index(*committer_index)
                        .mls_transport()
                        .await
                        .latest_commit_bundle()
                        .await
                        .welcome
                        .expect("we're processing an add operation, so there must be a welcome message");
                    // Process welcome message on receiver side
                    for new_member in invited_members.iter() {
                        new_member
                            .transaction
                            .process_welcome_message(
                                welcome_message.clone().into(),
                                self.conversation.case.custom_cfg(),
                            )
                            .await
                            .unwrap();
                    }
                    // Then update the member list
                    self.conversation.members.reserve(invited_members.len());
                    self.conversation.members.extend(invited_members);
                }
            }
        }
        self.conversation.actor_index = None;
        self.conversation.proposals.clear();
        self.conversation
    }
}

impl<'a> OperationGuard<'a, Proposal> {
    /// Notify all members about the proposal.
    pub async fn notify_members(mut self) -> TestConversation<'a> {
        let message_bytes = self.message.to_bytes().unwrap();
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

        // Remember the proposal for later so we can update member lists accordingly.
        self.conversation.proposals.push(self.operation);
        self.conversation.actor_index = None;

        self.conversation
    }
}

impl<'a> TestConversation<'a> {
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

        OperationGuard {
            conversation: self,
            operation: TestOperation::ExternalJoin(joiner),
            message: join_commit,
            _message_type: PhantomData,
        }
    }
}
