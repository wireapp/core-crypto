use crate::prelude::MlsConversationDecryptMessage;

use super::super::SessionContext;
use super::TestConversation;
use openmls::prelude::MlsMessageOut;
use std::collections::HashSet;
use std::marker::PhantomData;

pub struct Commit;

pub struct Proposal;

/// This struct encapsulates the result of an operation that creates a commit.
///
/// To notify all existing members of the conversation, call [`Self::notify_existing_members`].
/// Otherwise, use the struct members to do things manually.
pub struct OperationGuard<'a, MessageType> {
    pub(crate) conversation: TestConversation<'a>,
    /// The members at these indices won't be included in the list of [Self::members_to_notify]
    pub(crate) already_notified: HashSet<usize>,
    pub(crate) operation: TestOperation<'a>,
    pub(crate) message: MlsMessageOut,
    pub(crate) _message_type: PhantomData<MessageType>,
}

pub(crate) struct AddGuard<'a> {
    pub(crate) new_members: Vec<&'a SessionContext>,
}

/// Keeps state about the comitted operation that will be used when the
/// corresponding [CommitGuard] is used to (notify members)[CommitGuard::notify_members].
pub(crate) enum TestOperation<'a> {
    /// New members will added to the member list of the test conversation
    Add(AddGuard<'a>),
    /// All existing members will be notified, the new joiner will be added to the
    /// member list of the conversation.
    ExternalJoin(&'a SessionContext),
    Update,
    /// The provided [SessionContext] will be removed from the members list.
    Remove(&'a SessionContext),
}

impl<'a, T> OperationGuard<'a, T> {
    pub fn conversation(&self) -> &'a TestConversation {
        &self.conversation
    }

    // Call this once you're finished with manual processing and need mutable access
    // to the [TestConversation] again.
    //
    // Note: unlike [Self::notify_members] this does not propagate any state to the
    // [TestConversation]. If you want that behavior, call that method instead.
    pub fn finish(mut self) -> TestConversation<'a> {
        self.conversation.actor_index = None;
        self.conversation
    }

    pub fn message(&self) -> MlsMessageOut {
        self.message.clone()
    }

    pub async fn notify_member(mut self, member: &SessionContext) -> Self {
        let member_index = self.conversation().member_index(member).await;
        if self.already_notified.contains(&member_index) {
            return self;
        }
        self.notify_member_inner(member).await.unwrap();
        self.already_notified.insert(member_index);
        self
    }

    pub async fn notify_member_failible(
        mut self,
        member: &SessionContext,
    ) -> (Self, crate::mls::conversation::Result<MlsConversationDecryptMessage>) {
        let member_index = self.conversation().member_index(member).await;
        if self.already_notified.contains(&member_index) {
            println!("Member was already notified!");
            return (self, Err(crate::mls::conversation::Error::DuplicateMessage));
        }
        let result = self.notify_member_inner(member).await;
        self.already_notified.insert(member_index);
        (self, result)
    }

    async fn notify_member_inner(
        &self,
        member: &SessionContext,
    ) -> crate::mls::conversation::Result<MlsConversationDecryptMessage> {
        let message_bytes = self.message.to_bytes().unwrap();
        member
            .transaction
            .conversation(&self.conversation.id)
            .await
            .unwrap()
            .decrypt_message(&message_bytes)
            .await
    }
}

impl<'a> OperationGuard<'a, Commit> {
    /// Notify all members except the committer and those already notified by
    /// [Self::notify_member].
    pub async fn notify_members(mut self) -> TestConversation<'a> {
        let members = self.conversation.members.clone();
        for member in members.iter() {
            self = self.notify_member(member).await;
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
                TestOperation::Update => {}
                TestOperation::Remove(member) => {
                    let member_idx = self.conversation().member_index(member).await;
                    self.conversation.members.remove(member_idx);
                }
                TestOperation::ExternalJoin(joiner) => {
                    // If this is a rejoin, don't touch the member list
                    if !self.conversation().is_member(joiner).await {
                        self.conversation.members.push(joiner);
                    }
                }
                TestOperation::Add(AddGuard {
                    new_members: invited_members,
                }) => {
                    let welcome_message = self
                        .conversation()
                        .actor()
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
    /// Notify all members except the proposer and those already notified by
    /// [Self::notify_member].
    pub async fn notify_members(mut self) -> TestConversation<'a> {
        let members = self.conversation.members.clone();
        for member in members.iter() {
            self = self.notify_member(member).await;
        }

        // Remember the proposal for later so we can update member lists accordingly.
        self.conversation.proposals.push(self.operation);
        self.conversation.actor_index = None;

        self.conversation
    }
}
