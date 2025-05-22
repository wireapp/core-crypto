use super::super::SessionContext;
use super::TestConversation;
use openmls::prelude::MlsMessageOut;
use std::marker::PhantomData;

pub struct Commit;

pub struct Proposal;

/// This struct encapsulates the result of an operation that creates a commit.
///
/// To notify all existing members of the conversation, call [`Self::notify_existing_members`].
/// Otherwise, use the struct members to do things manually.
pub struct OperationGuard<'a, MessageType> {
    pub(crate) conversation: TestConversation<'a>,
    /// The member at this index won't be included in the list of [Self::members_to_notify]
    pub(crate) operation: TestOperation<'a>,
    pub(crate) message: MlsMessageOut,
    pub(crate) _message_type: PhantomData<MessageType>,
}

pub(crate) struct AddGuard<'a> {
    pub(crate) committer_index: usize,
    pub(crate) new_members: Vec<&'a SessionContext>,
}

/// Keeps state about the comitted operation that will be used when the
/// corresponding [CommitGuard] is used to (notify members)[CommitGuard::notify_members].
pub(crate) enum TestOperation<'a> {
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

    pub(crate) fn members_to_notify(&self) -> Box<dyn Iterator<Item = &'a SessionContext> + '_> {
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
