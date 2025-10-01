use std::{collections::HashSet, marker::PhantomData};

use openmls::prelude::MlsMessageOut;

use super::{SessionContext, TestConversation};
use crate::{MlsConversationDecryptMessage, mls::conversation::Conversation as _};

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

/// Keeps state about the committed operation that will be used when the
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
    HistorySharingEnabled,
    HistorySharingDisabled,
}

impl std::fmt::Debug for TestOperation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestOperation::Add(_) => f.write_str("Add"),
            TestOperation::ExternalJoin(_) => f.write_str("ExternalJoin"),
            TestOperation::Update => f.write_str("Update"),
            TestOperation::Remove(_) => f.write_str("Remove"),
            TestOperation::HistorySharingEnabled => f.write_str("HistorySharingEnabled"),
            TestOperation::HistorySharingDisabled => f.write_str("HistorySharingDisabled"),
        }
    }
}

// Needed for `.sort()`, which is is used to determine the processing order of proposals.
impl std::cmp::Ord for TestOperation<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Remove(_), Self::Remove(_)) => std::cmp::Ordering::Equal,
            (Self::Remove(_), _) => std::cmp::Ordering::Less,
            (_, Self::Remove(_)) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        }
    }
}

impl std::cmp::PartialOrd for TestOperation<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::PartialEq for TestOperation<'_> {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl std::cmp::Eq for TestOperation<'_> {}

impl<'a, T> OperationGuard<'a, T> {
    pub(super) fn new(
        operation: TestOperation<'a>,
        message: MlsMessageOut,
        conversation: TestConversation<'a>,
        already_notified: impl IntoIterator<Item = usize>,
    ) -> Self {
        Self {
            conversation,
            already_notified: HashSet::from_iter(already_notified),
            operation,
            message,
            _message_type: PhantomData,
        }
    }

    /// The [TestConversation] this operation was performed on.
    pub fn conversation(&self) -> &'a TestConversation<'_> {
        &self.conversation
    }

    /// The protocol message corresponding to this.
    pub fn message(&self) -> MlsMessageOut {
        self.message.clone()
    }

    /// Notify a single member about this.
    pub async fn notify_member(mut self, member: &SessionContext) -> Self {
        self.notify_member_inner(member).await.unwrap();
        self
    }

    /// Notify a single member about this and call [SessionContext::verify_sender_identity].
    pub async fn notify_member_and_verify_sender(mut self, member: &SessionContext) -> Self {
        let result = self.notify_member_inner(member).await.unwrap();
        let sender = self.conversation().actor();
        if let Some(ref decrypted) = result {
            sender.verify_sender_identity(self.conversation().case, decrypted).await;
        }
        self
    }

    async fn notify_member_inner(
        &mut self,
        member: &SessionContext,
    ) -> crate::mls::conversation::Result<Option<MlsConversationDecryptMessage>> {
        let member_index = self.conversation().member_index(member).await;
        if self.already_notified.contains(&member_index) {
            return Ok(None);
        }
        let message_bytes = self.message.to_bytes().unwrap();
        let result = member
            .transaction
            .conversation(&self.conversation.id)
            .await
            .unwrap()
            .decrypt_message(&message_bytes)
            .await;
        if result.is_ok() {
            self.already_notified.insert(member_index);
        }
        result.map(Some)
    }

    /// Use this if you need access to the [MlsConversationDecryptMessage] or potential error returned when the
    /// member is notified about this.
    pub async fn notify_member_fallible(
        mut self,
        member: &SessionContext,
    ) -> (Self, crate::mls::conversation::Result<MlsConversationDecryptMessage>) {
        let result = self.notify_member_inner(member).await;
        (
            self,
            result.and_then(|option| option.ok_or(crate::mls::conversation::Error::DuplicateMessage)),
        )
    }
}

impl<'a> OperationGuard<'a, Commit> {
    /// Notify all members except the committer and those already notified by
    /// [Self::notify_member].
    /// Also, propagate the state to the [TestConversation].
    pub async fn notify_members(mut self) -> TestConversation<'a> {
        let members = self.conversation.members.clone();
        let history_client = self
            .conversation
            .history_client
            .clone()
            .filter(|_| !matches!(self.operation, TestOperation::HistorySharingEnabled));
        let members = members.into_iter().chain(history_client.as_ref().into_iter());

        for member in members {
            self = self.notify_member(member).await;
        }
        self.process_member_changes().await.finish()
    }

    pub async fn notify_members_and_verify_sender(mut self) -> TestConversation<'a> {
        let members = self.conversation.members.clone();
        for member in members {
            self = self.notify_member_and_verify_sender(member).await;
        }
        self.process_member_changes().await.finish()
    }

    /// Propoagate the state from the commit to the [TestConversation].
    /// Needed if you notify members manually and never call [Self::notify_member].
    pub async fn process_member_changes(mut self) -> Self {
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
                    if self.conversation.guard().await.is_history_sharing_enabled().await {
                        let ephemeral_client = self.conversation.instantiate_history_client().await;
                        self.conversation.history_client.replace(ephemeral_client);
                        self.process_added_members(&[self.conversation.history_client.as_ref().unwrap()])
                            .await;
                    }
                    if !self.conversation().is_member(member).await {
                        // because we're eagerly pushing proposals into the list of operations to process,
                        // it's possible that we have duplicate operations.
                        continue;
                    }
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
                    if self.conversation().are_members(invited_members.clone()).await {
                        continue;
                    }
                    self.process_added_members(invited_members).await;
                    // Then update the member list
                    self.conversation.members.reserve(invited_members.len());
                    self.conversation.members.extend(invited_members);
                }
                TestOperation::HistorySharingEnabled => {
                    // create an add operation with the history client on the conversation
                    let history_client = self
                        .conversation
                        .history_client
                        .as_ref()
                        .expect("history client must have been added at this point");
                    self.process_added_members(&[history_client]).await;
                }
                TestOperation::HistorySharingDisabled => {
                    self.conversation.history_client.take();
                }
            }
        }
        self
    }

    async fn process_added_members(&self, invited_members: &[&SessionContext]) {
        let welcome_message = self
            .conversation()
            .actor()
            .mls_transport()
            .await
            .latest_commit_bundle()
            .await
            .welcome
            .expect("we're processing an add operation, so there must be a welcome message");

        for new_member in invited_members {
            new_member
                .transaction
                .process_welcome_message(welcome_message.clone().into(), self.conversation.case.custom_cfg())
                .await
                .unwrap();
        }
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
}

impl<'a> OperationGuard<'a, Proposal> {
    /// Notify all members except the proposer and those already notified by
    /// [Self::notify_member].
    pub async fn notify_members(mut self) -> TestConversation<'a> {
        let members = self.conversation.members.clone();
        for member in members {
            self = self.notify_member(member).await;
        }
        // During commit processing, process remove proposals first (see ordering implementation)
        self.conversation.proposals.sort();
        self.finish()
    }

    // Call this once you're finished with manual processing and need mutable access
    // to the [TestConversation] again.
    pub fn finish(mut self) -> TestConversation<'a> {
        self.conversation.actor_index = None;
        // Eagerly push proposals; This is desirable to avoid an extra call if the
        // welcome message of the commit with an add proposal should be processed.
        // However, this leads to slightly more complicated code: There may be duplicate
        // operations if a commit is added after this proposal which does the same operation.
        // This case is handled in notify_members() of the commit operation guard.
        self.conversation.proposals.push(self.operation);
        self.conversation
    }
}
