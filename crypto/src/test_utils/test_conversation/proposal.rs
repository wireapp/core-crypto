use openmls::prelude::ExternalProposal;

use crate::mls::conversation::Conversation;

use super::super::SessionContext;
use super::super::TestConversation;
use super::operation_guard::{AddGuard, OperationGuard, Proposal, TestOperation};

impl<'a> TestConversation<'a> {
    /// Propose inviting a member and notify all members.
    pub async fn invite_proposal_notify(self, session: &'a SessionContext) -> TestConversation<'a> {
        self.invite_proposal(session).await.notify_members().await
    }

    /// Propose inviting a member.
    pub async fn invite_proposal(self, new_member: &'a SessionContext) -> OperationGuard<'a, Proposal> {
        let proposer = self.actor();
        let key_package = new_member.rand_key_package(self.case).await;
        let proposal = proposer
            .transaction
            .new_add_proposal(self.id(), key_package.into())
            .await
            .unwrap()
            .proposal;
        let proposer_index = self.member_index(proposer).await;
        OperationGuard::new(
            TestOperation::Add(AddGuard {
                new_members: vec![new_member],
            }),
            proposal,
            self,
            [proposer_index],
        )
    }

    /// Propose updating the actor's key material and notify members.
    pub async fn update_proposal_notify(self) -> TestConversation<'a> {
        self.update_proposal().await.notify_members().await
    }

    /// Propose updating the actor's key material.
    pub async fn update_proposal(self) -> OperationGuard<'a, Proposal> {
        let proposer = self.actor();
        let proposal = proposer
            .transaction
            .new_update_proposal(self.id())
            .await
            .unwrap()
            .proposal;
        let proposer_index = self.actor_index();
        OperationGuard::new(TestOperation::Update, proposal, self, [proposer_index])
    }

    /// Propose removing the member and notify all members.
    pub async fn remove_proposal_notify(self, member: &'a SessionContext) -> TestConversation<'a> {
        self.remove_proposal(member).await.notify_members().await
    }

    /// Propose removing the member.
    pub async fn remove_proposal(self, member: &'a SessionContext) -> OperationGuard<'a, Proposal> {
        let proposer = self.actor();
        let member_id = member.session.id().await.unwrap();
        let proposal = proposer
            .transaction
            .new_remove_proposal(self.id(), member_id)
            .await
            .unwrap()
            .proposal;
        let proposer_index = self.actor_index();
        OperationGuard::new(TestOperation::Remove(member), proposal, self, [proposer_index])
    }

    /// Create an external join proposal and notify all members. The epoch count needed for this will be taken
    /// from the actor's state.
    pub async fn external_join_proposal_notify(self, joiner: &'a SessionContext) -> TestConversation<'a> {
        self.external_join_proposal(joiner).await.notify_members().await
    }

    /// Create an external join proposal. The epoch count needed for this will be taken from the actor's state.
    pub async fn external_join_proposal(self, joiner: &'a SessionContext) -> OperationGuard<'a, Proposal> {
        let external_proposal = joiner
            .transaction
            .new_external_add_proposal(
                self.id().clone(),
                self.guard().await.epoch().await.into(),
                self.case.ciphersuite(),
                self.case.credential_type,
            )
            .await
            .unwrap();

        OperationGuard::new(
            TestOperation::Add(AddGuard {
                new_members: vec![joiner],
            }),
            external_proposal,
            self,
            [],
        )
    }

    /// Like [Self::remove_proposal_notify], but by an external actor, the so-called external sender. We're using the sender index 0.
    pub async fn external_remove_proposal_notify(
        self,
        external_actor: &'a SessionContext,
        member: &'a SessionContext,
    ) -> TestConversation<'a> {
        self.external_remove_proposal(external_actor, member)
            .await
            .notify_members()
            .await
    }

    /// Like [Self::remove_proposal], but by an external actor, the so-called external sender. We're using the sender index 0.
    pub async fn external_remove_proposal(
        self,
        external_actor: &'a SessionContext,
        to_remove: &'a SessionContext,
    ) -> OperationGuard<'a, Proposal> {
        self.external_remove_proposal_with_sender_index(external_actor, 0, to_remove)
            .await
    }

    /// Like [Self::external_remove_proposal], but with an explicitly set sender index.
    pub async fn external_remove_proposal_with_sender_index(
        self,
        external_actor: &'a SessionContext,
        sender_index: u32,
        to_remove: &'a SessionContext,
    ) -> OperationGuard<'a, Proposal> {
        let to_remove_index = self.actor().index_of(self.id(), to_remove.get_client_id().await).await;
        let sender_index = openmls::prelude::SenderExtensionIndex::new(sender_index);

        let (sc, ct) = (self.case.signature_scheme(), self.case.credential_type);
        let cb = external_actor.find_most_recent_credential_bundle(sc, ct).await.unwrap();

        let group_id = openmls::group::GroupId::from_slice(self.id());
        let epoch = self.guard().await.epoch().await;
        let proposal =
            ExternalProposal::new_remove(to_remove_index, group_id, epoch.into(), &cb.signature_key, sender_index)
                .unwrap();
        OperationGuard::new(TestOperation::Remove(to_remove), proposal, self, [])
    }
}
