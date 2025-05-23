use std::marker::PhantomData;

use crate::mls::conversation::Conversation;

use super::super::SessionContext;
use super::super::TestConversation;
use super::operation_guard::{AddGuard, OperationGuard, Proposal, TestOperation};

impl<'a> TestConversation<'a> {
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
                new_members: vec![new_member],
            }),
            message: proposal,
            _message_type: PhantomData,
            already_notified: [proposer_index].into(),
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
            already_notified: [proposer_index].into(),
            operation: TestOperation::Update,
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
            operation: TestOperation::Remove(member),
            message: proposal,
            _message_type: PhantomData,
            already_notified: [proposer_index].into(),
        }
    }

    pub async fn external_join_proposal_guarded(self, joiner: &'a SessionContext) -> OperationGuard<'a, Proposal> {
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

        OperationGuard {
            conversation: self,
            operation: TestOperation::Add(AddGuard {
                new_members: vec![joiner],
            }),
            message: external_proposal,
            _message_type: PhantomData,
            already_notified: [].into(),
        }
    }
}
