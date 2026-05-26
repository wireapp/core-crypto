mod persistence;

use openmls::group::MlsGroup;

use super::{ConversationWithMls, MlsConversation, Result};
use crate::{ConversationId, MlsConversationConfiguration, Session};

/// An ImmutableConversation exposes the read-only interface of an MLS conversation.
#[derive(Debug)]
pub struct ImmutableConversation {
    pub(crate) id: ConversationId,
    pub(crate) group: MlsGroup,
    configuration: MlsConversationConfiguration,
    session: Session,
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl<'inner> ConversationWithMls<'inner> for ImmutableConversation {
    type Context = Session;

    type Conversation = &'inner MlsConversation;

    async fn context(&self) -> Result<Session> {
        Ok(self.session.clone())
    }

    async fn conversation(&'inner self) -> &'inner MlsConversation {
        unimplemented!("we will remove this trait shortly")
    }
}
