use std::sync::Arc;

use core_crypto::{MlsBufferedDecryptMessage, MlsDecryptMessage};

use crate::{ClientId, WireIdentity};

/// A decrypted message and various associated metadata.
#[derive(Debug, uniffi::Record)]
pub struct DecryptedMessage {
    /// Decrypted plaintext
    pub message: Option<Vec<u8>>,
    /// False if processing this message caused the client to be removed from the group, i.e. due to a Remove commit.
    pub is_active: bool,
    /// Commit delay in seconds.
    ///
    /// When set, clients must delay this long before processing a commit.
    /// This reduces load on the backend, which otherwise would receive epoch change notifications from all clients
    /// simultaneously.
    pub commit_delay: Option<u64>,
    /// `ClientId` of the sender of the message being decrypted. Only present for application messages.
    pub sender_client_id: Option<Arc<ClientId>>,
    /// Identity claims present in the sender credential.
    pub identity: WireIdentity,
    /// Only set when the decrypted message is a commit.
    ///
    /// Contains buffered messages for next epoch which were received before the commit creating the epoch
    /// because the DS did not fan them out in order.
    pub buffered_messages: Option<Vec<BufferedDecryptedMessage>>,
}

impl From<MlsDecryptMessage> for DecryptedMessage {
    fn from(from: MlsDecryptMessage) -> Self {
        let buffered_messages = from
            .buffered_messages
            .map(|bm| bm.into_iter().map(Into::into).collect::<Vec<_>>());

        Self {
            message: from.app_msg,
            is_active: from.is_active,
            commit_delay: from.delay,
            sender_client_id: from.sender_client_id.map(Into::into).map(Arc::new),
            identity: from.identity.into(),
            buffered_messages,
        }
    }
}

/// A decrypted message that was buffered due to out-of-order delivery by the distribution service.
///
/// These are returned in the `buffered_messages` field of a `DecryptedMessage` when a commit is
/// processed. They represent messages for the new epoch that arrived before the commit that created it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BufferedDecryptedMessage {
    /// Decrypted plaintext
    pub message: Option<Vec<u8>>,
    /// False if processing this message caused the client to be removed from the group, i.e. due to a Remove commit.
    pub is_active: bool,
    /// Commit delay in seconds.
    ///
    /// When set, clients must delay this long before processing a commit.
    /// This reduces load on the backend, which otherwise would receive epoch change notifications from all clients
    /// simultaneously.
    pub commit_delay: Option<u64>,
    /// `ClientId` of the sender of the message being decrypted. Only present for application messages.
    pub sender_client_id: Option<Arc<ClientId>>,
    /// Identity claims present in the sender credential.
    pub identity: WireIdentity,
}

impl From<MlsBufferedDecryptMessage> for BufferedDecryptedMessage {
    fn from(from: MlsBufferedDecryptMessage) -> Self {
        Self {
            message: from.app_msg,
            is_active: from.is_active,
            commit_delay: from.delay,
            sender_client_id: from.sender_client_id.map(Into::into).map(Arc::new),
            identity: from.identity.into(),
        }
    }
}
