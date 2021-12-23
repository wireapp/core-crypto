#![allow(dead_code, unused_variables)]

mod error;
mod message;
pub use self::error::*;
mod central;
mod mls_crypto_provider;

#[repr(u8)]
#[derive(Debug)]
pub enum Protocol {
    Mls,
    Proteus,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Protocol::Mls => "MLS",
                Protocol::Proteus => "Proteus",
            }
        )
    }
}

/////
// Sending
//
//
// To avoid possible decryption errors, CoreLogic will not send a message for encryption with MLS
//  until the backend is up and there are no incoming messages to process for that conversation.
//
// This is a blocking, synchronous call from CoreLogic to CoreCrypto. If successful, it returns an encrypted
//  MLSApplicationMessage.
// pub fun encryptMlsMessage(
//     qualifiedConversationId: String,
//     messageId: String,  // UUID4?
//     genericMessage: Vec<u8>    // CoreCrypto borrows genericMessage
// ) -> Result<Vec<u8>, Error>    // CoreLogic needs to copy the MLSApplicationMessage

//
// Receiving
//

// pub fun decryptMlsApplicationMessage(
//     mlsApplicationMessage: Vec<u8>   // CoreCrypto borrows the MLSApplicationMessage
// ) -> Result<(Vec<u8>, SavedStateDelta), Error>   // CoreLogic needs to copy the decrypted GenericMessage and state

// These are the events that could occur to an MLS group
// enum GroupAction {
//     none,                   // ex: Proposal
//     welcomedToGroup,
//     modifiedGroupMembers,
//     deletedGroup,
//     rekeyedGroup            // does CoreLogic care about this?
// }

// struct MlsGroupChangeEvent {
//     groupChangeEvent: GroupAction,
//     qualifiedConversationId: Option<String>,
//     addedClientList: Option<Vec<String>>,     // only relevant for newGroup and modifyGroupMembers
//     removedClientList: Option<Vec<String>>    // only relevant for modifyGroupMembers
// }

// pub fun processMlsControlMessage(
//     mlsControlMessage: Vec<u8>,             // CoreCrypto borrows the MLSControlMessage
//     // We can include the callback here or once at initialization time
//     wecomeCallback: Option<unsafe extern fn(&mut self, String, Vec<(String, String)>)>
// ) -> Result<(MlsGroupChangeEvent, SavedStateDelta), Error>
// CoreLogic needs to deep copy the MlsGroupChangeEvent
// C version would be like: unsafe extern "C" fn(*mut u8, usize)

//
// Group Management
//

// pub fun newMlsConversation(
//     qualifiedConversationId: String,
//     initKeyList: Vec<InitKey>,
//     // MlsConfiguration includes among other fun things:
//     //   list of admins
//     //   ciphersuite
//     //   amount of time before key rotation (ex: 1 week, 1 day, 1 hour)
//     groupConfig: mut MlsConfiguration
// ) -> Result<(Vec<u8>, SavedStateDelta), Error>   // The MLSControlMessage

// pub fun deleteConversation(
//     qualifiedConversationId: String
// ) -> Result<(Vec<u8>, SavedStateDelta), Error>

// pub fun modifyParticipants(
//     qualifiedConversationId: String,
//     addedClientList: Option<Vec<String>>,
//     removedClientList: Option<Vec<String>>
// ) -> Result<(Vec<u8>, SavedStateDelta), Error>

// pub fun modifyAuthorization(
//     qualifiedConversationId: String,
//     adminList: Vec<String>,  // list of UUIDs who can add/remove new users
//     guestList: Vec<String>   // list of guest client IDs?
// ) -> Result<(), Error>

// // ***
// // We got an unsolicited Welcome message. Someone invited us to join a
// // conversation (could also be a 1:1 "connection")
// // Is that OK CoreLogic?
// fun onWelcomeCallback(
//     inviter: String,          // userID of inviter
//     participants: Vec<(String, String)> // list of tuples of client IDs with each's wire handle
// ) -> Result<String, Error>   // Kotlin, return conversation ID if we should create
