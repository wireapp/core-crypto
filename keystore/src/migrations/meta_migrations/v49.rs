//! Populate `mls_inbox` from `mls_pending_messages` and `mls_buffered_commits`.
//!
//! The old tables don't record why a message is waiting, nor its epoch or content type. All three have to be
//! recovered by parsing each message and comparing it with the current state of its group.

use log::warn;
use openmls::prelude::{ContentType, MlsMessageIn, MlsMessageInBody, ProtocolMessage, TlsDeserializeTrait as _};

use crate::{
    CryptoKeystoreResult,
    ancillary::ConversationId,
    entities::{InboxMessage, WaitingFor},
    traits::EntityDatabaseMutation as _,
};

pub(crate) const VERSION: i32 = 49;

const TRANSIENT_WIRE_FORMAT: u16 = 0xF000;
const TARGETED_WIRE_FORMAT: u16 = 0xF001;
const TRANSIENT_TARGETED_WIRE_FORMAT: u16 = 0xF002;
const TNT_WIRE_FORMATS: std::ops::RangeInclusive<u16> = TRANSIENT_WIRE_FORMAT..=TRANSIENT_TARGETED_WIRE_FORMAT;

pub(crate) fn meta_migration(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    // the inbox table was just created
    let mut arrival_sequence = 0;
    let mut write_inbox_message =
        move |tx, conversation_id, message, content_type, waiting_for, epoch| -> CryptoKeystoreResult<()> {
            arrival_sequence += 1;
            InboxMessage {
                conversation_id,
                message,
                content_type,
                waiting_for,
                epoch,
                arrival_sequence,
            }
            .save(tx)?;
            Ok(())
        };

    let mut group_data_stmt = tx.prepare_cached("SELECT is_pending, epoch FROM mls_groups WHERE id = ?")?;

    // handle pending messages
    {
        let mut stmt = tx.prepare("SELECT conversation_id, message FROM mls_pending_messages ORDER BY rowid")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, ConversationId>("conversation_id")?,
                row.get::<_, Vec<u8>>("message")?,
            ))
        })?;
        for maybe_row in rows {
            let (conversation_id, message) = maybe_row?;
            let (group_is_pending, group_epoch) = group_data_stmt.query_one([&conversation_id], |row| {
                Ok((row.get::<_, bool>(0)?, row.get::<_, u64>(1)?))
            })?;
            let Some((content_type, msg_epoch)) = parse_message(&message) else {
                // anything we can't parse gets skipped, which ends up dropping it
                warn!(conversation_id, group_epoch, group_is_pending; "migration failed to parse a pending message; dropping");
                continue;
            };

            let waiting_for = if group_is_pending {
                WaitingFor::PendingJoin
            } else if msg_epoch > group_epoch {
                WaitingFor::Epoch
            } else {
                // we can't do anything about this message; it's either stale or failed to pull out when we joined the
                // current epoch, and nothing will pull it anymore. So just skip it.
                warn!(msg_epoch, group_epoch; "migration found a message in the pending queue which should already have been replayed; dropping");
                continue;
            };

            write_inbox_message(tx, conversation_id, message, content_type, waiting_for, msg_epoch)?;
        }
    }

    // handle buffered commits
    {
        let mut stmt = tx.prepare("SELECT conversation_id, commit_data FROM mls_buffered_commits")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, ConversationId>("conversation_id")?,
                // commit data is nullable for some reason
                row.get::<_, Option<Vec<u8>>>("commit_data")?,
            ))
        })?;
        for maybe_row in rows {
            let (conversation_id, message) = maybe_row?;
            let Some(message) = message else {
                // if `message` is `None`, no point in keeping this around
                warn!(conversation_id; "migration found a buffered commit with no commit data; dropping");
                continue;
            };
            let (group_is_pending, group_epoch) = group_data_stmt.query_one([&conversation_id], |row| {
                Ok((row.get::<_, bool>(0)?, row.get::<_, u64>(1)?))
            })?;
            let Some((content_type, msg_epoch)) = parse_message(&message) else {
                // anything we can't parse gets skipped, which ends up dropping it
                warn!(conversation_id, group_epoch, group_is_pending; "migration failed to parse a buffered commit; dropping");
                continue;
            };

            let waiting_for = if group_is_pending {
                WaitingFor::PendingJoin
            } else if content_type == ContentType::Commit && msg_epoch == group_epoch {
                WaitingFor::Proposal
            } else {
                // we can't do anything about this message; it's either stale or weirdly from the future
                warn!(msg_epoch, group_epoch; "migration found a message in the buffered commits which doesn't match the current epoch; dropping");
                continue;
            };

            write_inbox_message(tx, conversation_id, message, content_type, waiting_for, msg_epoch)?;
        }
    }

    Ok(())
}

/// Recover the content type and epoch of a message without interpreting it any further.
fn parse_message(message: &[u8]) -> Option<(ContentType, u64)> {
    // Bytes 2 and 3 are the wire format.
    let wire_format = u16::from_be_bytes(message.get(2..4)?.try_into().ok()?);
    if TNT_WIRE_FORMATS.contains(&wire_format) {
        let epoch = parse_tnt_epoch(wire_format, message)?;
        return Some((ContentType::Application, epoch));
    }

    let protocol_message: ProtocolMessage = match MlsMessageIn::tls_deserialize_exact(message).ok()?.extract() {
        MlsMessageInBody::PublicMessage(message) => message.into(),
        MlsMessageInBody::PrivateMessage(message) => message.into(),
        _ => return None,
    };

    Some((protocol_message.content_type(), protocol_message.epoch().as_u64()))
}

/// compute the number of bytes occupied by a vlbytes field starting at `initial_offset`
///
/// returns `None` if the field can't be read or if it would overrun the `message`.
fn vlbytes_field_length(initial_offset: usize, message: &[u8]) -> Option<usize> {
    let length_of_length = match message.get(initial_offset)? >> 6 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        _ => return None,
    };
    let mut length_encoded = [0; 4];
    length_encoded[4 - length_of_length..]
        .copy_from_slice(message.get(initial_offset..initial_offset + length_of_length)?);
    length_encoded[4 - length_of_length] &= 0b11_1111; // clear the length_of_length bits from the leading byte
    let field_length = length_of_length + u32::from_be_bytes(length_encoded) as usize;
    (message.len() >= initial_offset + field_length).then_some(field_length)
}

/// Recover the epoch of a TNT message.
///
/// The keystore can't see `core-crypto`'s `TntMessage`, so this reads the wire format directly.
///
/// - Transient field layout: an MLS `GroupContext`, i.e. protocol version (u16), ciphersuite (u16), group id (variable
///   length), then the epoch (u64).
/// - Targeted and transient targeted field layout: counter (u32), sender (u32), recipient (u32), recipient id (variable
///   length), then the epoch (u64).
fn parse_tnt_epoch(wire_format: u16, message: &[u8]) -> Option<u64> {
    let mut offset = 2 + 2; // protocol_version, wire_format
    match wire_format {
        TRANSIENT_WIRE_FORMAT => {
            offset += 2 + 2; // protocol_version, ciphersuite
            offset += vlbytes_field_length(offset, message)?; // group_id
        }
        TARGETED_WIRE_FORMAT | TRANSIENT_TARGETED_WIRE_FORMAT => {
            offset += 4 + 4 + 4; // counter, sender_leaf, recipient_leaf
            offset += vlbytes_field_length(offset, message)?; // recipient_id
        }
        _ => return None, // unknown wire format
    }
    message.get(offset..offset + 8)?.try_into().ok().map(u64::from_be_bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use rstest::rstest;

    use super::*;

    /// `field` with a one-byte variable-length prefix; `field` must be shorter than 64 bytes.
    pub(crate) fn short_field(field: &[u8]) -> Vec<u8> {
        assert!(field.len() < 64, "a one-byte prefix only holds lengths up to 63");
        [&[field.len() as u8], field].concat()
    }

    /// A transient TNT message, up to and including its epoch, followed by bytes the parser must ignore.
    pub(crate) fn transient_message(epoch: u64) -> Vec<u8> {
        [
            &[0x00, 0x01][..],      // tnt protocol version
            &[0xF0, 0x00],          // wire format: transient
            &[0x00, 0x01],          // group context: mls protocol version
            &[0x00, 0x01],          // group context: ciphersuite
            &short_field(b"group"), // group context: group id
            &epoch.to_be_bytes(),   // group context: epoch
            b"the rest of the group context, then sender, counter, payload, and signature",
        ]
        .concat()
    }

    /// A targeted TNT message of the given wire format, up to and including its epoch, followed by bytes the parser
    /// must ignore.
    pub(crate) fn targeted_message(wire_format: u16, epoch: u64) -> Vec<u8> {
        [
            &[0x00, 0x01][..],          // tnt protocol version
            &wire_format.to_be_bytes(), // wire format
            &[0, 0, 0, 7],              // counter
            &[0, 0, 0, 1],              // sender
            &[0, 0, 0, 2],              // recipient
            &short_field(b"bob"),       // recipient id
            &epoch.to_be_bytes(),       // epoch
            b"group id, payload, and signature",
        ]
        .concat()
    }

    /// An MLS `PrivateMessage` with the given content type and epoch.
    ///
    /// Only the header is plaintext, and parsing never decrypts, so the encrypted fields can be any bytes.
    pub(crate) fn private_message(content_type: u8, epoch: u64) -> Vec<u8> {
        private_message_with_ciphertext(content_type, epoch, b"ciphertext of whatever")
    }

    /// Like [`private_message`], but with the given ciphertext, so that several messages can share a header.
    pub(crate) fn private_message_with_ciphertext(content_type: u8, epoch: u64, ciphertext: &[u8]) -> Vec<u8> {
        [
            &[0x00, 0x01][..],                      // mls protocol version
            &[0x00, 0x02],                          // wire format: private message
            &short_field(b"group"),                 // group id
            &epoch.to_be_bytes(),                   // epoch
            &[content_type],                        // content type
            &short_field(b""),                      // authenticated data
            &short_field(b"encrypted sender data"), // encrypted sender data
            &short_field(ciphertext),               // ciphertext
        ]
        .concat()
    }

    /// An MLS `PublicMessage` from a member, with the given epoch and content.
    ///
    /// `content` is the content type followed by its body. Nothing verifies the signature or the tags while parsing,
    /// so they can be any bytes.
    pub(crate) fn public_message(epoch: u64, content: &[u8], is_commit: bool) -> Vec<u8> {
        // commits carry a confirmation tag; nothing else does
        let confirmation_tag = if is_commit {
            short_field(b"confirmation tag")
        } else {
            Vec::new()
        };
        [
            &[0x00, 0x01][..],              // mls protocol version
            &[0x00, 0x01],                  // wire format: public message
            &short_field(b"group"),         // group id
            &epoch.to_be_bytes(),           // epoch
            &[0x01, 0, 0, 0, 1],            // sender: member at leaf index 1
            &short_field(b""),              // authenticated data
            content,                        // content type and body
            &short_field(b"the signature"), // signature
            &confirmation_tag,
            &short_field(b"membership tag"), // a member sender carries a membership tag
        ]
        .concat()
    }

    /// A commit with no proposals and no update path: content type 3, an empty proposal list, and an absent path.
    pub(crate) const EMPTY_COMMIT: &[u8] = &[0x03, 0x00, 0x00];

    /// A proposal removing the member at leaf index 2: content type 2, proposal type 3 (remove), then the leaf index.
    pub(crate) const REMOVE_PROPOSAL: &[u8] = &[0x02, 0x00, 0x03, 0, 0, 0, 2];

    #[rstest]
    #[case::one_byte_prefix(&[0x03, b'a', b'b', b'c'], 0, Some(4))]
    #[case::empty_field(&[0x00], 0, Some(1))]
    #[case::trailing_bytes_ignored(&[0x01, b'a', b'b', b'c'], 0, Some(2))]
    #[case::nonzero_offset(&[b'x', b'y', 0x01, b'a'], 2, Some(2))]
    #[case::two_byte_prefix(&[&[0x40, 0x40][..], &[0; 64]].concat(), 0, Some(66))]
    #[case::four_byte_prefix(&[&[0x80, 0x00, 0x40, 0x00][..], &[0; 0x4000]].concat(), 0, Some(0x4004))]
    #[case::eight_byte_prefix(&[0xC0, 0, 0, 0, 0, 0, 0, 0], 0, None)]
    #[case::truncated_prefix(&[0x40], 0, None)]
    #[case::field_overruns_message(&[0x05, b'a', b'b'], 0, None)]
    #[case::offset_past_end(&[0x00], 1, None)]
    fn vlbytes_field_length_measures_prefix_and_field(
        #[case] message: &[u8],
        #[case] offset: usize,
        #[case] expected: Option<usize>,
    ) {
        assert_eq!(vlbytes_field_length(offset, message), expected);
    }

    #[rstest]
    #[case::transient(TRANSIENT_WIRE_FORMAT, transient_message(0x0102_0304_0506_0708))]
    #[case::targeted(TARGETED_WIRE_FORMAT, targeted_message(TARGETED_WIRE_FORMAT, 0x0102_0304_0506_0708))]
    #[case::transient_targeted(
        TRANSIENT_TARGETED_WIRE_FORMAT,
        targeted_message(TRANSIENT_TARGETED_WIRE_FORMAT, 0x0102_0304_0506_0708)
    )]
    fn parse_tnt_epoch_reads_the_epoch(#[case] wire_format: u16, #[case] message: Vec<u8>) {
        assert_eq!(parse_tnt_epoch(wire_format, &message), Some(0x0102_0304_0506_0708));
    }

    #[rstest]
    #[case::transient_cut_short(TRANSIENT_WIRE_FORMAT, transient_message(5))]
    #[case::targeted_cut_short(TARGETED_WIRE_FORMAT, targeted_message(TARGETED_WIRE_FORMAT, 5))]
    fn parse_tnt_epoch_rejects_a_message_which_ends_inside_the_epoch(
        #[case] wire_format: u16,
        #[case] message: Vec<u8>,
    ) {
        // keep everything up to the last byte of the epoch, and drop that byte
        let epoch_end = message.len() - message.iter().rev().position(|&b| b == 5).unwrap();
        assert_eq!(parse_tnt_epoch(wire_format, &message[..epoch_end - 1]), None);
    }

    #[test]
    fn parse_tnt_epoch_rejects_an_unknown_wire_format() {
        assert_eq!(parse_tnt_epoch(0xF003, &targeted_message(0xF003, 5)), None);
    }

    #[rstest]
    #[case::private_application(private_message(1, 4), Some((ContentType::Application, 4)))]
    #[case::private_proposal(private_message(2, 4), Some((ContentType::Proposal, 4)))]
    #[case::private_commit(private_message(3, 4), Some((ContentType::Commit, 4)))]
    #[case::public_commit(public_message(4, EMPTY_COMMIT, true), Some((ContentType::Commit, 4)))]
    #[case::public_proposal(public_message(4, REMOVE_PROPOSAL, false), Some((ContentType::Proposal, 4)))]
    #[case::transient(transient_message(4), Some((ContentType::Application, 4)))]
    #[case::targeted(targeted_message(TARGETED_WIRE_FORMAT, 4), Some((ContentType::Application, 4)))]
    #[case::too_short_for_a_wire_format(vec![0x00, 0x01, 0x00], None)]
    #[case::not_a_message(b"not a message at all".to_vec(), None)]
    #[case::trailing_bytes_after_mls(
        [private_message(1, 4), b"trailing".to_vec()].concat(),
        None
    )]
    fn parse_message_recovers_content_type_and_epoch(
        #[case] message: Vec<u8>,
        #[case] expected: Option<(ContentType, u64)>,
    ) {
        assert_eq!(parse_message(&message), expected);
    }
}
