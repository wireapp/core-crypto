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
