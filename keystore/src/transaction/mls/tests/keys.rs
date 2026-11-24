//! Keys which the schema stores as bytes elsewhere are stored as their raw bytes.

use openmls::{
    group::{GroupEpoch, GroupId},
    treesync::EncryptionKey,
};

use crate::connection::{convert, raw_bytes};

#[test]
fn group_id_key_is_the_raw_conversation_id() {
    let conversation_id = b"some conversation";
    assert_eq!(
        raw_bytes(&GroupId::from_slice(conversation_id)).unwrap(),
        conversation_id
    );
}

#[test]
fn encryption_key_is_the_raw_public_key() {
    let public_key = vec![7; 32];
    assert_eq!(raw_bytes(&EncryptionKey::from(public_key.clone())).unwrap(), public_key);
}

#[test]
fn epoch_key_is_the_epoch_number() {
    // Large enough that postcard needs several bytes to encode it.
    let epoch = 300_000;
    assert_eq!(convert::<_, u64>(&GroupEpoch::from(epoch)).unwrap(), epoch);
}

#[test]
fn converting_to_bytes_rejects_a_value_with_more_than_bytes() {
    assert!(raw_bytes(&(vec![1_u8, 2], 3_u8)).is_err());
}
