// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

#[allow(dead_code)]
pub(crate) const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

use core_crypto::*;
use std::{cell::RefCell, ffi::CString};

use libc::{c_int, c_uchar, size_t};
use safer_ffi::{
    char_p::char_p_ref,
    prelude::*,
    slice::{slice_mut, slice_ref},
};

use crate::*;

macro_rules! check_nullptr {
    ($ptr:ident) => {
        if $ptr.is_null() {
            update_last_error(CryptoError::NullPointerGiven);
            return CallStatus::err();
        }
    };
}

macro_rules! try_ffi {
    ($res:expr) => {
        try_ffi!($res, CallStatus::err())
    };

    ($res:expr, $errval:expr) => {
        match $res {
            Ok(result) => result,
            Err(e) => {
                update_last_error(e);
                return $errval;
            }
        }
    };
}

type CoreCryptoPtr = *const CoreCrypto;

pub type FFiClientId = safer_ffi::vec::Vec<u8>;

thread_local! {
    static CC_LAST_ERROR: RefCell<Option<CryptoError>> = RefCell::new(None);
}

#[inline]
fn update_last_error(err: CryptoError) {
    CC_LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(err);
    });
}

#[inline]
fn take_last_error() -> Option<CryptoError> {
    CC_LAST_ERROR.with(|prev| prev.borrow_mut().take())
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CallStatus<const T: usize> {
    pub status: c_int,
    pub written: [size_t; T],
}

impl<const T: usize> CallStatus<T> {
    #[inline(always)]
    fn with_bytes_written(status: c_int, written: [size_t; T]) -> Self {
        Self { status, written }
    }

    #[inline(always)]
    fn with_status(status: c_int) -> Self {
        Self {
            status,
            written: [0; T],
        }
    }

    #[inline(always)]
    fn err() -> Self {
        Self::with_status(-1)
    }

    #[inline(always)]
    fn ok(written: [size_t; T]) -> Self {
        Self::with_bytes_written(0, written)
    }
}

impl<const T: usize> Default for CallStatus<T> {
    fn default() -> Self {
        Self {
            status: 0,
            written: [0; T],
        }
    }
}

#[ffi_export]
pub fn cc_last_error_len() -> size_t {
    CC_LAST_ERROR.with(|prev| {
        (*prev)
            .borrow()
            .as_ref()
            .map(|e| e.to_string().len() + 1)
            .unwrap_or_default()
    })
}

#[no_mangle]
pub extern "C" fn cc_last_error(mut buffer: slice_mut<c_uchar>) -> CallStatus<1> {
    let last_error = match take_last_error() {
        Some(err) => err,
        None => {
            return CallStatus::with_bytes_written(0, [0]);
        }
    };

    // SAFETY: This unwrap is safe as our errors do not include null bytes - a property of Rust strings in general
    let error_message = CString::new(last_error.to_string()).unwrap();
    let err_bytes = error_message.to_bytes_with_nul();
    let err_len = err_bytes.len();
    if err_len >= buffer.len() {
        return CallStatus::err();
    }
    buffer.copy_from_slice(err_bytes);

    CallStatus::with_bytes_written(0, [err_len])
}

#[no_mangle]
pub extern "C" fn cc_init_with_path_and_key(path: char_p_ref, key: char_p_ref, client_id: char_p_ref) -> CoreCryptoPtr {
    let path = path.to_str();
    let key = key.to_str();
    let client_id = client_id.to_str();

    let cc = try_ffi!(CoreCrypto::new(path, key, client_id), std::ptr::null());
    let cc = std::mem::ManuallyDrop::new(cc);
    &*cc
}

//////////////////////////////////////////// CLIENT APIS ////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn cc_client_public_key(ptr: CoreCryptoPtr, mut buf: slice_mut<u8>) -> CallStatus<1> {
    check_nullptr!(ptr);

    let cc = unsafe { &*ptr };
    let pk = try_ffi!(cc.client_public_key());
    let pk_len = pk.len();
    buf.copy_from_slice(&pk);
    CallStatus::ok([pk_len])
}

#[no_mangle]
/// SAFETY: `dest` should be at least `amount_requested` long
pub extern "C" fn cc_client_keypackages(
    ptr: CoreCryptoPtr,
    amount_requested: size_t,
    mut dest: slice_mut<slice_mut<u8>>,
) -> CallStatus<1> {
    check_nullptr!(ptr);

    let cc = unsafe { &*ptr };
    let res = cc
        .client_keypackages(amount_requested as u32)
        .and_then(|serialized_kps| {
            let mut bytes_written = 0;

            for (i, kp) in serialized_kps.into_iter().enumerate() {
                let kp_len = kp.len();
                let dest_item_len = dest[i].len();
                if kp_len > dest_item_len {
                    return Err(CryptoError::BufferTooSmall {
                        needed: kp_len,
                        given: dest_item_len,
                    });
                }

                dest[i].copy_from_slice(&kp);
                bytes_written += kp_len;
            }

            Ok(CallStatus::ok([bytes_written]))
        });

    try_ffi!(res)
}

///////////////////////////////////////// CONVERSATIONS API /////////////////////////////////////////

#[no_mangle]
pub extern "C" fn cc_create_conversation(
    ptr: CoreCryptoPtr,
    id: slice_ref<u8>,
    params: *const ConversationConfiguration,
    mut welcome_msg_buffer: slice_mut<u8>,
    mut commit_msg_buffer: slice_mut<u8>,
) -> CallStatus<2> {
    check_nullptr!(ptr);
    check_nullptr!(params);

    let cc = unsafe { &*ptr };
    let params = (unsafe { &*params }).clone();

    let maybe_welcome_message = try_ffi!(cc.create_conversation(id.as_slice().into(), params));

    if let Some(msgs) = maybe_welcome_message {
        let MemberAddedMessages { welcome, message } = msgs;
        let welcome_len = welcome.len();
        let message_len = message.len();
        welcome_msg_buffer.copy_from_slice(&welcome);
        commit_msg_buffer.copy_from_slice(&message);

        CallStatus::with_bytes_written(0, [welcome_len, message_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub extern "C" fn cc_process_welcome_message(
    ptr: CoreCryptoPtr,
    welcome: slice_ref<u8>,
    mut conversation_id_buf: slice_mut<u8>,
) -> CallStatus<1> {
    check_nullptr!(ptr);

    let cc = unsafe { &*ptr };

    let conversation_id = try_ffi!(cc.process_welcome_message(welcome.as_slice()));
    let conversation_id_len = conversation_id.len();
    conversation_id_buf.copy_from_slice(&conversation_id);
    CallStatus::ok([conversation_id_len])
}

#[no_mangle]
pub extern "C" fn cc_add_clients_to_conversation(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    keypackages: slice_ref<Invitee>,
    // TODO: split welcome & message under their own params? maybe makes it easier
    dest: *mut MemberAddedMessages,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(dest);
    let cc = unsafe { &*ptr };
    let mut maybe_messages =
        try_ffi!(cc.add_clients_to_conversation(conversation_id.as_slice().into(), keypackages.as_slice().into()));

    if let Some(msg) = maybe_messages.take() {
        let welcome_len = msg.welcome.len();
        let message_len = msg.message.len();
        unsafe {
            (*dest).welcome[..welcome_len].copy_from_slice(&msg.welcome);
            (*dest).message[..message_len].copy_from_slice(&msg.message);
        }
        CallStatus::with_bytes_written(0, [welcome_len + message_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub extern "C" fn cc_remove_clients_from_conversation(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    client_ids: slice_ref<slice_ref<u8>>,
    mut dest_commit: slice_mut<u8>,
) -> CallStatus<1> {
    check_nullptr!(ptr);

    let cc = unsafe { &*ptr };

    let mut maybe_message = try_ffi!(cc.remove_clients_from_conversation(
        conversation_id.as_slice().into(),
        client_ids.as_slice().iter().map(|ids| ids.as_slice().into()).collect(),
    ));

    if let Some(commit_message) = maybe_message.take() {
        let commit_msg_len = commit_message.len();
        dest_commit.copy_from_slice(&commit_message);
        CallStatus::ok([commit_msg_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub extern "C" fn cc_conversation_exists(ptr: CoreCryptoPtr, conversation_id: slice_ref<u8>) -> c_uchar {
    if ptr.is_null() {
        return 0;
    }

    let cc = unsafe { &*ptr };
    if cc.conversation_exists(conversation_id.as_slice().into()) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn cc_leave_conversation(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    other_clients: slice_ref<ClientId>,
    mut self_removal_proposal: slice_mut<u8>,
    mut other_clients_removal_commit: slice_mut<u8>,
) -> CallStatus<2> {
    check_nullptr!(ptr);
    let cc = unsafe { &*ptr };
    let mut messages = try_ffi!(cc.leave_conversation(conversation_id.as_slice().into(), other_clients.as_slice()));

    let removal_proposal_len = messages.self_removal_proposal.len();
    let mut commit_len = 0;
    self_removal_proposal[..removal_proposal_len].copy_from_slice(&messages.self_removal_proposal);
    if let Some(commit) = messages.other_clients_removal_commit.take() {
        commit_len = commit.len();
        other_clients_removal_commit[..commit_len].copy_from_slice(&commit);
    }
    CallStatus::ok([removal_proposal_len, commit_len])
}

//////////////////////////////////////////// MESSAGES API ////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn cc_decrypt_message(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    payload: slice_ref<u8>,
    mut dest_buffer: slice_mut<u8>,
) -> CallStatus<1> {
    check_nullptr!(ptr);

    let cc = unsafe { &*ptr };

    let decrypted_message = try_ffi!(cc.decrypt_message(conversation_id.as_slice().into(), payload.as_slice()));

    if let Some(decrypted_message) = decrypted_message {
        let decrypted_message_len = decrypted_message.len();
        dest_buffer.copy_from_slice(&decrypted_message);
        CallStatus::with_bytes_written(0, [decrypted_message_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub extern "C" fn cc_encrypt_message(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    payload: slice_ref<u8>,
    mut dest_buffer: slice_mut<u8>,
) -> CallStatus<1> {
    check_nullptr!(ptr);

    let cc = unsafe { &*ptr };

    let buf = try_ffi!(cc.encrypt_message(conversation_id.as_slice().into(), payload.as_slice()));
    let encrypted_message_len = buf.len();
    dest_buffer.copy_from_slice(&buf);
    CallStatus::ok([encrypted_message_len])
}

/////////////////////////////////////////// PROPOSALS API ///////////////////////////////////////////

#[no_mangle]
pub extern "C" fn cc_new_add_proposal(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    key_package: slice_ref<u8>,
    mut dest: slice_mut<u8>,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    let cc = unsafe { &*ptr };
    let welcome = try_ffi!(cc.new_add_proposal(conversation_id.as_slice().into(), key_package.as_slice().into()));
    let welcome_len = welcome.len();
    dest[..welcome_len].copy_from_slice(&welcome);
    CallStatus::ok([welcome_len])
}

#[no_mangle]
pub extern "C" fn cc_new_update_proposal(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    mut dest: slice_mut<u8>,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    let cc = unsafe { &*ptr };
    let buf = try_ffi!(cc.new_update_proposal(conversation_id.as_slice().into()));
    let buf_len = buf.len();
    dest[..buf_len].copy_from_slice(&buf);
    CallStatus::ok([buf_len])
}

#[no_mangle]
pub extern "C" fn cc_new_remove_proposal(
    ptr: CoreCryptoPtr,
    conversation_id: slice_ref<u8>,
    client_id: slice_ref<u8>,
    mut dest: slice_mut<u8>,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    let cc = unsafe { &*ptr };

    let buf = try_ffi!(cc.new_remove_proposal(conversation_id.to_vec(), client_id.to_vec().into()));
    let buf_len = buf.len();
    dest[..buf_len].copy_from_slice(&buf);
    CallStatus::ok([buf_len])
}

//////////////////////////////////////////// MISC APIS ////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn cc_version() -> *const c_uchar {
    VERSION.as_ptr()
}
