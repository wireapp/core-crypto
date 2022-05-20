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
use std::{
    cell::RefCell,
    ffi::{CStr, CString},
};

use libc::{c_char, c_int, c_uchar, size_t};

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

#[no_mangle]
pub extern "C" fn cc_last_error_len() -> size_t {
    CC_LAST_ERROR.with(|prev| {
        (*prev)
            .borrow()
            .as_ref()
            .map(|e| e.to_string().len() + 1)
            .unwrap_or_default()
    })
}

#[no_mangle]
pub extern "C" fn cc_last_error(buffer: *mut c_uchar) -> CallStatus<1> {
    check_nullptr!(buffer);

    let old_err_len = cc_last_error_len();
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

    assert_eq!(old_err_len, err_len);

    // SAFETY: the destination buffer has to be exactly `err_len` big
    unsafe { std::ptr::copy_nonoverlapping(err_bytes.as_ptr(), buffer, err_len) };

    CallStatus::with_bytes_written(0, [err_len])
}

#[no_mangle]
pub extern "C" fn cc_init_with_path_and_key(
    path: *const c_char,
    key: *const c_char,
    client_id: *const c_char,
) -> CoreCryptoPtr {
    let path = unsafe { CStr::from_ptr(path) }.to_str().unwrap();
    let key = unsafe { CStr::from_ptr(key) }.to_str().unwrap();
    let client_id = unsafe { CStr::from_ptr(client_id) }.to_str().unwrap();

    let cc = try_ffi!(CoreCrypto::new(path, key, client_id), std::ptr::null());
    let cc = std::mem::ManuallyDrop::new(cc);
    &*cc
}

//////////////////////////////////////////// CLIENT APIS ////////////////////////////////////////////

#[no_mangle]
pub unsafe extern "C" fn cc_client_public_key(ptr: CoreCryptoPtr, buf: *mut u8) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(buf);

    let cc = &*ptr;
    let pk = try_ffi!(cc.client_public_key());
    let pk_len = pk.len();
    std::ptr::copy_nonoverlapping(pk.as_ptr(), buf, pk_len);
    CallStatus::ok([pk_len])
}

#[no_mangle]
/// SAFETY: `dest` should be at least `amount_requested` long
/// SAFETY: `kp_buf_len` is the length of each buffer in `dest` and MUST be identical
pub unsafe extern "C" fn cc_client_keypackages(
    ptr: CoreCryptoPtr,
    amount_requested: size_t,
    dest: *mut *mut u8,
    kp_buf_len: size_t,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(dest);

    let dest = std::slice::from_raw_parts_mut(dest, amount_requested);
    let mut dest: Vec<&mut [u8]> = dest
        .into_iter()
        .map(|ptr| std::slice::from_raw_parts_mut(*ptr, kp_buf_len))
        .collect();

    let cc = &*ptr;
    let res = cc
        .client_keypackages(amount_requested as u32)
        .and_then(move |serialized_kps| {
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
pub unsafe extern "C" fn cc_create_conversation(
    ptr: CoreCryptoPtr,
    id: *const u8,
    id_len: size_t,
    params: *const ConversationConfiguration,
    welcome_msg_buffer: *mut u8,
    commit_msg_buffer: *mut u8,
) -> CallStatus<2> {
    check_nullptr!(ptr);
    check_nullptr!(params);
    check_nullptr!(id);
    check_nullptr!(welcome_msg_buffer);
    check_nullptr!(commit_msg_buffer);

    let cc = &*ptr;
    let params = (&*params).clone();

    let id = std::slice::from_raw_parts(id, id_len);

    let maybe_welcome_message = try_ffi!(cc.create_conversation(id.into(), params));

    if let Some(msgs) = maybe_welcome_message {
        let MemberAddedMessages {
            welcome,
            message: commit,
        } = msgs;

        let welcome_len = welcome.len();
        let commit_len = commit.len();

        std::ptr::copy_nonoverlapping(welcome.as_ptr(), welcome_msg_buffer, welcome_len);
        std::ptr::copy_nonoverlapping(commit.as_ptr(), commit_msg_buffer, commit_len);

        CallStatus::with_bytes_written(0, [welcome_len, commit_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_process_welcome_message(
    ptr: CoreCryptoPtr,
    welcome: *const u8,
    welcome_len: size_t,
    conversation_id_buf: *mut u8,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(welcome);
    check_nullptr!(conversation_id_buf);

    let cc = &*ptr;
    let welcome = std::slice::from_raw_parts(welcome, welcome_len);

    let conversation_id = try_ffi!(cc.process_welcome_message(welcome));
    let conversation_id_len = conversation_id.len();
    let conversation_id_buf = std::slice::from_raw_parts_mut(conversation_id_buf, conversation_id_len);
    conversation_id_buf.copy_from_slice(&conversation_id);
    CallStatus::ok([conversation_id_len])
}

#[no_mangle]
pub unsafe extern "C" fn cc_add_clients_to_conversation(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    keypackages: *const Invitee,
    keypackages_count: size_t,
    welcome_buffer: *mut u8,
    commit_buffer: *mut u8,
) -> CallStatus<2> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(keypackages);
    check_nullptr!(welcome_buffer);
    check_nullptr!(commit_buffer);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let keypackages = std::slice::from_raw_parts(keypackages, keypackages_count);

    let mut maybe_messages = try_ffi!(cc.add_clients_to_conversation(conversation_id.into(), keypackages.into()));

    if let Some(msg) = maybe_messages.take() {
        let welcome_len = msg.welcome.len();
        let message_len = msg.message.len();
        std::ptr::copy_nonoverlapping(msg.welcome.as_ptr(), welcome_buffer, welcome_len);
        std::ptr::copy_nonoverlapping(msg.message.as_ptr(), commit_buffer, message_len);

        CallStatus::with_bytes_written(0, [welcome_len, message_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_remove_clients_from_conversation(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    client_ids: *const *const u8,
    client_ids_amount: size_t,
    client_ids_lengths: *const size_t,
    dest_commit: *mut u8,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(client_ids);
    check_nullptr!(client_ids_lengths);
    check_nullptr!(dest_commit);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let client_ids = std::slice::from_raw_parts(client_ids, client_ids_amount);
    let client_id_lengths = std::slice::from_raw_parts(client_ids_lengths, client_ids_amount);
    let client_ids: Vec<ClientId> = client_ids
        .into_iter()
        .zip(client_id_lengths.into_iter())
        .map(|(ptr, len)| std::slice::from_raw_parts(*ptr, *len))
        .map(Into::into)
        .collect();

    let mut maybe_message = try_ffi!(cc.remove_clients_from_conversation(conversation_id.into(), client_ids));

    if let Some(commit_message) = maybe_message.take() {
        let commit_msg_len = commit_message.len();
        std::ptr::copy_nonoverlapping(commit_message.as_ptr(), dest_commit, commit_msg_len);
        CallStatus::ok([commit_msg_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_conversation_exists(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
) -> c_uchar {
    if ptr.is_null() {
        return 0;
    }

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    if cc.conversation_exists(conversation_id.into()) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_leave_conversation(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    other_clients: *const ClientId,
    other_clients_count: size_t,
    self_removal_proposal: *mut u8,
    other_clients_removal_commit: *mut u8,
) -> CallStatus<2> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(other_clients);
    check_nullptr!(self_removal_proposal);
    check_nullptr!(other_clients_removal_commit);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let other_clients = std::slice::from_raw_parts(other_clients, other_clients_count);

    let mut messages = try_ffi!(cc.leave_conversation(conversation_id.into(), other_clients));

    let removal_proposal_len = messages.self_removal_proposal.len();
    let mut commit_len = 0;
    std::ptr::copy_nonoverlapping(
        messages.self_removal_proposal.as_ptr(),
        self_removal_proposal,
        removal_proposal_len,
    );
    if let Some(commit) = messages.other_clients_removal_commit.take() {
        commit_len = commit.len();
        std::ptr::copy_nonoverlapping(commit.as_ptr(), other_clients_removal_commit, commit_len);
    }
    CallStatus::ok([removal_proposal_len, commit_len])
}

//////////////////////////////////////////// MESSAGES API ////////////////////////////////////////////

#[no_mangle]
pub unsafe extern "C" fn cc_decrypt_message(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    payload: *const u8,
    payload_len: size_t,
    dest_buffer: *mut u8,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(payload);
    check_nullptr!(dest_buffer);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let payload = std::slice::from_raw_parts(payload, payload_len);

    let decrypted_message = try_ffi!(cc.decrypt_message(conversation_id.into(), payload));

    if let Some(decrypted_message) = decrypted_message {
        let decrypted_message_len = decrypted_message.len();
        std::ptr::copy_nonoverlapping(decrypted_message.as_ptr(), dest_buffer, decrypted_message_len);
        CallStatus::with_bytes_written(0, [decrypted_message_len])
    } else {
        CallStatus::default()
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_encrypt_message(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    payload: *const u8,
    payload_len: size_t,
    dest_buffer: *mut u8,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(payload);
    check_nullptr!(dest_buffer);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let payload = std::slice::from_raw_parts(payload, payload_len);

    let buf = try_ffi!(cc.encrypt_message(conversation_id.into(), payload));
    let encrypted_message_len = buf.len();
    std::ptr::copy_nonoverlapping(buf.as_ptr(), dest_buffer, encrypted_message_len);

    CallStatus::ok([encrypted_message_len])
}

/////////////////////////////////////////// PROPOSALS API ///////////////////////////////////////////

#[no_mangle]
pub unsafe extern "C" fn cc_new_add_proposal(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    key_package: *const u8,
    key_package_len: size_t,
    dest: *mut u8,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(key_package);
    check_nullptr!(dest);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let key_package = std::slice::from_raw_parts(key_package, key_package_len);

    let welcome = try_ffi!(cc.new_add_proposal(conversation_id.into(), key_package.into()));
    let welcome_len = welcome.len();
    std::ptr::copy_nonoverlapping(welcome.as_ptr(), dest, welcome_len);
    CallStatus::ok([welcome_len])
}

#[no_mangle]
pub unsafe extern "C" fn cc_new_update_proposal(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    dest: *mut u8,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(dest);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);

    let buf = try_ffi!(cc.new_update_proposal(conversation_id.into()));
    let buf_len = buf.len();
    std::ptr::copy_nonoverlapping(buf.as_ptr(), dest, buf_len);
    CallStatus::ok([buf_len])
}

#[no_mangle]
pub unsafe extern "C" fn cc_new_remove_proposal(
    ptr: CoreCryptoPtr,
    conversation_id: *const u8,
    conversation_id_len: size_t,
    client_id: *const u8,
    client_id_len: size_t,
    dest: *mut u8,
) -> CallStatus<1> {
    check_nullptr!(ptr);
    check_nullptr!(conversation_id);
    check_nullptr!(client_id);
    check_nullptr!(dest);

    let cc = &*ptr;
    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let client_id = std::slice::from_raw_parts(client_id, client_id_len);

    let buf = try_ffi!(cc.new_remove_proposal(conversation_id.to_vec(), client_id.to_vec().into()));
    let buf_len = buf.len();
    std::ptr::copy_nonoverlapping(buf.as_ptr(), dest, buf_len);
    CallStatus::ok([buf_len])
}

//////////////////////////////////////////// MISC APIS ////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn cc_version() -> *const c_uchar {
    VERSION.as_ptr()
}
