use core_crypto::*;
use std::cell::RefCell;

use libc::{c_char, c_int, c_uchar, size_t};

use crate::*;

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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
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
pub unsafe extern "C" fn cc_last_error(buf: *mut c_char, len: size_t) -> CallStatus<1> {
    if buf.is_null() {
        return CallStatus::err();
    }

    let last_error = match take_last_error() {
        Some(err) => err,
        None => {
            return CallStatus::with_bytes_written(0, [0]);
        }
    };

    let error_message = last_error.to_string();
    let buffer = std::slice::from_raw_parts_mut(buf as *mut u8, len);
    if error_message.len() >= buffer.len() {
        return CallStatus::err();
    }

    std::ptr::copy_nonoverlapping(error_message.as_ptr(), buffer.as_mut_ptr(), error_message.len());
    buffer[error_message.len()] = b'\0';

    CallStatus::with_bytes_written(0, [error_message.len()])
}

#[no_mangle]
pub unsafe extern "C" fn cc_init_with_path_and_key(
    path: *const c_char,
    key: *const c_char,
    client_id: *const c_char,
) -> CoreCryptoPtr {
    let path = std::ffi::CStr::from_ptr(path).to_string_lossy();
    let key = std::ffi::CStr::from_ptr(key).to_string_lossy();
    let client_id = std::ffi::CStr::from_ptr(client_id).to_string_lossy();

    let cc_res = CoreCrypto::new(&path, &key, &client_id);

    match cc_res {
        Ok(cc) => {
            let cc = std::mem::ManuallyDrop::new(cc);
            &*cc
        }
        Err(e) => {
            update_last_error(e);
            std::ptr::null()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_create_conversation(
    ptr: CoreCryptoPtr,
    id: *const u8,
    id_len: usize,
    params: *const ConversationConfiguration,
    welcome_msg_buffer: *mut u8,
    commit_msg_buffer: *mut u8,
) -> CallStatus<2> {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    let id = std::slice::from_raw_parts(id, id_len);
    let cc = &*ptr;

    match cc.create_conversation(id.into(), (&*params).clone()) {
        Ok(maybe_welcome_message) => {
            if let Some(msgs) = maybe_welcome_message {
                let MemberAddedMessages { welcome, message } = msgs;
                let welcome_len = welcome.len();
                let message_len = message.len();
                std::ptr::copy_nonoverlapping(welcome.as_ptr(), welcome_msg_buffer, welcome_len);
                std::ptr::copy_nonoverlapping(message.as_ptr(), commit_msg_buffer, message_len);

                CallStatus::with_bytes_written(0, [welcome_len, message_len])
            } else {
                CallStatus::default()
            }
        }
        Err(e) => {
            update_last_error(e);
            CallStatus::err()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_decrypt_message(
    ptr: CoreCryptoPtr,
    conversation_id: *mut u8,
    conversation_id_len: usize,
    payload: *const u8,
    payload_len: usize,
    dest_buffer: *mut u8,
) -> CallStatus<1> {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let payload = std::slice::from_raw_parts(payload, payload_len);
    let cc = &*ptr;
    let decrypted_message_res = cc.decrypt_message(conversation_id.into(), &payload);
    match decrypted_message_res {
        Ok(decrypted_message) => {
            if let Some(decrypted_message) = decrypted_message {
                let decrypted_message_len = decrypted_message.len();
                std::ptr::copy_nonoverlapping(decrypted_message.as_ptr(), dest_buffer, decrypted_message_len);
                CallStatus::with_bytes_written(0, [decrypted_message_len])
            } else {
                CallStatus::default()
            }
        }
        Err(e) => {
            update_last_error(e);
            CallStatus::err()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_encrypt_message(
    ptr: CoreCryptoPtr,
    conversation_id: *mut u8,
    conversation_id_len: usize,
    payload: *const u8,
    payload_len: usize,
    dest_buffer: *mut u8,
) -> CallStatus<1> {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let payload = std::slice::from_raw_parts(payload, payload_len);
    let cc = &*ptr;

    match cc.encrypt_message(conversation_id.into(), &payload) {
        Ok(buf) => {
            let encrypted_message_len = buf.len();
            std::ptr::copy_nonoverlapping(buf.as_ptr(), dest_buffer, encrypted_message_len);
            CallStatus::with_bytes_written(0, [encrypted_message_len])
        }
        Err(e) => {
            update_last_error(e);
            CallStatus::err()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_process_welcome_message(
    ptr: CoreCryptoPtr,
    welcome: *const u8,
    welcome_len: usize,
    conversation_id_buf: *mut u8,
    config: ConversationConfiguration,
) -> CallStatus<1> {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    let welcome_raw = std::slice::from_raw_parts(welcome, welcome_len);
    let cc = &*ptr;

    match cc.process_welcome_message(welcome_raw, config) {
        Ok(conversation_id) => {
            let conversation_id_len = conversation_id.len();
            std::ptr::copy_nonoverlapping(conversation_id.as_ptr(), conversation_id_buf, conversation_id_len);
            CallStatus::with_bytes_written(0, [conversation_id_len])
        }
        Err(e) => {
            update_last_error(e);
            CallStatus::err()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_client_public_key(ptr: CoreCryptoPtr, buf: *mut u8) -> CallStatus<1> {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    let cc = &*ptr;
    match cc.client_public_key() {
        Ok(pk) => {
            let pk_len = pk.len();
            std::ptr::copy_nonoverlapping(pk.as_ptr(), buf, pk_len);
            CallStatus::with_bytes_written(0, [pk_len])
        }
        Err(e) => {
            update_last_error(e);
            CallStatus::err()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn cc_client_keypackages(
    ptr: CoreCryptoPtr,
    amount_requested: size_t,
    dest: *const [*mut u8],
) -> CallStatus<1> {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    let cc = &*ptr;
    let res = cc
        .client_keypackages(amount_requested as u32)
        .and_then(|serialized_kps| {
            let mut bytes_written = 0;
            for (i, kp) in serialized_kps.into_iter().enumerate() {
                let kp_len = kp.len();
                // FIXME: Find the proper type to write into an slice of buffers that are C-allocated
                // std::ptr::copy_nonoverlapping(kp.as_ptr(), dest[i], kp_len);
                bytes_written += kp_len;
            }
            Ok(CallStatus::with_bytes_written(0, [bytes_written]))
        });

    match res {
        Ok(status) => status,
        Err(e) => {
            update_last_error(e);
            CallStatus::err()
        }
    }
}

#[no_mangle]
pub extern "C" fn cc_add_clients_to_conversation(ptr: CoreCryptoPtr) {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    todo!()
}

#[no_mangle]
pub extern "C" fn cc_remove_clients_from_conversation(ptr: CoreCryptoPtr) {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn cc_conversation_exists(
    ptr: CoreCryptoPtr,
    conversation_id: *mut u8,
    conversation_id_len: usize,
) -> c_uchar {
    if ptr.is_null() {
        update_last_error(CryptoError::NullPointerGiven);
        return CallStatus::err();
    }

    let conversation_id = std::slice::from_raw_parts(conversation_id, conversation_id_len);
    let cc = &*ptr;
    if cc.conversation_exists(conversation_id.into()) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn cc_version() -> *const std::os::raw::c_uchar {
    crate::VERSION.as_ptr()
}
