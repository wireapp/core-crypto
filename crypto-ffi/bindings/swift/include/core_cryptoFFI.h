// This file was autogenerated by some hot garbage in the `uniffi` crate.
// Trust me, you don't want to mess with it!

#pragma once

#include <stdbool.h>
#include <stdint.h>

// The following structs are used to implement the lowest level
// of the FFI, and thus useful to multiple uniffied crates.
// We ensure they are declared exactly once, with a header guard, UNIFFI_SHARED_H.
#ifdef UNIFFI_SHARED_H
    // We also try to prevent mixing versions of shared uniffi header structs.
    // If you add anything to the #else block, you must increment the version suffix in UNIFFI_SHARED_HEADER_V4
    #ifndef UNIFFI_SHARED_HEADER_V4
        #error Combining helper code from multiple versions of uniffi is not supported
    #endif // ndef UNIFFI_SHARED_HEADER_V4
#else
#define UNIFFI_SHARED_H
#define UNIFFI_SHARED_HEADER_V4
// ⚠️ Attention: If you change this #else block (ending in `#endif // def UNIFFI_SHARED_H`) you *must* ⚠️
// ⚠️ increment the version suffix in all instances of UNIFFI_SHARED_HEADER_V4 in this file.           ⚠️

typedef struct RustBuffer
{
    int32_t capacity;
    int32_t len;
    uint8_t *_Nullable data;
} RustBuffer;

typedef int32_t (*ForeignCallback)(uint64_t, int32_t, RustBuffer, RustBuffer *_Nonnull);

typedef struct ForeignBytes
{
    int32_t len;
    const uint8_t *_Nullable data;
} ForeignBytes;

// Error definitions
typedef struct RustCallStatus {
    int8_t code;
    RustBuffer errorBuf;
} RustCallStatus;

// ⚠️ Attention: If you change this #else block (ending in `#endif // def UNIFFI_SHARED_H`) you *must* ⚠️
// ⚠️ increment the version suffix in all instances of UNIFFI_SHARED_HEADER_V4 in this file.           ⚠️
#endif // def UNIFFI_SHARED_H

<<<<<<< HEAD
<<<<<<< HEAD
void ffi_CoreCrypto_61fc_CoreCrypto_object_free(
||||||| parent of ce3916d (Add tests)
void ffi_CoreCrypto_1e1b_CoreCrypto_object_free(
=======
void ffi_CoreCrypto_1128_CoreCrypto_object_free(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void ffi_CoreCrypto_1128_CoreCrypto_object_free(
=======
void ffi_CoreCrypto_55fb_CoreCrypto_object_free(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
void*_Nonnull CoreCrypto_61fc_CoreCrypto_new(
||||||| parent of ce3916d (Add tests)
void*_Nonnull CoreCrypto_1e1b_CoreCrypto_new(
=======
void*_Nonnull CoreCrypto_1128_CoreCrypto_new(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void*_Nonnull CoreCrypto_1128_CoreCrypto_new(
=======
void*_Nonnull CoreCrypto_55fb_CoreCrypto_new(
>>>>>>> 12607bd (Fix udl)
      RustBuffer path,RustBuffer key,RustBuffer client_id,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
void CoreCrypto_61fc_CoreCrypto_set_callbacks(
||||||| parent of ce3916d (Add tests)
void CoreCrypto_1e1b_CoreCrypto_set_callbacks(
=======
void CoreCrypto_1128_CoreCrypto_set_callbacks(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void CoreCrypto_1128_CoreCrypto_set_callbacks(
=======
void CoreCrypto_55fb_CoreCrypto_set_callbacks(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,uint64_t callbacks,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_client_public_key(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_client_public_key(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_client_public_key(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_client_public_key(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_client_public_key(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_client_keypackages(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_client_keypackages(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_client_keypackages(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_client_keypackages(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_client_keypackages(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,uint32_t amount_requested,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
void CoreCrypto_61fc_CoreCrypto_create_conversation(
||||||| parent of ce3916d (Add tests)
void CoreCrypto_1e1b_CoreCrypto_create_conversation(
=======
void CoreCrypto_1128_CoreCrypto_create_conversation(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void CoreCrypto_1128_CoreCrypto_create_conversation(
=======
void CoreCrypto_55fb_CoreCrypto_create_conversation(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer config,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
int8_t CoreCrypto_61fc_CoreCrypto_conversation_exists(
||||||| parent of ce3916d (Add tests)
int8_t CoreCrypto_1e1b_CoreCrypto_conversation_exists(
=======
int8_t CoreCrypto_1128_CoreCrypto_conversation_exists(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
int8_t CoreCrypto_1128_CoreCrypto_conversation_exists(
=======
int8_t CoreCrypto_55fb_CoreCrypto_conversation_exists(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_process_welcome_message(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_process_welcome_message(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_process_welcome_message(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_process_welcome_message(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_process_welcome_message(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer welcome_message,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_add_clients_to_conversation(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_add_clients_to_conversation(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_add_clients_to_conversation(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_add_clients_to_conversation(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_add_clients_to_conversation(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer clients,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_remove_clients_from_conversation(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_remove_clients_from_conversation(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_remove_clients_from_conversation(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_remove_clients_from_conversation(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_remove_clients_from_conversation(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer clients,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_leave_conversation(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_leave_conversation(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_leave_conversation(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_leave_conversation(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_leave_conversation(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer other_clients,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_decrypt_message(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_decrypt_message(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_decrypt_message(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_decrypt_message(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_decrypt_message(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer payload,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_encrypt_message(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_encrypt_message(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_encrypt_message(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_encrypt_message(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_encrypt_message(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer message,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_new_add_proposal(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_new_add_proposal(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_new_add_proposal(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_new_add_proposal(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_new_add_proposal(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer key_package,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_new_update_proposal(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_new_update_proposal(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_new_update_proposal(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_new_update_proposal(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_new_update_proposal(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_new_remove_proposal(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_new_remove_proposal(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_new_remove_proposal(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_new_remove_proposal(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_new_remove_proposal(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer client_id,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_new_external_add_proposal(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_new_external_add_proposal(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_new_external_add_proposal(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_new_external_add_proposal(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_new_external_add_proposal(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,uint64_t epoch,RustBuffer key_package,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_new_external_remove_proposal(
      void*_Nonnull ptr,RustBuffer conversation_id,uint64_t epoch,RustBuffer key_package_ref,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_61fc_CoreCrypto_update_keying_material(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_update_keying_material(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_update_keying_material(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_update_keying_material(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_update_keying_material(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_join_by_external_commit(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_join_by_external_commit(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_join_by_external_commit(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_join_by_external_commit(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_join_by_external_commit(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer group_state,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_CoreCrypto_export_group_state(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_CoreCrypto_export_group_state(
=======
RustBuffer CoreCrypto_1128_CoreCrypto_export_group_state(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_CoreCrypto_export_group_state(
=======
RustBuffer CoreCrypto_55fb_CoreCrypto_export_group_state(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
void CoreCrypto_61fc_CoreCrypto_merge_pending_group_from_external_commit(
||||||| parent of ce3916d (Add tests)
void CoreCrypto_1e1b_CoreCrypto_merge_pending_group_from_external_commit(
=======
void CoreCrypto_1128_CoreCrypto_merge_pending_group_from_external_commit(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void CoreCrypto_1128_CoreCrypto_merge_pending_group_from_external_commit(
=======
void CoreCrypto_55fb_CoreCrypto_merge_pending_group_from_external_commit(
>>>>>>> 12607bd (Fix udl)
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer config,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
void ffi_CoreCrypto_61fc_CoreCryptoCallbacks_init_callback(
||||||| parent of ce3916d (Add tests)
void ffi_CoreCrypto_1e1b_CoreCryptoCallbacks_init_callback(
=======
void ffi_CoreCrypto_1128_CoreCryptoCallbacks_init_callback(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void ffi_CoreCrypto_1128_CoreCryptoCallbacks_init_callback(
=======
void ffi_CoreCrypto_55fb_CoreCryptoCallbacks_init_callback(
>>>>>>> 12607bd (Fix udl)
      ForeignCallback  _Nonnull callback_stub,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
void*_Nonnull CoreCrypto_61fc_init_with_path_and_key(
||||||| parent of ce3916d (Add tests)
void*_Nonnull CoreCrypto_1e1b_init_with_path_and_key(
=======
void*_Nonnull CoreCrypto_1128_init_with_path_and_key(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void*_Nonnull CoreCrypto_1128_init_with_path_and_key(
=======
void*_Nonnull CoreCrypto_55fb_init_with_path_and_key(
>>>>>>> 12607bd (Fix udl)
      RustBuffer path,RustBuffer key,RustBuffer client_id,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer CoreCrypto_61fc_version(
||||||| parent of ce3916d (Add tests)
RustBuffer CoreCrypto_1e1b_version(
=======
RustBuffer CoreCrypto_1128_version(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer CoreCrypto_1128_version(
=======
RustBuffer CoreCrypto_55fb_version(
>>>>>>> 12607bd (Fix udl)
      
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer ffi_CoreCrypto_61fc_rustbuffer_alloc(
||||||| parent of ce3916d (Add tests)
RustBuffer ffi_CoreCrypto_1e1b_rustbuffer_alloc(
=======
RustBuffer ffi_CoreCrypto_1128_rustbuffer_alloc(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer ffi_CoreCrypto_1128_rustbuffer_alloc(
=======
RustBuffer ffi_CoreCrypto_55fb_rustbuffer_alloc(
>>>>>>> 12607bd (Fix udl)
      int32_t size,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer ffi_CoreCrypto_61fc_rustbuffer_from_bytes(
||||||| parent of ce3916d (Add tests)
RustBuffer ffi_CoreCrypto_1e1b_rustbuffer_from_bytes(
=======
RustBuffer ffi_CoreCrypto_1128_rustbuffer_from_bytes(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer ffi_CoreCrypto_1128_rustbuffer_from_bytes(
=======
RustBuffer ffi_CoreCrypto_55fb_rustbuffer_from_bytes(
>>>>>>> 12607bd (Fix udl)
      ForeignBytes bytes,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
void ffi_CoreCrypto_61fc_rustbuffer_free(
||||||| parent of ce3916d (Add tests)
void ffi_CoreCrypto_1e1b_rustbuffer_free(
=======
void ffi_CoreCrypto_1128_rustbuffer_free(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
void ffi_CoreCrypto_1128_rustbuffer_free(
=======
void ffi_CoreCrypto_55fb_rustbuffer_free(
>>>>>>> 12607bd (Fix udl)
      RustBuffer buf,
    RustCallStatus *_Nonnull out_status
    );
<<<<<<< HEAD
<<<<<<< HEAD
RustBuffer ffi_CoreCrypto_61fc_rustbuffer_reserve(
||||||| parent of ce3916d (Add tests)
RustBuffer ffi_CoreCrypto_1e1b_rustbuffer_reserve(
=======
RustBuffer ffi_CoreCrypto_1128_rustbuffer_reserve(
>>>>>>> ce3916d (Add tests)
||||||| parent of 12607bd (Fix udl)
RustBuffer ffi_CoreCrypto_1128_rustbuffer_reserve(
=======
RustBuffer ffi_CoreCrypto_55fb_rustbuffer_reserve(
>>>>>>> 12607bd (Fix udl)
      RustBuffer buf,int32_t additional,
    RustCallStatus *_Nonnull out_status
    );
