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

void ffi_CoreCrypto_59cc_CoreCrypto_object_free(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
void*_Nonnull CoreCrypto_59cc_CoreCrypto_new(
      RustBuffer path,RustBuffer key,RustBuffer client_id,RustBuffer entropy_seed,
    RustCallStatus *_Nonnull out_status
    );
void*_Nonnull CoreCrypto_59cc_CoreCrypto_deferred_init(
      RustBuffer path,RustBuffer key,RustBuffer entropy_seed,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_mls_init(
      void*_Nonnull ptr,RustBuffer client_id,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_restore_from_disk(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_set_callbacks(
      void*_Nonnull ptr,uint64_t callbacks,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_client_public_key(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_client_keypackages(
      void*_Nonnull ptr,uint32_t amount_requested,
    RustCallStatus *_Nonnull out_status
    );
uint64_t CoreCrypto_59cc_CoreCrypto_client_valid_keypackages_count(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_create_conversation(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer config,
    RustCallStatus *_Nonnull out_status
    );
uint64_t CoreCrypto_59cc_CoreCrypto_conversation_epoch(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
int8_t CoreCrypto_59cc_CoreCrypto_conversation_exists(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_process_welcome_message(
      void*_Nonnull ptr,RustBuffer welcome_message,RustBuffer custom_configuration,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_add_clients_to_conversation(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer clients,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_remove_clients_from_conversation(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer clients,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_update_keying_material(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_commit_pending_proposals(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_wipe_conversation(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_decrypt_message(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer payload,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_encrypt_message(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer message,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_new_add_proposal(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer key_package,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_new_update_proposal(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_new_remove_proposal(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer client_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_new_external_add_proposal(
      void*_Nonnull ptr,RustBuffer conversation_id,uint64_t epoch,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_new_external_remove_proposal(
      void*_Nonnull ptr,RustBuffer conversation_id,uint64_t epoch,RustBuffer key_package_ref,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_join_by_external_commit(
      void*_Nonnull ptr,RustBuffer public_group_state,RustBuffer custom_configuration,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_merge_pending_group_from_external_commit(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_clear_pending_group_from_external_commit(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_export_group_state(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_export_secret_key(
      void*_Nonnull ptr,RustBuffer conversation_id,uint32_t key_length,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_get_client_ids(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_random_bytes(
      void*_Nonnull ptr,uint32_t length,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_reseed_rng(
      void*_Nonnull ptr,RustBuffer seed,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_commit_accepted(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_clear_pending_proposal(
      void*_Nonnull ptr,RustBuffer conversation_id,RustBuffer proposal_ref,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_clear_pending_commit(
      void*_Nonnull ptr,RustBuffer conversation_id,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_proteus_init(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_proteus_session_from_prekey(
      void*_Nonnull ptr,RustBuffer session_id,RustBuffer prekey,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_session_from_message(
      void*_Nonnull ptr,RustBuffer session_id,RustBuffer envelope,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_proteus_session_save(
      void*_Nonnull ptr,RustBuffer session_id,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_proteus_session_delete(
      void*_Nonnull ptr,RustBuffer session_id,
    RustCallStatus *_Nonnull out_status
    );
int8_t CoreCrypto_59cc_CoreCrypto_proteus_session_exists(
      void*_Nonnull ptr,RustBuffer session_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_decrypt(
      void*_Nonnull ptr,RustBuffer session_id,RustBuffer ciphertext,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_encrypt(
      void*_Nonnull ptr,RustBuffer session_id,RustBuffer plaintext,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_encrypt_batched(
      void*_Nonnull ptr,RustBuffer session_id,RustBuffer plaintext,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_new_prekey(
      void*_Nonnull ptr,uint16_t prekey_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_new_prekey_auto(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_fingerprint(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_fingerprint_local(
      void*_Nonnull ptr,RustBuffer session_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_fingerprint_remote(
      void*_Nonnull ptr,RustBuffer session_id,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_CoreCrypto_proteus_fingerprint_prekeybundle(
      void*_Nonnull ptr,RustBuffer prekey,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_CoreCrypto_proteus_cryptobox_migrate(
      void*_Nonnull ptr,RustBuffer path,
    RustCallStatus *_Nonnull out_status
    );
void*_Nonnull CoreCrypto_59cc_CoreCrypto_new_acme_enrollment(
      void*_Nonnull ptr,RustBuffer ciphersuite,
    RustCallStatus *_Nonnull out_status
    );
uint32_t CoreCrypto_59cc_CoreCrypto_proteus_last_error_code(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
void ffi_CoreCrypto_59cc_WireE2eIdentity_object_free(
      void*_Nonnull ptr,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_directory_response(
      void*_Nonnull ptr,RustBuffer directory,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_new_account_request(
      void*_Nonnull ptr,RustBuffer directory,RustBuffer previous_nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_new_account_response(
      void*_Nonnull ptr,RustBuffer account,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_new_order_request(
      void*_Nonnull ptr,RustBuffer handle,RustBuffer client_id,uint32_t expiry_days,RustBuffer directory,RustBuffer account,RustBuffer previous_nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_new_order_response(
      void*_Nonnull ptr,RustBuffer order,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_new_authz_request(
      void*_Nonnull ptr,RustBuffer url,RustBuffer account,RustBuffer previous_nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_new_authz_response(
      void*_Nonnull ptr,RustBuffer authz,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_create_dpop_token(
      void*_Nonnull ptr,RustBuffer access_token_url,RustBuffer user_id,uint64_t client_id,RustBuffer domain,RustBuffer client_id_challenge,RustBuffer backend_nonce,uint32_t expiry_days,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_new_challenge_request(
      void*_Nonnull ptr,RustBuffer handle,RustBuffer account,RustBuffer previous_nonce,
    RustCallStatus *_Nonnull out_status
    );
void CoreCrypto_59cc_WireE2eIdentity_new_challenge_response(
      void*_Nonnull ptr,RustBuffer challenge,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_check_order_request(
      void*_Nonnull ptr,RustBuffer order_url,RustBuffer account,RustBuffer previous_nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_check_order_response(
      void*_Nonnull ptr,RustBuffer order,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_finalize_request(
      void*_Nonnull ptr,RustBuffer domains,RustBuffer order,RustBuffer account,RustBuffer previous_nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_finalize_response(
      void*_Nonnull ptr,RustBuffer finalize,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_certificate_request(
      void*_Nonnull ptr,RustBuffer finalize,RustBuffer account,RustBuffer previous_nonce,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_WireE2eIdentity_certificate_response(
      void*_Nonnull ptr,RustBuffer certificate_chain,
    RustCallStatus *_Nonnull out_status
    );
void ffi_CoreCrypto_59cc_CoreCryptoCallbacks_init_callback(
      ForeignCallback  _Nonnull callback_stub,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer CoreCrypto_59cc_version(
      
    RustCallStatus *_Nonnull out_status
    );
RustBuffer ffi_CoreCrypto_59cc_rustbuffer_alloc(
      int32_t size,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer ffi_CoreCrypto_59cc_rustbuffer_from_bytes(
      ForeignBytes bytes,
    RustCallStatus *_Nonnull out_status
    );
void ffi_CoreCrypto_59cc_rustbuffer_free(
      RustBuffer buf,
    RustCallStatus *_Nonnull out_status
    );
RustBuffer ffi_CoreCrypto_59cc_rustbuffer_reserve(
      RustBuffer buf,int32_t additional,
    RustCallStatus *_Nonnull out_status
    );
