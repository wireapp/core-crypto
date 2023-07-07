package com.wire.crypto



expect object UniFFILib {
    fun ffi_CoreCrypto_fbd8_CoreCrypto_object_free(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_new(`path`: RustBuffer,`key`: RustBuffer,`clientId`: RustBuffer,`ciphersuites`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer

    fun CoreCrypto_fbd8_CoreCrypto_deferred_init(`path`: RustBuffer,`key`: RustBuffer,`ciphersuites`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer

    fun CoreCrypto_fbd8_CoreCrypto_mls_init(`ptr`: Pointer,`clientId`: RustBuffer,`ciphersuites`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_mls_generate_keypairs(`ptr`: Pointer,`ciphersuites`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_mls_init_with_client_id(`ptr`: Pointer,`clientId`: RustBuffer,`signaturePublicKeys`: RustBuffer,`ciphersuites`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_restore_from_disk(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_set_callbacks(`ptr`: Pointer,`callbacks`: ULong,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_client_public_key(`ptr`: Pointer,`ciphersuite`: UShort,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_client_keypackages(`ptr`: Pointer,`ciphersuite`: UShort,`amountRequested`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_client_valid_keypackages_count(`ptr`: Pointer,`ciphersuite`: UShort,
    _uniffi_out_err: RustCallStatus
    ): ULong

    fun CoreCrypto_fbd8_CoreCrypto_create_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`creatorCredentialType`: RustBuffer,`config`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_conversation_epoch(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): ULong

    fun CoreCrypto_fbd8_CoreCrypto_conversation_exists(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Byte

    fun CoreCrypto_fbd8_CoreCrypto_process_welcome_message(`ptr`: Pointer,`welcomeMessage`: RustBuffer,`customConfiguration`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_add_clients_to_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`clients`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_remove_clients_from_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`clients`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_mark_conversation_as_child_of(`ptr`: Pointer,`childId`: RustBuffer,`parentId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_update_keying_material(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_commit_pending_proposals(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_wipe_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_decrypt_message(`ptr`: Pointer,`conversationId`: RustBuffer,`payload`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_encrypt_message(`ptr`: Pointer,`conversationId`: RustBuffer,`message`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_new_add_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`keyPackage`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_new_update_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_new_remove_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`clientId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_new_external_add_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`epoch`: ULong,`ciphersuite`: UShort,`credentialType`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_join_by_external_commit(`ptr`: Pointer,`groupInfo`: RustBuffer,`customConfiguration`: RustBuffer,`credentialType`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_merge_pending_group_from_external_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_clear_pending_group_from_external_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_export_group_info(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_export_secret_key(`ptr`: Pointer,`conversationId`: RustBuffer,`keyLength`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_get_client_ids(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_random_bytes(`ptr`: Pointer,`length`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_reseed_rng(`ptr`: Pointer,`seed`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_commit_accepted(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_clear_pending_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`proposalRef`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_clear_pending_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_proteus_init(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_proteus_session_from_prekey(`ptr`: Pointer,`sessionId`: RustBuffer,`prekey`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_proteus_session_from_message(`ptr`: Pointer,`sessionId`: RustBuffer,`envelope`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_session_save(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_proteus_session_delete(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_proteus_session_exists(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Byte

    fun CoreCrypto_fbd8_CoreCrypto_proteus_decrypt(`ptr`: Pointer,`sessionId`: RustBuffer,`ciphertext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_encrypt(`ptr`: Pointer,`sessionId`: RustBuffer,`plaintext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_encrypt_batched(`ptr`: Pointer,`sessionId`: RustBuffer,`plaintext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_new_prekey(`ptr`: Pointer,`prekeyId`: UShort,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_new_prekey_auto(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_last_resort_prekey(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_last_resort_prekey_id(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): UShort

    fun CoreCrypto_fbd8_CoreCrypto_proteus_fingerprint(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_fingerprint_local(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_fingerprint_remote(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_fingerprint_prekeybundle(`ptr`: Pointer,`prekey`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_proteus_cryptobox_migrate(`ptr`: Pointer,`path`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_proteus_last_error_code(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): UInt

    fun CoreCrypto_fbd8_CoreCrypto_e2ei_new_enrollment(`ptr`: Pointer,`clientId`: RustBuffer,`displayName`: RustBuffer,`handle`: RustBuffer,`expiryDays`: UInt,`ciphersuite`: UShort,
    _uniffi_out_err: RustCallStatus
    ): Pointer

    fun CoreCrypto_fbd8_CoreCrypto_e2ei_mls_init(`ptr`: Pointer,`enrollment`: Pointer,`certificateChain`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_CoreCrypto_e2ei_enrollment_stash(`ptr`: Pointer,`enrollment`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_CoreCrypto_e2ei_enrollment_stash_pop(`ptr`: Pointer,`handle`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer

    fun CoreCrypto_fbd8_CoreCrypto_e2ei_is_degraded(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Byte

    fun ffi_CoreCrypto_fbd8_WireE2eIdentity_object_free(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_WireE2eIdentity_directory_response(`ptr`: Pointer,`directory`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_account_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_account_response(`ptr`: Pointer,`account`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_WireE2eIdentity_new_order_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_order_response(`ptr`: Pointer,`order`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_authz_request(`ptr`: Pointer,`url`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_authz_response(`ptr`: Pointer,`authz`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_create_dpop_token(`ptr`: Pointer,`expirySecs`: UInt,`backendNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_dpop_challenge_request(`ptr`: Pointer,`accessToken`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_oidc_challenge_request(`ptr`: Pointer,`idToken`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_new_challenge_response(`ptr`: Pointer,`challenge`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_WireE2eIdentity_check_order_request(`ptr`: Pointer,`orderUrl`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_check_order_response(`ptr`: Pointer,`order`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_finalize_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_finalize_response(`ptr`: Pointer,`finalize`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_fbd8_WireE2eIdentity_certificate_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun ffi_CoreCrypto_fbd8_CoreCryptoCallbacks_init_callback(`callbackStub`: ForeignCallback,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_fbd8_version(
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun ffi_CoreCrypto_fbd8_rustbuffer_alloc(`size`: Int,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun ffi_CoreCrypto_fbd8_rustbuffer_from_bytes(`bytes`: ForeignBytes,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun ffi_CoreCrypto_fbd8_rustbuffer_free(`buf`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun ffi_CoreCrypto_fbd8_rustbuffer_reserve(`buf`: RustBuffer,`additional`: Int,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    
}