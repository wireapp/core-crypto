package com.wire.crypto



expect object UniFFILib {
    fun ffi_CoreCrypto_8881_CoreCrypto_object_free(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_new(`path`: RustBuffer,`key`: RustBuffer,`clientId`: RustBuffer,`entropySeed`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer

    fun CoreCrypto_8881_CoreCrypto_deferred_init(`path`: RustBuffer,`key`: RustBuffer,`entropySeed`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer

    fun CoreCrypto_8881_CoreCrypto_mls_init(`ptr`: Pointer,`clientId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_restore_from_disk(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_set_callbacks(`ptr`: Pointer,`callbacks`: ULong,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_client_public_key(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_client_keypackages(`ptr`: Pointer,`amountRequested`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_client_valid_keypackages_count(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): ULong

    fun CoreCrypto_8881_CoreCrypto_create_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`config`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_conversation_epoch(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): ULong

    fun CoreCrypto_8881_CoreCrypto_conversation_exists(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Byte

    fun CoreCrypto_8881_CoreCrypto_process_welcome_message(`ptr`: Pointer,`welcomeMessage`: RustBuffer,`customConfiguration`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_add_clients_to_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`clients`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_remove_clients_from_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`clients`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_update_keying_material(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_commit_pending_proposals(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_wipe_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_decrypt_message(`ptr`: Pointer,`conversationId`: RustBuffer,`payload`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_encrypt_message(`ptr`: Pointer,`conversationId`: RustBuffer,`message`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_new_add_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`keyPackage`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_new_update_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_new_remove_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`clientId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_new_external_add_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`epoch`: ULong,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_new_external_remove_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`epoch`: ULong,`keyPackageRef`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_join_by_external_commit(`ptr`: Pointer,`publicGroupState`: RustBuffer,`customConfiguration`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_merge_pending_group_from_external_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_clear_pending_group_from_external_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_export_group_state(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_export_secret_key(`ptr`: Pointer,`conversationId`: RustBuffer,`keyLength`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_get_client_ids(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_random_bytes(`ptr`: Pointer,`length`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_reseed_rng(`ptr`: Pointer,`seed`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_commit_accepted(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_clear_pending_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`proposalRef`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_clear_pending_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_proteus_init(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_proteus_session_from_prekey(`ptr`: Pointer,`sessionId`: RustBuffer,`prekey`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_proteus_session_from_message(`ptr`: Pointer,`sessionId`: RustBuffer,`envelope`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_session_save(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_proteus_session_delete(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_CoreCrypto_proteus_session_exists(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Byte

    fun CoreCrypto_8881_CoreCrypto_proteus_decrypt(`ptr`: Pointer,`sessionId`: RustBuffer,`ciphertext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_encrypt(`ptr`: Pointer,`sessionId`: RustBuffer,`plaintext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_encrypt_batched(`ptr`: Pointer,`sessionId`: RustBuffer,`plaintext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_new_prekey(`ptr`: Pointer,`prekeyId`: UShort,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_new_prekey_auto(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_fingerprint(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_fingerprint_local(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_fingerprint_remote(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_fingerprint_prekeybundle(`ptr`: Pointer,`prekey`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun CoreCrypto_8881_CoreCrypto_proteus_cryptobox_migrate(`ptr`: Pointer,`path`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun ffi_CoreCrypto_8881_CoreCryptoCallbacks_init_callback(`callbackStub`: ForeignCallback,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun CoreCrypto_8881_version(
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun ffi_CoreCrypto_8881_rustbuffer_alloc(`size`: Int,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun ffi_CoreCrypto_8881_rustbuffer_from_bytes(`bytes`: ForeignBytes,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    fun ffi_CoreCrypto_8881_rustbuffer_free(`buf`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit

    fun ffi_CoreCrypto_8881_rustbuffer_reserve(`buf`: RustBuffer,`additional`: Int,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer

    
}