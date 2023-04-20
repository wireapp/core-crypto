package com.wire.crypto



actual object UniFFILib {
    init {
        FfiConverterTypeCoreCryptoCallbacks.register(this)
        
    }

    actual fun ffi_CoreCrypto_552_CoreCrypto_object_free(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.ffi_CoreCrypto_552_CoreCrypto_object_free(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_new(`path`: RustBuffer,`key`: RustBuffer,`clientId`: RustBuffer,`entropySeed`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_new(`path`,`key`,`clientId`,`entropySeed`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_deferred_init(`path`: RustBuffer,`key`: RustBuffer,`entropySeed`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_deferred_init(`path`,`key`,`entropySeed`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_mls_init(`ptr`: Pointer,`clientId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_mls_init(`ptr`,`clientId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_mls_generate_keypair(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_mls_generate_keypair(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_mls_init_with_client_id(`ptr`: Pointer,`clientId`: RustBuffer,`signaturePublicKey`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_mls_init_with_client_id(`ptr`,`clientId`,`signaturePublicKey`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_restore_from_disk(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_restore_from_disk(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_set_callbacks(`ptr`: Pointer,`callbacks`: ULong,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_set_callbacks(`ptr`,`callbacks`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_client_public_key(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_client_public_key(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_client_keypackages(`ptr`: Pointer,`amountRequested`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_client_keypackages(`ptr`,`amountRequested`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_client_valid_keypackages_count(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): ULong =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_client_valid_keypackages_count(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_create_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`config`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_create_conversation(`ptr`,`conversationId`,`config`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_conversation_epoch(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): ULong =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_conversation_epoch(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_conversation_exists(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Byte =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_conversation_exists(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_process_welcome_message(`ptr`: Pointer,`welcomeMessage`: RustBuffer,`customConfiguration`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_process_welcome_message(`ptr`,`welcomeMessage`,`customConfiguration`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_add_clients_to_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`clients`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_add_clients_to_conversation(`ptr`,`conversationId`,`clients`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_remove_clients_from_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,`clients`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_remove_clients_from_conversation(`ptr`,`conversationId`,`clients`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_mark_conversation_as_child_of(`ptr`: Pointer,`childId`: RustBuffer,`parentId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_mark_conversation_as_child_of(`ptr`,`childId`,`parentId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_update_keying_material(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_update_keying_material(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_commit_pending_proposals(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_commit_pending_proposals(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_wipe_conversation(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_wipe_conversation(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_decrypt_message(`ptr`: Pointer,`conversationId`: RustBuffer,`payload`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_decrypt_message(`ptr`,`conversationId`,`payload`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_encrypt_message(`ptr`: Pointer,`conversationId`: RustBuffer,`message`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_encrypt_message(`ptr`,`conversationId`,`message`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_new_add_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`keyPackage`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_new_add_proposal(`ptr`,`conversationId`,`keyPackage`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_new_update_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_new_update_proposal(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_new_remove_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`clientId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_new_remove_proposal(`ptr`,`conversationId`,`clientId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_new_external_add_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`epoch`: ULong,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_new_external_add_proposal(`ptr`,`conversationId`,`epoch`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_new_external_remove_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`epoch`: ULong,`keyPackageRef`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_new_external_remove_proposal(`ptr`,`conversationId`,`epoch`,`keyPackageRef`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_join_by_external_commit(`ptr`: Pointer,`publicGroupState`: RustBuffer,`customConfiguration`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_join_by_external_commit(`ptr`,`publicGroupState`,`customConfiguration`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_merge_pending_group_from_external_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_merge_pending_group_from_external_commit(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_clear_pending_group_from_external_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_clear_pending_group_from_external_commit(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_export_group_state(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_export_group_state(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_export_secret_key(`ptr`: Pointer,`conversationId`: RustBuffer,`keyLength`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_export_secret_key(`ptr`,`conversationId`,`keyLength`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_get_client_ids(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_get_client_ids(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_random_bytes(`ptr`: Pointer,`length`: UInt,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_random_bytes(`ptr`,`length`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_reseed_rng(`ptr`: Pointer,`seed`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_reseed_rng(`ptr`,`seed`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_commit_accepted(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_commit_accepted(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_clear_pending_proposal(`ptr`: Pointer,`conversationId`: RustBuffer,`proposalRef`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_clear_pending_proposal(`ptr`,`conversationId`,`proposalRef`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_clear_pending_commit(`ptr`: Pointer,`conversationId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_clear_pending_commit(`ptr`,`conversationId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_init(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_init(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_session_from_prekey(`ptr`: Pointer,`sessionId`: RustBuffer,`prekey`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_session_from_prekey(`ptr`,`sessionId`,`prekey`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_session_from_message(`ptr`: Pointer,`sessionId`: RustBuffer,`envelope`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_session_from_message(`ptr`,`sessionId`,`envelope`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_session_save(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_session_save(`ptr`,`sessionId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_session_delete(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_session_delete(`ptr`,`sessionId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_session_exists(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Byte =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_session_exists(`ptr`,`sessionId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_decrypt(`ptr`: Pointer,`sessionId`: RustBuffer,`ciphertext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_decrypt(`ptr`,`sessionId`,`ciphertext`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_encrypt(`ptr`: Pointer,`sessionId`: RustBuffer,`plaintext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_encrypt(`ptr`,`sessionId`,`plaintext`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_encrypt_batched(`ptr`: Pointer,`sessionId`: RustBuffer,`plaintext`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_encrypt_batched(`ptr`,`sessionId`,`plaintext`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_new_prekey(`ptr`: Pointer,`prekeyId`: UShort,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_new_prekey(`ptr`,`prekeyId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_new_prekey_auto(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_new_prekey_auto(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_last_resort_prekey(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_last_resort_prekey(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_last_resort_prekey_id(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): UShort =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_last_resort_prekey_id(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_fingerprint(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_fingerprint(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_fingerprint_local(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_fingerprint_local(`ptr`,`sessionId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_fingerprint_remote(`ptr`: Pointer,`sessionId`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_fingerprint_remote(`ptr`,`sessionId`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_fingerprint_prekeybundle(`ptr`: Pointer,`prekey`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_fingerprint_prekeybundle(`ptr`,`prekey`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_cryptobox_migrate(`ptr`: Pointer,`path`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_cryptobox_migrate(`ptr`,`path`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_new_acme_enrollment(`ptr`: Pointer,`clientId`: RustBuffer,`displayName`: RustBuffer,`handle`: RustBuffer,`expiryDays`: UInt,`ciphersuite`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Pointer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_new_acme_enrollment(`ptr`,`clientId`,`displayName`,`handle`,`expiryDays`,`ciphersuite`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_e2ei_mls_init(`ptr`: Pointer,`e2ei`: Pointer,`certificateChain`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_e2ei_mls_init(`ptr`,`e2ei`,`certificateChain`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_CoreCrypto_proteus_last_error_code(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): UInt =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_CoreCrypto_proteus_last_error_code(`ptr`,
    _uniffi_out_err
        ))

    actual fun ffi_CoreCrypto_552_WireE2eIdentity_object_free(`ptr`: Pointer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.ffi_CoreCrypto_552_WireE2eIdentity_object_free(`ptr`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_directory_response(`ptr`: Pointer,`directory`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_directory_response(`ptr`,`directory`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_account_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_account_request(`ptr`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_account_response(`ptr`: Pointer,`account`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_account_response(`ptr`,`account`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_order_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_order_request(`ptr`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_order_response(`ptr`: Pointer,`order`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_order_response(`ptr`,`order`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_authz_request(`ptr`: Pointer,`url`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_authz_request(`ptr`,`url`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_authz_response(`ptr`: Pointer,`authz`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_authz_response(`ptr`,`authz`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_create_dpop_token(`ptr`: Pointer,`accessTokenUrl`: RustBuffer,`backendNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_create_dpop_token(`ptr`,`accessTokenUrl`,`backendNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_dpop_challenge_request(`ptr`: Pointer,`accessToken`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_dpop_challenge_request(`ptr`,`accessToken`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_oidc_challenge_request(`ptr`: Pointer,`idToken`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_oidc_challenge_request(`ptr`,`idToken`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_new_challenge_response(`ptr`: Pointer,`challenge`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_new_challenge_response(`ptr`,`challenge`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_check_order_request(`ptr`: Pointer,`orderUrl`: RustBuffer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_check_order_request(`ptr`,`orderUrl`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_check_order_response(`ptr`: Pointer,`order`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_check_order_response(`ptr`,`order`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_finalize_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_finalize_request(`ptr`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_finalize_response(`ptr`: Pointer,`finalize`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_finalize_response(`ptr`,`finalize`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_WireE2eIdentity_certificate_request(`ptr`: Pointer,`previousNonce`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_WireE2eIdentity_certificate_request(`ptr`,`previousNonce`,
    _uniffi_out_err
        ))

    actual fun ffi_CoreCrypto_552_CoreCryptoCallbacks_init_callback(`callbackStub`: ForeignCallback,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.ffi_CoreCrypto_552_CoreCryptoCallbacks_init_callback(`callbackStub`,
    _uniffi_out_err
        ))

    actual fun CoreCrypto_552_version(
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.CoreCrypto_552_version(
    _uniffi_out_err
        ))

    actual fun ffi_CoreCrypto_552_rustbuffer_alloc(`size`: Int,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.ffi_CoreCrypto_552_rustbuffer_alloc(`size`,
    _uniffi_out_err
        ))

    actual fun ffi_CoreCrypto_552_rustbuffer_from_bytes(`bytes`: ForeignBytes,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.ffi_CoreCrypto_552_rustbuffer_from_bytes(`bytes`,
    _uniffi_out_err
        ))

    actual fun ffi_CoreCrypto_552_rustbuffer_free(`buf`: RustBuffer,
    _uniffi_out_err: RustCallStatus
    ): Unit =
        requireNotNull(com.wire.crypto.cinterop.ffi_CoreCrypto_552_rustbuffer_free(`buf`,
    _uniffi_out_err
        ))

    actual fun ffi_CoreCrypto_552_rustbuffer_reserve(`buf`: RustBuffer,`additional`: Int,
    _uniffi_out_err: RustCallStatus
    ): RustBuffer =
        requireNotNull(com.wire.crypto.cinterop.ffi_CoreCrypto_552_rustbuffer_reserve(`buf`,`additional`,
    _uniffi_out_err
        ))

    
}