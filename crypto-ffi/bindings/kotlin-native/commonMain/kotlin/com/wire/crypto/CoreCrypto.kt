package com.wire.crypto


import okio.Buffer

interface CoreCryptoInterface {
    
    @Throws(CryptoException::class)
    fun `mlsInit`(`clientId`: ClientId)
    
    @Throws(CryptoException::class)
    fun `restoreFromDisk`()
    
    @Throws(CryptoException::class)
    fun `setCallbacks`(`callbacks`: CoreCryptoCallbacks)
    
    @Throws(CryptoException::class)
    fun `clientPublicKey`(): List<UByte>
    
    @Throws(CryptoException::class)
    fun `clientKeypackages`(`amountRequested`: UInt): List<List<UByte>>
    
    @Throws(CryptoException::class)
    fun `clientValidKeypackagesCount`(): ULong
    
    @Throws(CryptoException::class)
    fun `createConversation`(`conversationId`: ConversationId, `config`: ConversationConfiguration)
    
    @Throws(CryptoException::class)
    fun `conversationEpoch`(`conversationId`: ConversationId): ULong
    
    fun `conversationExists`(`conversationId`: ConversationId): Boolean
    
    @Throws(CryptoException::class)
    fun `processWelcomeMessage`(`welcomeMessage`: List<UByte>, `customConfiguration`: CustomConfiguration): ConversationId
    
    @Throws(CryptoException::class)
    fun `addClientsToConversation`(`conversationId`: ConversationId, `clients`: List<Invitee>): MemberAddedMessages
    
    @Throws(CryptoException::class)
    fun `removeClientsFromConversation`(`conversationId`: ConversationId, `clients`: List<ClientId>): CommitBundle
    
    @Throws(CryptoException::class)
    fun `updateKeyingMaterial`(`conversationId`: ConversationId): CommitBundle
    
    @Throws(CryptoException::class)
    fun `commitPendingProposals`(`conversationId`: ConversationId): CommitBundle?
    
    @Throws(CryptoException::class)
    fun `wipeConversation`(`conversationId`: ConversationId)
    
    @Throws(CryptoException::class)
    fun `decryptMessage`(`conversationId`: ConversationId, `payload`: List<UByte>): DecryptedMessage
    
    @Throws(CryptoException::class)
    fun `encryptMessage`(`conversationId`: ConversationId, `message`: List<UByte>): List<UByte>
    
    @Throws(CryptoException::class)
    fun `newAddProposal`(`conversationId`: ConversationId, `keyPackage`: List<UByte>): ProposalBundle
    
    @Throws(CryptoException::class)
    fun `newUpdateProposal`(`conversationId`: ConversationId): ProposalBundle
    
    @Throws(CryptoException::class)
    fun `newRemoveProposal`(`conversationId`: ConversationId, `clientId`: ClientId): ProposalBundle
    
    @Throws(CryptoException::class)
    fun `newExternalAddProposal`(`conversationId`: ConversationId, `epoch`: ULong): List<UByte>
    
    @Throws(CryptoException::class)
    fun `newExternalRemoveProposal`(`conversationId`: ConversationId, `epoch`: ULong, `keyPackageRef`: List<UByte>): List<UByte>
    
    @Throws(CryptoException::class)
    fun `joinByExternalCommit`(`publicGroupState`: List<UByte>, `customConfiguration`: CustomConfiguration): ConversationInitBundle
    
    @Throws(CryptoException::class)
    fun `mergePendingGroupFromExternalCommit`(`conversationId`: ConversationId)
    
    @Throws(CryptoException::class)
    fun `clearPendingGroupFromExternalCommit`(`conversationId`: ConversationId)
    
    @Throws(CryptoException::class)
    fun `exportGroupState`(`conversationId`: ConversationId): List<UByte>
    
    @Throws(CryptoException::class)
    fun `exportSecretKey`(`conversationId`: ConversationId, `keyLength`: UInt): List<UByte>
    
    @Throws(CryptoException::class)
    fun `getClientIds`(`conversationId`: ConversationId): List<ClientId>
    
    @Throws(CryptoException::class)
    fun `randomBytes`(`length`: UInt): List<UByte>
    
    @Throws(CryptoException::class)
    fun `reseedRng`(`seed`: List<UByte>)
    
    @Throws(CryptoException::class)
    fun `commitAccepted`(`conversationId`: ConversationId)
    
    @Throws(CryptoException::class)
    fun `clearPendingProposal`(`conversationId`: ConversationId, `proposalRef`: List<UByte>)
    
    @Throws(CryptoException::class)
    fun `clearPendingCommit`(`conversationId`: ConversationId)
    
    @Throws(CryptoException::class)
    fun `proteusInit`()
    
    @Throws(CryptoException::class)
    fun `proteusSessionFromPrekey`(`sessionId`: String, `prekey`: List<UByte>)
    
    @Throws(CryptoException::class)
    fun `proteusSessionFromMessage`(`sessionId`: String, `envelope`: List<UByte>): List<UByte>
    
    @Throws(CryptoException::class)
    fun `proteusSessionSave`(`sessionId`: String)
    
    @Throws(CryptoException::class)
    fun `proteusSessionDelete`(`sessionId`: String)
    
    @Throws(CryptoException::class)
    fun `proteusSessionExists`(`sessionId`: String): Boolean
    
    @Throws(CryptoException::class)
    fun `proteusDecrypt`(`sessionId`: String, `ciphertext`: List<UByte>): List<UByte>
    
    @Throws(CryptoException::class)
    fun `proteusEncrypt`(`sessionId`: String, `plaintext`: List<UByte>): List<UByte>
    
    @Throws(CryptoException::class)
    fun `proteusEncryptBatched`(`sessionId`: List<String>, `plaintext`: List<UByte>): Map<String, List<UByte>>
    
    @Throws(CryptoException::class)
    fun `proteusNewPrekey`(`prekeyId`: UShort): List<UByte>
    
    @Throws(CryptoException::class)
    fun `proteusNewPrekeyAuto`(): List<UByte>
    
    @Throws(CryptoException::class)
    fun `proteusFingerprint`(): String
    
    @Throws(CryptoException::class)
    fun `proteusFingerprintLocal`(`sessionId`: String): String
    
    @Throws(CryptoException::class)
    fun `proteusFingerprintRemote`(`sessionId`: String): String
    
    @Throws(CryptoException::class)
    fun `proteusFingerprintPrekeybundle`(`prekey`: List<UByte>): String
    
    @Throws(CryptoException::class)
    fun `proteusCryptoboxMigrate`(`path`: String)
    
}

class CoreCrypto(
    pointer: Pointer
) : FFIObject(pointer), CoreCryptoInterface {
    constructor(`path`: String, `key`: String, `clientId`: ClientId, `entropySeed`: List<UByte>?) :
        this(
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_new(FfiConverterString.lower(`path`), FfiConverterString.lower(`key`), FfiConverterTypeClientId.lower(`clientId`), FfiConverterOptionalSequenceUByte.lower(`entropySeed`), _status)
})

    override protected fun freeRustArcPtr() {
        rustCall() { status ->
            UniFFILib.ffi_CoreCrypto_8881_CoreCrypto_object_free(this.pointer, status)
        }
    }

    
    @Throws(CryptoException::class)override fun `mlsInit`(`clientId`: ClientId) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_mls_init(it, FfiConverterTypeClientId.lower(`clientId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `restoreFromDisk`() =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_restore_from_disk(it,  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `setCallbacks`(`callbacks`: CoreCryptoCallbacks) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_set_callbacks(it, FfiConverterTypeCoreCryptoCallbacks.lower(`callbacks`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `clientPublicKey`(): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_client_public_key(it,  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `clientKeypackages`(`amountRequested`: UInt): List<List<UByte>> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_client_keypackages(it, FfiConverterUInt.lower(`amountRequested`),  _status)
}
        }.let {
            FfiConverterSequenceSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `clientValidKeypackagesCount`(): ULong =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_client_valid_keypackages_count(it,  _status)
}
        }.let {
            FfiConverterULong.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `createConversation`(`conversationId`: ConversationId, `config`: ConversationConfiguration) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_create_conversation(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterTypeConversationConfiguration.lower(`config`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `conversationEpoch`(`conversationId`: ConversationId): ULong =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_conversation_epoch(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }.let {
            FfiConverterULong.lift(it)
        }
    override fun `conversationExists`(`conversationId`: ConversationId): Boolean =
        callWithPointer {
    rustCall() { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_conversation_exists(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }.let {
            FfiConverterBoolean.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `processWelcomeMessage`(`welcomeMessage`: List<UByte>, `customConfiguration`: CustomConfiguration): ConversationId =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_process_welcome_message(it, FfiConverterSequenceUByte.lower(`welcomeMessage`), FfiConverterTypeCustomConfiguration.lower(`customConfiguration`),  _status)
}
        }.let {
            FfiConverterTypeConversationId.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `addClientsToConversation`(`conversationId`: ConversationId, `clients`: List<Invitee>): MemberAddedMessages =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_add_clients_to_conversation(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterSequenceTypeInvitee.lower(`clients`),  _status)
}
        }.let {
            FfiConverterTypeMemberAddedMessages.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `removeClientsFromConversation`(`conversationId`: ConversationId, `clients`: List<ClientId>): CommitBundle =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_remove_clients_from_conversation(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterSequenceTypeClientId.lower(`clients`),  _status)
}
        }.let {
            FfiConverterTypeCommitBundle.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `updateKeyingMaterial`(`conversationId`: ConversationId): CommitBundle =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_update_keying_material(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }.let {
            FfiConverterTypeCommitBundle.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `commitPendingProposals`(`conversationId`: ConversationId): CommitBundle? =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_commit_pending_proposals(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }.let {
            FfiConverterOptionalTypeCommitBundle.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `wipeConversation`(`conversationId`: ConversationId) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_wipe_conversation(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `decryptMessage`(`conversationId`: ConversationId, `payload`: List<UByte>): DecryptedMessage =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_decrypt_message(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterSequenceUByte.lower(`payload`),  _status)
}
        }.let {
            FfiConverterTypeDecryptedMessage.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `encryptMessage`(`conversationId`: ConversationId, `message`: List<UByte>): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_encrypt_message(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterSequenceUByte.lower(`message`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `newAddProposal`(`conversationId`: ConversationId, `keyPackage`: List<UByte>): ProposalBundle =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_new_add_proposal(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterSequenceUByte.lower(`keyPackage`),  _status)
}
        }.let {
            FfiConverterTypeProposalBundle.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `newUpdateProposal`(`conversationId`: ConversationId): ProposalBundle =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_new_update_proposal(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }.let {
            FfiConverterTypeProposalBundle.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `newRemoveProposal`(`conversationId`: ConversationId, `clientId`: ClientId): ProposalBundle =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_new_remove_proposal(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterTypeClientId.lower(`clientId`),  _status)
}
        }.let {
            FfiConverterTypeProposalBundle.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `newExternalAddProposal`(`conversationId`: ConversationId, `epoch`: ULong): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_new_external_add_proposal(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterULong.lower(`epoch`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `newExternalRemoveProposal`(`conversationId`: ConversationId, `epoch`: ULong, `keyPackageRef`: List<UByte>): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_new_external_remove_proposal(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterULong.lower(`epoch`), FfiConverterSequenceUByte.lower(`keyPackageRef`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `joinByExternalCommit`(`publicGroupState`: List<UByte>, `customConfiguration`: CustomConfiguration): ConversationInitBundle =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_join_by_external_commit(it, FfiConverterSequenceUByte.lower(`publicGroupState`), FfiConverterTypeCustomConfiguration.lower(`customConfiguration`),  _status)
}
        }.let {
            FfiConverterTypeConversationInitBundle.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `mergePendingGroupFromExternalCommit`(`conversationId`: ConversationId) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_merge_pending_group_from_external_commit(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `clearPendingGroupFromExternalCommit`(`conversationId`: ConversationId) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_clear_pending_group_from_external_commit(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `exportGroupState`(`conversationId`: ConversationId): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_export_group_state(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `exportSecretKey`(`conversationId`: ConversationId, `keyLength`: UInt): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_export_secret_key(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterUInt.lower(`keyLength`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `getClientIds`(`conversationId`: ConversationId): List<ClientId> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_get_client_ids(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }.let {
            FfiConverterSequenceTypeClientId.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `randomBytes`(`length`: UInt): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_random_bytes(it, FfiConverterUInt.lower(`length`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `reseedRng`(`seed`: List<UByte>) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_reseed_rng(it, FfiConverterSequenceUByte.lower(`seed`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `commitAccepted`(`conversationId`: ConversationId) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_commit_accepted(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `clearPendingProposal`(`conversationId`: ConversationId, `proposalRef`: List<UByte>) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_clear_pending_proposal(it, FfiConverterTypeConversationId.lower(`conversationId`), FfiConverterSequenceUByte.lower(`proposalRef`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `clearPendingCommit`(`conversationId`: ConversationId) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_clear_pending_commit(it, FfiConverterTypeConversationId.lower(`conversationId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `proteusInit`() =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_init(it,  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `proteusSessionFromPrekey`(`sessionId`: String, `prekey`: List<UByte>) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_session_from_prekey(it, FfiConverterString.lower(`sessionId`), FfiConverterSequenceUByte.lower(`prekey`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `proteusSessionFromMessage`(`sessionId`: String, `envelope`: List<UByte>): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_session_from_message(it, FfiConverterString.lower(`sessionId`), FfiConverterSequenceUByte.lower(`envelope`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusSessionSave`(`sessionId`: String) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_session_save(it, FfiConverterString.lower(`sessionId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `proteusSessionDelete`(`sessionId`: String) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_session_delete(it, FfiConverterString.lower(`sessionId`),  _status)
}
        }
    
    
    @Throws(CryptoException::class)override fun `proteusSessionExists`(`sessionId`: String): Boolean =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_session_exists(it, FfiConverterString.lower(`sessionId`),  _status)
}
        }.let {
            FfiConverterBoolean.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusDecrypt`(`sessionId`: String, `ciphertext`: List<UByte>): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_decrypt(it, FfiConverterString.lower(`sessionId`), FfiConverterSequenceUByte.lower(`ciphertext`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusEncrypt`(`sessionId`: String, `plaintext`: List<UByte>): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_encrypt(it, FfiConverterString.lower(`sessionId`), FfiConverterSequenceUByte.lower(`plaintext`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusEncryptBatched`(`sessionId`: List<String>, `plaintext`: List<UByte>): Map<String, List<UByte>> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_encrypt_batched(it, FfiConverterSequenceString.lower(`sessionId`), FfiConverterSequenceUByte.lower(`plaintext`),  _status)
}
        }.let {
            FfiConverterMapStringListUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusNewPrekey`(`prekeyId`: UShort): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_new_prekey(it, FfiConverterUShort.lower(`prekeyId`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusNewPrekeyAuto`(): List<UByte> =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_new_prekey_auto(it,  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusFingerprint`(): String =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_fingerprint(it,  _status)
}
        }.let {
            FfiConverterString.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusFingerprintLocal`(`sessionId`: String): String =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_fingerprint_local(it, FfiConverterString.lower(`sessionId`),  _status)
}
        }.let {
            FfiConverterString.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusFingerprintRemote`(`sessionId`: String): String =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_fingerprint_remote(it, FfiConverterString.lower(`sessionId`),  _status)
}
        }.let {
            FfiConverterString.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusFingerprintPrekeybundle`(`prekey`: List<UByte>): String =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_fingerprint_prekeybundle(it, FfiConverterSequenceUByte.lower(`prekey`),  _status)
}
        }.let {
            FfiConverterString.lift(it)
        }
    
    @Throws(CryptoException::class)override fun `proteusCryptoboxMigrate`(`path`: String) =
        callWithPointer {
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_proteus_cryptobox_migrate(it, FfiConverterString.lower(`path`),  _status)
}
        }
    
    

    companion object {
        fun `deferredInit`(`path`: String, `key`: String, `entropySeed`: List<UByte>?): CoreCrypto =
            CoreCrypto(
    rustCallWithError(CryptoException) { _status ->
    UniFFILib.CoreCrypto_8881_CoreCrypto_deferred_init(FfiConverterString.lower(`path`), FfiConverterString.lower(`key`), FfiConverterOptionalSequenceUByte.lower(`entropySeed`), _status)
})
        
    }
    
}

object FfiConverterTypeCoreCrypto: FfiConverter<CoreCrypto, Pointer> {
    override fun lower(value: CoreCrypto): Pointer = value.callWithPointer { it }

    override fun lift(value: Pointer): CoreCrypto {
        return CoreCrypto(value)
    }

    override fun read(buf: Buffer): CoreCrypto {
        return lift(buf.readLong().toPointer())
    }

    override fun allocationSize(value: CoreCrypto) = 8

    override fun write(value: CoreCrypto, buf: Buffer) {
        buf.writeLong(lower(value).toLong())
    }
}