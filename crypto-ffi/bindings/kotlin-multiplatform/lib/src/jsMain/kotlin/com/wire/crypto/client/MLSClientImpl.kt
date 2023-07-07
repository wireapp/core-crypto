package com.wire.crypto.client

import externals.*
import externals.Ciphersuite as CoreCryptoCiphersuite
import externals.GroupInfoBundle as CoreCryptoGroupInfoBundle
import externals.CommitBundle as CoreCryptoCommitBundle
import externals.RatchetTreeType as CoreCryptoRatchetTreeType
import externals.GroupInfoEncryptionType as CoreCryptoGroupInfoEncryptionType
import externals.CredentialType as CoreCryptoCredentialType
import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

typealias ConversationId = Uint8Array
typealias CoreCryptoClientId = Uint8Array

class ExternalAddProposalArgsImpl(
    override var conversationId: ConversationId,
    override var epoch: Number,
    override var ciphersuite: externals.Ciphersuite,
    override var credentialType: externals.CredentialType
) : ExternalAddProposalArgs

class InviteeArgs(override var id: CoreCryptoClientId, override var kp: Uint8Array) : Invitee

@Suppress("TooManyFunctions")
class MLSClientImpl(private val coreCrypto: CoreCrypto): MLSClient {

    override suspend fun getPublicKey(ciphersuite: Ciphersuite): ByteArray =
        coreCrypto.clientPublicKey(toCiphersuite(ciphersuite)).await().toByteArray()

    override suspend fun generateKeyPackages(ciphersuite: Ciphersuite, amount: Int): List<ByteArray> =
        coreCrypto.clientKeypackages(toCiphersuite(ciphersuite), amount).await().map { it.toByteArray() }

    override suspend fun validKeyPackageCount(ciphersuite: Ciphersuite): ULong =
        coreCrypto.clientValidKeypackagesCount(toCiphersuite(ciphersuite)).await().toLong().toULong()

    override suspend fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle =
        toCommitBundle(coreCrypto.updateKeyingMaterial(groupId.toUint8Array()).await())

    override suspend fun conversationExists(groupId: MLSGroupId): Boolean =
        coreCrypto.conversationExists(groupId.toUint8Array()).await()

    override suspend fun conversationEpoch(groupId: MLSGroupId): ULong =
        coreCrypto.conversationEpoch(groupId.toUint8Array()).await().toLong().toULong()

    override suspend fun joinConversation(
        groupId: MLSGroupId,
        epoch: ULong,
        ciphersuite: Ciphersuite,
        credentialType: CredentialType
    ): HandshakeMessage =
        coreCrypto.newExternalProposal(
            ExternalProposalType.Add,
            ExternalAddProposalArgsImpl(
                groupId.toUint8Array(),
                epoch.toLong(),
                toCiphersuite(ciphersuite),
                toCredentialType(credentialType)
            )
        ).await().toByteArray()

    override suspend fun joinByExternalCommit(
        groupInfo: ByteArray,
        credentialType: CredentialType
    ): CommitBundle =
        toCommitBundle(coreCrypto.joinByExternalCommit(groupInfo.toUint8Array(), toCredentialType(credentialType)).await())

    override suspend fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId) =
        coreCrypto.mergePendingGroupFromExternalCommit(groupId.toUint8Array()).await()

    override suspend fun clearPendingGroupExternalCommit(groupId: MLSGroupId) =
        coreCrypto.clearPendingGroupFromExternalCommit(groupId.toUint8Array()).await()

    override suspend fun createConversation(
        groupId: MLSGroupId,
        creatorCredentialType: CredentialType,
        externalSenders: List<Ed22519Key>
    ) {
        coreCrypto.createConversation(
            groupId.toUint8Array(),
            toCredentialType(creatorCredentialType),
            object : ConversationConfiguration {
            override var ciphersuite: externals.Ciphersuite?
                get() = externals.Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                set(_) {}
            override var externalSenders: Array<Uint8Array>?
                get() = externalSenders.map { it.toUint8Array() }.toTypedArray()
                set(_) {}

            override var custom: CustomConfiguration?
                get() = null
                set(_) {}
        }).await()
    }

    override suspend fun wipeConversation(groupId: MLSGroupId) =
        coreCrypto.wipeConversation(groupId.toUint8Array()).await()

    override suspend fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId =
        coreCrypto.processWelcomeMessage(message.toUint8Array()).await().toByteArray()

    override suspend fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage =
        coreCrypto.encryptMessage(groupId.toUint8Array(), message.toUint8Array()).await().toByteArray()

    override suspend fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle =
        toDecryptedMessageBundle(coreCrypto.decryptMessage(groupId.toUint8Array(), message.toUint8Array()).await())

    override suspend fun commitAccepted(groupId: MLSGroupId) =
        coreCrypto.commitAccepted(groupId.toUint8Array()).await()

    override suspend fun commitPendingProposals(groupId: MLSGroupId): CommitBundle? =
        coreCrypto.commitPendingProposals(groupId.toUint8Array()).await()?.let { toCommitBundle(it) }

    override suspend fun clearPendingCommit(groupId: MLSGroupId) =
        coreCrypto.clearPendingCommit(groupId.toUint8Array()).await()

    override suspend fun members(groupId: MLSGroupId): List<ClientId> =
        coreCrypto.getClientIds(groupId.toUint8Array()).await().map { it.toByteArray().decodeToString() }

    override suspend fun addMember(groupId: MLSGroupId, members: List<Pair<ClientId, MLSKeyPackage>>): CommitBundle? {
        if (members.isEmpty()) {
            return null
        }

        val invitees = members.map {
            InviteeArgs(
                it.first.toUint8Array(),
                it.second.toUint8Array()
            )
        }.toTypedArray<Invitee>()

        return toCommitBundle(coreCrypto.addClientsToConversation(groupId.toUint8Array(), invitees).await())
    }

    override suspend fun removeMember(groupId: MLSGroupId, members: List<ClientId>): CommitBundle =
        toCommitBundle(
            coreCrypto.removeClientsFromConversation(
                groupId.toUint8Array(),
                members.map { it.toUint8Array() }.toTypedArray()
            ).await()
        )

    override suspend fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray =
        coreCrypto.exportSecretKey(groupId.toUint8Array(), keyLength.toInt()).await().toByteArray()

    companion object {
        fun toCommitBundle(value: MemberAddedMessages) = CommitBundle(
            value.commit.toByteArray(),
            value.welcome.toByteArray(),
            toPublicGroupStateBundle(value.groupInfo)
        )

        fun toCommitBundle(value: CoreCryptoCommitBundle) = CommitBundle(
            value.commit.toByteArray(),
            value.welcome?.toByteArray(),
            toPublicGroupStateBundle(value.groupInfo)
        )

        fun toCommitBundle(value: ConversationInitBundle) = CommitBundle(
            value.commit.toByteArray(),
            null,
            toPublicGroupStateBundle(value.groupInfo)
        )

        fun toPublicGroupStateBundle(value: CoreCryptoGroupInfoBundle) = GroupInfoBundle(
            toEncryptionType(value.encryptionType),
            ratchetTreeType(value.ratchetTreeType),
            value.payload.toByteArray()
        )

        fun toDecryptedMessageBundle(value: DecryptedMessage) = DecryptedMessageBundle(
            value.message?.toByteArray(),
            value.commitDelay?.toLong(),
            value.senderClientId?.toByteArray()?.decodeToString(),
            value.hasEpochChanged
        )

        fun toEncryptionType(encryptionType: CoreCryptoGroupInfoEncryptionType) =
            when (encryptionType) {
                CoreCryptoGroupInfoEncryptionType.Plaintext -> GroupInfoEncryptionType.PLAINTEXT
                CoreCryptoGroupInfoEncryptionType.JweEncrypted -> GroupInfoEncryptionType.JWE_ENCRYPTED
            }

        fun ratchetTreeType(ratchetTreeType: CoreCryptoRatchetTreeType) =
            when (ratchetTreeType) {
                CoreCryptoRatchetTreeType.Full -> RatchetTreeType.FULL
                CoreCryptoRatchetTreeType.Delta -> RatchetTreeType.DELTA
                CoreCryptoRatchetTreeType.ByRef -> RatchetTreeType.BY_REF
            }

        fun toCredentialType(credentialType: CredentialType) =
            when (credentialType) {
                CredentialType.X509 -> CoreCryptoCredentialType.X509
                CredentialType.BASIC -> CoreCryptoCredentialType.Basic
            }

        fun toCiphersuite(ciphersuite: Ciphersuite) =
            when (ciphersuite.toUInt()) {
                1u -> CoreCryptoCiphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                2u -> CoreCryptoCiphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256
                3u -> CoreCryptoCiphersuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                4u -> CoreCryptoCiphersuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
                5u -> CoreCryptoCiphersuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521
                6u -> CoreCryptoCiphersuite.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
                7u -> CoreCryptoCiphersuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384
                else -> throw RuntimeException("Unknown ciphersuite")
            }
    }
}
