package com.wire.crypto.client

import externals.*
import externals.PublicGroupStateBundle
import externals.CommitBundle as CoreCryptoCommitBundle
import externals.RatchetTreeType as CoreCryptoRatchetTreeType
import externals.PublicGroupStateEncryptionType as CoreCryptoPublicGroupStateEncryptionType
import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

typealias ConversationId = Uint8Array
typealias CoreCryptoClientId = Uint8Array

class ExternalAddProposalArgs(
    override var conversationId: ConversationId,
    override var epoch: Number
) : ExternalProposalArgs

class InviteeArgs(override var id: CoreCryptoClientId, override var kp: Uint8Array) : Invitee

@Suppress("TooManyFunctions")
class MLSClientImpl(private val coreCrypto: CoreCrypto): MLSClient {

    override suspend fun getPublicKey(): ByteArray =
        coreCrypto.clientPublicKey().await().toByteArray()

    override suspend fun generateKeyPackages(amount: Int): List<ByteArray> =
        coreCrypto.clientKeypackages(amount).await().map { it.toByteArray() }

    override suspend fun validKeyPackageCount(): ULong =
        coreCrypto.clientValidKeypackagesCount().await().toLong().toULong()

    override suspend fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle =
        toCommitBundle(coreCrypto.updateKeyingMaterial(groupId.toUint8Array()).await())

    override suspend fun conversationExists(groupId: MLSGroupId): Boolean =
        coreCrypto.conversationExists(groupId.toUint8Array()).await()

    override suspend fun conversationEpoch(groupId: MLSGroupId): ULong =
        coreCrypto.conversationEpoch(groupId.toUint8Array()).await().toLong().toULong()

    override suspend fun joinConversation(groupId: MLSGroupId, epoch: ULong): HandshakeMessage =
        coreCrypto.newExternalProposal(
            ExternalProposalType.Add, ExternalAddProposalArgs(
                groupId.toUint8Array(),
                epoch.toLong()
            )
        ).await().toByteArray()

    override suspend fun joinByExternalCommit(publicGroupState: ByteArray): CommitBundle =
        toCommitBundle(coreCrypto.joinByExternalCommit(publicGroupState.toUint8Array()).await())

    override suspend fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId) =
        coreCrypto.mergePendingGroupFromExternalCommit(groupId.toUint8Array()).await()

    override suspend fun clearPendingGroupExternalCommit(groupId: MLSGroupId) =
        coreCrypto.clearPendingGroupFromExternalCommit(groupId.toUint8Array()).await()

    override suspend fun createConversation(groupId: MLSGroupId, externalSenders: List<Ed22519Key>) {
        coreCrypto.createConversation(groupId.toUint8Array(), object : ConversationConfiguration {
            override var ciphersuite: Ciphersuite?
                get() = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
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
            toPublicGroupStateBundle(value.publicGroupState)
        )

        fun toCommitBundle(value: CoreCryptoCommitBundle) = CommitBundle(
            value.commit.toByteArray(),
            value.welcome?.toByteArray(),
            toPublicGroupStateBundle(value.publicGroupState)
        )

        fun toCommitBundle(value: ConversationInitBundle) = CommitBundle(
            value.commit.toByteArray(),
            null,
            toPublicGroupStateBundle(value.publicGroupState)
        )

        fun toPublicGroupStateBundle(value: PublicGroupStateBundle) = PublicGroupStateBundle(
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

        fun toEncryptionType(encryptionType: CoreCryptoPublicGroupStateEncryptionType) =
            when (encryptionType) {
                CoreCryptoPublicGroupStateEncryptionType.Plaintext -> PublicGroupStateEncryptionType.PLAINTEXT
                CoreCryptoPublicGroupStateEncryptionType.JweEncrypted -> PublicGroupStateEncryptionType.JWE_ENCRYPTED
            }

        fun ratchetTreeType(ratchetTreeType: CoreCryptoRatchetTreeType) =
            when (ratchetTreeType) {
                CoreCryptoRatchetTreeType.Full -> RatchetTreeType.FULL
                CoreCryptoRatchetTreeType.Delta -> RatchetTreeType.DELTA
                CoreCryptoRatchetTreeType.ByRef -> RatchetTreeType.BY_REF
            }
    }
}
