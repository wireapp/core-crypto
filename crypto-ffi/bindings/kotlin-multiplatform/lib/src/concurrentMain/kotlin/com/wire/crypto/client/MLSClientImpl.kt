package com.wire.crypto.client

import com.wire.crypto.*
import com.wire.crypto.client.CoreCryptoCentral.Companion.DEFAULT_CIPHERSUITE
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

@Suppress("TooManyFunctions")
@OptIn(ExperimentalUnsignedTypes::class)
class MLSClientImpl constructor(
    private val coreCrypto: CoreCrypto
) : MLSClient {
    private val keyRotationDuration: Duration = 30.toDuration(DurationUnit.DAYS)
    private val defaultGroupConfiguration = CustomConfiguration(keyRotationDuration, MlsWirePolicy.PLAINTEXT)

    override suspend fun getPublicKey(ciphersuite: Ciphersuite): ByteArray {
        return coreCrypto.clientPublicKey(ciphersuite).toUByteArray().asByteArray()
    }

    override suspend fun generateKeyPackages(ciphersuite: Ciphersuite, amount: Int): List<ByteArray> {
        return coreCrypto.clientKeypackages(ciphersuite, amount.toUInt()).map { it.toUByteArray().asByteArray() }
    }

    override suspend fun validKeyPackageCount(ciphersuite: Ciphersuite): ULong {
        return coreCrypto.clientValidKeypackagesCount(ciphersuite)
    }

    override suspend fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle {
        return toCommitBundle(coreCrypto.updateKeyingMaterial(groupId.toUByteList()))
    }

    override suspend fun conversationExists(groupId: MLSGroupId): Boolean {
        return coreCrypto.conversationExists(groupId.toUByteList())
    }

    override suspend fun conversationEpoch(groupId: MLSGroupId): ULong {
        return coreCrypto.conversationEpoch(groupId.toUByteList())
    }

    override suspend fun joinConversation(
        groupId: MLSGroupId,
        epoch: ULong,
        ciphersuite: Ciphersuite,
        credentialType: CredentialType
    ): HandshakeMessage {
        return coreCrypto.newExternalAddProposal(
            conversationId = groupId.toUByteList(),
            epoch = epoch,
            ciphersuite = ciphersuite,
            credentialType = toCredentialType(credentialType)
        ).toByteArray()
    }

    override suspend fun joinByExternalCommit(
        groupInfo: ByteArray,
        credentialType: CredentialType
    ): CommitBundle {
        return toCommitBundle(
            coreCrypto.joinByExternalCommit(
                groupInfo.toUByteList(),
                defaultGroupConfiguration,
                toCredentialType(credentialType))
        )
    }

    override suspend fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId) {
        val groupIdAsBytes = groupId.toUByteList()
        coreCrypto.mergePendingGroupFromExternalCommit(groupIdAsBytes)
    }

    override suspend fun clearPendingGroupExternalCommit(groupId: MLSGroupId) {
        coreCrypto.clearPendingGroupFromExternalCommit(groupId.toUByteList())
    }

    override suspend fun createConversation(
        groupId: MLSGroupId,
        creatorCredentialType: CredentialType,
        externalSenders: List<Ed22519Key>
    ) {
        val conf = ConversationConfiguration(
            DEFAULT_CIPHERSUITE,
            externalSenders.map { it.toUByteList() },
            defaultGroupConfiguration
        )

        val groupIdAsBytes = groupId.toUByteList()
        coreCrypto.createConversation(groupIdAsBytes, toCredentialType(creatorCredentialType), conf)
    }

    override suspend fun wipeConversation(groupId: MLSGroupId) {
        coreCrypto.wipeConversation(groupId.toUByteList())
    }

    override suspend fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId {
        val conversationId = coreCrypto.processWelcomeMessage(message.toUByteList(), defaultGroupConfiguration)
        return conversationId.toByteArray()
    }

    override suspend fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage {
        val applicationMessage = coreCrypto.encryptMessage(groupId.toUByteList(), message.toUByteList())
        return applicationMessage.toByteArray()
    }

    override suspend fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle {
        return toDecryptedMessageBundle(coreCrypto.decryptMessage(groupId.toUByteList(), message.toUByteList()))
    }

    override suspend fun commitAccepted(groupId: MLSGroupId) {
        coreCrypto.commitAccepted(groupId.toUByteList())
    }

    override suspend fun commitPendingProposals(groupId: MLSGroupId): CommitBundle? {
        return coreCrypto.commitPendingProposals(groupId.toUByteList())?.let { toCommitBundle(it) }
    }

    override suspend fun clearPendingCommit(groupId: MLSGroupId) {
        coreCrypto.clearPendingCommit(groupId.toUByteList())
    }

    override suspend fun members(groupId: MLSGroupId): List<ClientId> {
        return coreCrypto.getClientIds(groupId.toUByteList()).map {
            it.toByteArray().decodeToString()
        }
    }

    override suspend fun addMember(
        groupId: MLSGroupId,
        members: List<Pair<ClientId, MLSKeyPackage>>
    ): CommitBundle? {
        if (members.isEmpty()) {
            return null
        }

        val invitees = members.map {
            Invitee(it.first.toUByteList(), it.second.toUByteList())
        }

        return toCommitBundle(coreCrypto.addClientsToConversation(groupId.toUByteList(), invitees))
    }

    override suspend fun removeMember(
        groupId: MLSGroupId,
        members: List<ClientId>
    ): CommitBundle {
        val clientIds = members.map {
            it.toUByteList()
        }

        return toCommitBundle(coreCrypto.removeClientsFromConversation(groupId.toUByteList(), clientIds))
    }

    override suspend fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray {
        return coreCrypto.exportSecretKey(groupId.toUByteList(), keyLength).toByteArray()
    }

    companion object {
        fun toCommitBundle(value: com.wire.crypto.MemberAddedMessages) = CommitBundle(
            value.commit.toByteArray(),
            value.welcome.toByteArray(),
            toGroupInfo(value.groupInfo)
        )

        fun toCommitBundle(value: com.wire.crypto.CommitBundle) = CommitBundle(
            value.commit.toByteArray(),
            value.welcome?.toByteArray(),
            toGroupInfo(value.groupInfo)
        )

        fun toCommitBundle(value: com.wire.crypto.ConversationInitBundle) = CommitBundle(
            value.commit.toByteArray(),
            null,
            toGroupInfo(value.groupInfo)
        )

        fun toGroupInfo(value: com.wire.crypto.GroupInfoBundle) = GroupInfoBundle(
            toEncryptionType(value.encryptionType),
            toRatchetTreeType(value.ratchetTreeType),
            value.payload.toByteArray()
        )

        fun toDecryptedMessageBundle(value: DecryptedMessage) = DecryptedMessageBundle(
            value.message?.toByteArray(),
            value.commitDelay?.toLong(),
            value.senderClientId?.toByteArray()?.decodeToString(),
            value.hasEpochChanged
        )

        fun toEncryptionType(encryptionType: MlsGroupInfoEncryptionType) =
            when (encryptionType) {
                MlsGroupInfoEncryptionType.PLAINTEXT -> GroupInfoEncryptionType.PLAINTEXT
                MlsGroupInfoEncryptionType.JWE_ENCRYPTED -> GroupInfoEncryptionType.JWE_ENCRYPTED
            }

        fun toRatchetTreeType(ratchetTreeType: MlsRatchetTreeType) =
            when (ratchetTreeType) {
                MlsRatchetTreeType.FULL -> RatchetTreeType.FULL
                MlsRatchetTreeType.DELTA -> RatchetTreeType.DELTA
                MlsRatchetTreeType.BY_REF -> RatchetTreeType.BY_REF
            }

        fun toCredentialType(credentialType: CredentialType) =
            when (credentialType) {
                CredentialType.X509 -> MlsCredentialType.X509
                CredentialType.BASIC -> MlsCredentialType.BASIC
            }
    }

}
