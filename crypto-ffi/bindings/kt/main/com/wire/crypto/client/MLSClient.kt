/*
 * Wire
 * Copyright (C) 2023 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 */

package com.wire.crypto.client

import com.wire.crypto.*
import com.wire.crypto.client.CoreCryptoCentral.Companion.DEFAULT_CIPHERSUITE
import com.wire.crypto.client.CoreCryptoCentral.Companion.DEFAULT_CIPHERSUITES
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

typealias MLSGroupId = ByteArray
typealias ClientId = String
typealias Ed22519Key = ByteArray

typealias WelcomeMessage = ByteArray
typealias HandshakeMessage = ByteArray
typealias ApplicationMessage = ByteArray
typealias PlainMessage = ByteArray
typealias MLSKeyPackage = ByteArray

open class GroupInfoBundle(
    var encryptionType: MlsGroupInfoEncryptionType,
    var ratchetTreeType: MlsRatchetTreeType,
    var payload: ByteArray
)

open class CommitBundle(
    val commit: ByteArray,
    val welcome: ByteArray?,
    val groupInfoBundle: GroupInfoBundle
)

class DecryptedMessageBundle(
    val message: ByteArray?,
    val commitDelay: Long?,
    val senderClientId: ClientId?,
    val hasEpochChanged: Boolean
)

interface MLSClient {

    fun mlsInit(clientId: String)

    fun getPublicKey(ciphersuite: Ciphersuite): ByteArray

    fun generateKeyPackages(ciphersuite: Ciphersuite, amount: Int): List<ByteArray>

    fun validKeyPackageCount(ciphersuite: Ciphersuite): ULong

    fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle

    fun conversationExists(groupId: MLSGroupId): Boolean

    fun conversationEpoch(groupId: MLSGroupId): ULong

    fun joinConversation(
        groupId: MLSGroupId,
        epoch: ULong,
        ciphersuite: Ciphersuite,
        credentialType: MlsCredentialType
    ): HandshakeMessage

    fun joinByExternalCommit(groupInfo: ByteArray, credentialType: MlsCredentialType): CommitBundle

    fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId)

    fun clearPendingGroupExternalCommit(groupId: MLSGroupId)

    fun createConversation(
        groupId: MLSGroupId,
        creatorCredentialType: MlsCredentialType,
        externalSenders: List<Ed22519Key> = emptyList()
    )

    fun wipeConversation(groupId: MLSGroupId)

    fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId

    fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage

    fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle

    fun commitAccepted(groupId: MLSGroupId)

    fun commitPendingProposals(groupId: MLSGroupId): CommitBundle?

    fun clearPendingCommit(groupId: MLSGroupId)

    fun members(groupId: MLSGroupId): List<ClientId>

    fun addMember(
        groupId: MLSGroupId,
        members: List<Pair<ClientId, MLSKeyPackage>>
    ): CommitBundle?

    fun removeMember(
        groupId: MLSGroupId,
        members: List<ClientId>
    ): CommitBundle

    fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray

    fun e2eiIsDegraded(groupId: MLSGroupId): Boolean
}

@Suppress("TooManyFunctions")
@OptIn(ExperimentalUnsignedTypes::class)
class MLSClientImpl(
    private val cc: CoreCrypto,
) : MLSClient {

    override fun mlsInit(clientId: String) {
        cc.mlsInit(clientId.toUByteList(), DEFAULT_CIPHERSUITES)
    }

    override fun getPublicKey(ciphersuite: Ciphersuite): ByteArray {
        return cc.clientPublicKey(ciphersuite).toUByteArray().asByteArray()
    }

    override fun generateKeyPackages(ciphersuite: Ciphersuite, amount: Int): List<ByteArray> {
        return cc.clientKeypackages(ciphersuite, amount.toUInt()).map { it.toUByteArray().asByteArray() }
    }

    override fun validKeyPackageCount(ciphersuite: Ciphersuite): ULong {
        return cc.clientValidKeypackagesCount(ciphersuite)
    }

    override fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle {
        return cc.updateKeyingMaterial(groupId.toUByteList()).toCommitBundle()
    }

    override fun conversationExists(groupId: MLSGroupId): Boolean {
        return cc.conversationExists(groupId.toUByteList())
    }

    override fun conversationEpoch(groupId: MLSGroupId): ULong {
        return cc.conversationEpoch(groupId.toUByteList())
    }

    override fun joinConversation(
        groupId: MLSGroupId,
        epoch: ULong,
        ciphersuite: Ciphersuite,
        credentialType: MlsCredentialType
    ): HandshakeMessage {
        return cc.newExternalAddProposal(
            conversationId = groupId.toUByteList(),
            epoch = epoch,
            ciphersuite,
            credentialType,
        ).toByteArray()
    }

    override fun joinByExternalCommit(groupInfo: ByteArray, credentialType: MlsCredentialType): CommitBundle {
        return cc.joinByExternalCommit(
            groupInfo.toUByteList(),
            defaultGroupConfiguration,
            credentialType
        ).toCommitBundle()
    }

    override fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId) {
        val groupIdAsBytes = groupId.toUByteList()
        cc.mergePendingGroupFromExternalCommit(groupIdAsBytes)
    }

    override fun clearPendingGroupExternalCommit(groupId: MLSGroupId) {
        cc.clearPendingGroupFromExternalCommit(groupId.toUByteList())
    }

    override fun createConversation(groupId: MLSGroupId, creatorCredentialType: MlsCredentialType, externalSenders: List<Ed22519Key>) {
        val conf = ConversationConfiguration(
            DEFAULT_CIPHERSUITE,
            externalSenders.map { it.toUByteList() },
            defaultGroupConfiguration
        )

        val groupIdAsBytes = groupId.toUByteList()
        cc.createConversation(groupIdAsBytes, creatorCredentialType, conf)
    }

    override fun wipeConversation(groupId: MLSGroupId) {
        cc.wipeConversation(groupId.toUByteList())
    }

    override fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId {
        val conversationId = cc.processWelcomeMessage(message.toUByteList(), defaultGroupConfiguration)
        return conversationId.toByteArray()
    }

    override fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage {
        val applicationMessage = cc.encryptMessage(groupId.toUByteList(), message.toUByteList())
        return applicationMessage.toByteArray()
    }

    override fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle {
        return cc.decryptMessage(groupId.toUByteList(), message.toUByteList()).toDecryptedMessageBundle()
    }

    override fun commitAccepted(groupId: MLSGroupId) {
        cc.commitAccepted(groupId.toUByteList())
    }

    override fun commitPendingProposals(groupId: MLSGroupId): CommitBundle? {
        return cc.commitPendingProposals(groupId.toUByteList())?.toCommitBundle()
    }

    override fun clearPendingCommit(groupId: MLSGroupId) {
        cc.clearPendingCommit(groupId.toUByteList())
    }

    override fun members(groupId: MLSGroupId): List<ClientId> {
        return cc.getClientIds(groupId.toUByteList()).map { String(it.toByteArray()) }
    }

    override fun addMember(
        groupId: MLSGroupId,
        members: List<Pair<ClientId, MLSKeyPackage>>
    ): CommitBundle? {
        if (members.isEmpty()) {
            return null
        }

        val invitees = members.map {
            Invitee(it.first.toUByteList(), it.second.toUByteList())
        }

        return cc.addClientsToConversation(groupId.toUByteList(), invitees).toCommitBundle()
    }

    override fun removeMember(
        groupId: MLSGroupId,
        members: List<ClientId>
    ): CommitBundle {
        val clientIds = members.map { it.toUByteList() }
        return cc.removeClientsFromConversation(groupId.toUByteList(), clientIds).toCommitBundle()
    }

    override fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray {
        return cc.exportSecretKey(groupId.toUByteList(), keyLength).toByteArray()
    }

    override fun e2eiIsDegraded(groupId: MLSGroupId): Boolean {
        return cc.e2eiIsDegraded(groupId.toUByteList())
    }

    companion object {

        private val keyRotationDuration: Duration = 30.toDuration(DurationUnit.DAYS)
        private val defaultGroupConfiguration =
            CustomConfiguration(java.time.Duration.ofDays(keyRotationDuration.inWholeDays), MlsWirePolicy.PLAINTEXT)

        fun ByteArray.toUByteList(): List<UByte> = asUByteArray().asList()
        fun String.toUByteList(): List<UByte> = encodeToByteArray().asUByteArray().asList()
        fun List<UByte>.toByteArray() = toUByteArray().asByteArray()

        fun MemberAddedMessages.toCommitBundle() = CommitBundle(
            commit.toByteArray(),
            welcome.toByteArray(),
            groupInfo.toGroupInfoBundle()
        )

        fun com.wire.crypto.CommitBundle.toCommitBundle() = CommitBundle(
            commit.toByteArray(),
            welcome?.toByteArray(),
            groupInfo.toGroupInfoBundle()
        )

        fun ConversationInitBundle.toCommitBundle() = CommitBundle(
            commit.toByteArray(),
            null,
            groupInfo.toGroupInfoBundle()
        )

        fun com.wire.crypto.GroupInfoBundle.toGroupInfoBundle() = GroupInfoBundle(
            encryptionType,
            ratchetTreeType,
            payload.toByteArray()
        )

        fun DecryptedMessage.toDecryptedMessageBundle() = DecryptedMessageBundle(
            message?.toByteArray(),
            commitDelay?.toLong(),
            senderClientId?.toByteArray()?.let { String(it) },
            hasEpochChanged
        )
    }

}
