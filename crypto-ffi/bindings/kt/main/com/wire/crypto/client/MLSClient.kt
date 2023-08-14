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
import com.wire.crypto.client.MLSClientImpl.Companion.toUByteList
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
    var payload: ByteArray,
)

open class CommitBundle(
    val commit: ByteArray,
    val welcome: ByteArray?,
    val groupInfoBundle: GroupInfoBundle,
)

class DecryptedMessageBundle(
    val message: ByteArray?,
    val commitDelay: Long?,
    val senderClientId: ClientId?,
    val hasEpochChanged: Boolean,
)

interface MLSClient {

    suspend fun mlsInit(clientId: String)

    suspend fun getPublicKey(ciphersuite: Ciphersuite): ByteArray

    suspend fun generateKeyPackages(ciphersuite: Ciphersuite, credentialType: MlsCredentialType, amount: Int): List<ByteArray>

    suspend fun validKeyPackageCount(ciphersuite: Ciphersuite, credentialType: MlsCredentialType): ULong

    suspend fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle

    suspend fun conversationExists(groupId: MLSGroupId): Boolean

    suspend fun conversationEpoch(groupId: MLSGroupId): ULong

    suspend fun joinConversation(
        groupId: MLSGroupId,
        epoch: ULong,
        ciphersuite: Ciphersuite,
        credentialType: MlsCredentialType,
    ): HandshakeMessage

    suspend fun joinByExternalCommit(groupInfo: ByteArray, credentialType: MlsCredentialType): CommitBundle

    suspend fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId): List<DecryptedMessage>?

    suspend fun clearPendingGroupExternalCommit(groupId: MLSGroupId)

    suspend fun createConversation(
        groupId: MLSGroupId,
        creatorCredentialType: MlsCredentialType,
        externalSenders: List<Ed22519Key> = emptyList(),
        perDomainTrustAnchors: List<PerDomainTrustAnchor> = emptyList(),
    )

    suspend fun wipeConversation(groupId: MLSGroupId)

    suspend fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId

    suspend fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage

    suspend fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle

    suspend fun updateTrustAnchorsFromConversation(
        groupId: MLSGroupId,
        removeDomainNames: List<String>,
        addTrustAnchors: List<PerDomainTrustAnchor>,
    ): CommitBundle?

    suspend fun commitAccepted(groupId: MLSGroupId)

    suspend fun commitPendingProposals(groupId: MLSGroupId): CommitBundle?

    suspend fun clearPendingCommit(groupId: MLSGroupId)

    suspend fun members(groupId: MLSGroupId): List<ClientId>

    suspend fun addMember(
        groupId: MLSGroupId,
        members: List<Pair<ClientId, MLSKeyPackage>>,
    ): CommitBundle?

    suspend fun removeMember(
        groupId: MLSGroupId,
        members: List<ClientId>,
    ): CommitBundle

    suspend fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray

    suspend fun e2eiConversationState(groupId: MLSGroupId): E2eiConversationState

    suspend fun e2eiIsEnabled(ciphersuite: Ciphersuite): Boolean
}

@Suppress("TooManyFunctions")
@OptIn(ExperimentalUnsignedTypes::class)
class MLSClientImpl(
    private val cc: CoreCrypto,
) : MLSClient {

    override suspend fun mlsInit(clientId: String) {
        cc.mlsInit(clientId.encodeToByteArray().toUByteList(), DEFAULT_CIPHERSUITES)
    }

    override suspend fun getPublicKey(ciphersuite: Ciphersuite): ByteArray {
        return cc.clientPublicKey(ciphersuite).toUByteArray().asByteArray()
    }

    override suspend fun generateKeyPackages(ciphersuite: Ciphersuite, credentialType: MlsCredentialType, amount: Int): List<ByteArray> {
        return cc.clientKeypackages(ciphersuite, credentialType, amount.toUInt()).map { it.toUByteArray().asByteArray() }
    }

    override suspend fun validKeyPackageCount(ciphersuite: Ciphersuite, credentialType: MlsCredentialType): ULong {
        return cc.clientValidKeypackagesCount(ciphersuite, credentialType)
    }

    override suspend fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle {
        return cc.updateKeyingMaterial(groupId.toUByteList()).toCommitBundle()
    }

    override suspend fun conversationExists(groupId: MLSGroupId): Boolean {
        return cc.conversationExists(groupId.toUByteList())
    }

    override suspend fun conversationEpoch(groupId: MLSGroupId): ULong {
        return cc.conversationEpoch(groupId.toUByteList())
    }

    override suspend fun joinConversation(
        groupId: MLSGroupId,
        epoch: ULong,
        ciphersuite: Ciphersuite,
        credentialType: MlsCredentialType,
    ): HandshakeMessage {
        return cc.newExternalAddProposal(
            conversationId = groupId.toUByteList(),
            epoch = epoch,
            ciphersuite,
            credentialType,
        ).toByteArray()
    }

    override suspend fun joinByExternalCommit(groupInfo: ByteArray, credentialType: MlsCredentialType): CommitBundle {
        return cc.joinByExternalCommit(
            groupInfo.toUByteList(),
            defaultGroupConfiguration,
            credentialType,
        ).toCommitBundle()
    }

    override suspend fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId): List<DecryptedMessage>? {
        val groupIdAsBytes = groupId.toUByteList()
        return cc.mergePendingGroupFromExternalCommit(groupIdAsBytes)
    }

    override suspend fun clearPendingGroupExternalCommit(groupId: MLSGroupId) {
        cc.clearPendingGroupFromExternalCommit(groupId.toUByteList())
    }

    override suspend fun createConversation(groupId: MLSGroupId, creatorCredentialType: MlsCredentialType, externalSenders: List<Ed22519Key>, perDomainTrustAnchors: List<PerDomainTrustAnchor>) {
        val conf = ConversationConfiguration(
            DEFAULT_CIPHERSUITE,
            externalSenders,
            defaultGroupConfiguration,
            perDomainTrustAnchors,
        )

        val groupIdAsBytes = groupId.toUByteList()
        cc.createConversation(groupIdAsBytes, creatorCredentialType, conf)
    }

    override suspend fun wipeConversation(groupId: MLSGroupId) {
        cc.wipeConversation(groupId.toUByteList())
    }

    override suspend fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId {
        val conversationId = cc.processWelcomeMessage(message.toUByteList(), defaultGroupConfiguration)
        return conversationId.toByteArray()
    }

    override suspend fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage {
        val applicationMessage = cc.encryptMessage(groupId.toUByteList(), message.toUByteList())
        return applicationMessage.toByteArray()
    }

    override suspend fun updateTrustAnchorsFromConversation(
        groupId: MLSGroupId,
        removeDomainNames: List<String>,
        addTrustAnchors: List<PerDomainTrustAnchor>,
    ): CommitBundle? {
        val result = cc.updateTrustAnchorsFromConversation(groupId.toUByteList(), removeDomainNames, addTrustAnchors)
        return result.toCommitBundle()
    }

    override suspend fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle {
        return cc.decryptMessage(groupId.toUByteList(), message.toUByteList()).toDecryptedMessageBundle()
    }

    override suspend fun commitAccepted(groupId: MLSGroupId) {
        return cc.commitAccepted(groupId.toUByteList())
    }

    override suspend fun commitPendingProposals(groupId: MLSGroupId): CommitBundle? {
        return cc.commitPendingProposals(groupId.toUByteList())?.toCommitBundle()
    }

    override suspend fun clearPendingCommit(groupId: MLSGroupId) {
        cc.clearPendingCommit(groupId.toUByteList())
    }

    override suspend fun members(groupId: MLSGroupId): List<ClientId> {
        return cc.getClientIds(groupId.toUByteList()).map { String(it.toUByteArray().asByteArray()) }
    }

    override suspend fun addMember(
        groupId: MLSGroupId,
        members: List<Pair<ClientId, MLSKeyPackage>>,
    ): CommitBundle? {
        if (members.isEmpty()) {
            return null
        }

        val invitees = members.map {
            Invitee(it.first.encodeToByteArray().toUByteList(), it.second.toUByteList().toByteArray())
        }

        return cc.addClientsToConversation(groupId.toUByteList(), invitees).toCommitBundle()
    }

    override suspend fun removeMember(
        groupId: MLSGroupId,
        members: List<ClientId>,
    ): CommitBundle {
        val clientIds = members.map { it.encodeToByteArray().toUByteList() }
        return cc.removeClientsFromConversation(groupId.toUByteList(), clientIds).toCommitBundle()
    }

    override suspend fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray {
        return cc.exportSecretKey(groupId.toUByteList(), keyLength).toByteArray()
    }

    override suspend fun e2eiConversationState(groupId: MLSGroupId): E2eiConversationState {
        return cc.e2eiConversationState(groupId.toUByteList())
    }

    override suspend fun e2eiIsEnabled(ciphersuite: Ciphersuite): Boolean {
        return cc.e2eiIsEnabled(ciphersuite)
    }

    companion object {

        private val keyRotationDuration: Duration = 30.toDuration(DurationUnit.DAYS)
        private val defaultGroupConfiguration =
            CustomConfiguration(java.time.Duration.ofDays(keyRotationDuration.inWholeDays), MlsWirePolicy.PLAINTEXT)

        fun ByteArray.toUByteList(): List<UByte> = asUByteArray().asList()
        fun String.toUByteList(): List<UByte> = encodeToByteArray().asUByteArray().asList()
        fun List<UByte>.toByteArray() = toUByteArray().asByteArray()

        fun MemberAddedMessages.toCommitBundle() = CommitBundle(
            commit,
            welcome,
            groupInfo.toGroupInfoBundle(),
        )

        fun com.wire.crypto.CommitBundle.toCommitBundle() = CommitBundle(
            commit,
            welcome,
            groupInfo.toGroupInfoBundle(),
        )

        fun ConversationInitBundle.toCommitBundle() = CommitBundle(
            commit,
            null,
            groupInfo.toGroupInfoBundle(),
        )

        fun com.wire.crypto.GroupInfoBundle.toGroupInfoBundle() = GroupInfoBundle(
            encryptionType,
            ratchetTreeType,
            payload,
        )

        fun DecryptedMessage.toDecryptedMessageBundle() = DecryptedMessageBundle(
            message,
            commitDelay?.toLong(),
            senderClientId?.let { String(it.toByteArray()) },
            hasEpochChanged,
        )
    }
}
