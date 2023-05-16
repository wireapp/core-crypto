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

open class PublicGroupStateBundle(
    var encryptionType: MlsPublicGroupStateEncryptionType,
    var ratchetTreeType: MlsRatchetTreeType,
    var payload: ByteArray
)

open class CommitBundle(
    val commit: ByteArray,
    val welcome: ByteArray?,
    val publicGroupStateBundle: PublicGroupStateBundle
)

class DecryptedMessageBundle(
    val message: ByteArray?,
    val commitDelay: Long?,
    val senderClientId: ClientId?,
    val hasEpochChanged: Boolean
)

interface MLSClient {

    companion object {
        val defaultCiphersuite = CiphersuiteName.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519
    }

    fun mlsInit(clientId: String, ciphersuites: List<CiphersuiteName> = listOf(defaultCiphersuite))

    fun getPublicKey(ciphersuite: CiphersuiteName): ByteArray

    fun generateKeyPackages(ciphersuite: CiphersuiteName, amount: Int): List<ByteArray>

    fun validKeyPackageCount(ciphersuite: CiphersuiteName): ULong

    fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle

    fun conversationExists(groupId: MLSGroupId): Boolean

    fun conversationEpoch(groupId: MLSGroupId): ULong

    fun joinConversation(
        groupId: MLSGroupId,
        epoch: ULong,
        ciphersuite: CiphersuiteName,
        credentialType: MlsCredentialType
    ): HandshakeMessage

    fun joinByExternalCommit(publicGroupState: ByteArray, credentialType: MlsCredentialType): CommitBundle

    fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId)

    fun clearPendingGroupExternalCommit(groupId: MLSGroupId)

    fun createConversation(
        groupId: MLSGroupId,
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
}

@Suppress("TooManyFunctions")
@OptIn(ExperimentalUnsignedTypes::class)
class MLSClientImpl(
    private val cc: CoreCrypto,
) : MLSClient {

    override fun mlsInit(clientId: String, ciphersuites: List<CiphersuiteName>) {
        cc.mlsInit(clientId.toUByteList(), ciphersuites)
    }

    override fun getPublicKey(ciphersuite: CiphersuiteName): ByteArray {
        return cc.clientPublicKey(ciphersuite).toUByteArray().asByteArray()
    }

    override fun generateKeyPackages(ciphersuite: CiphersuiteName, amount: Int): List<ByteArray> {
        return cc.clientKeypackages(ciphersuite, amount.toUInt()).map { it.toUByteArray().asByteArray() }
    }

    override fun validKeyPackageCount(ciphersuite: CiphersuiteName): ULong {
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
        ciphersuite: CiphersuiteName,
        credentialType: MlsCredentialType
    ): HandshakeMessage {
        return cc.newExternalAddProposal(
            conversationId = groupId.toUByteList(),
            epoch = epoch,
            ciphersuite,
            credentialType,
        ).toByteArray()
    }

    override fun joinByExternalCommit(publicGroupState: ByteArray, credentialType: MlsCredentialType): CommitBundle {
        return cc.joinByExternalCommit(
            publicGroupState.toUByteList(),
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

    override fun createConversation(groupId: MLSGroupId, externalSenders: List<Ed22519Key>) {
        val conf = ConversationConfiguration(
            MLSClient.defaultCiphersuite,
            externalSenders.map { it.toUByteList() },
            defaultGroupConfiguration
        )

        val groupIdAsBytes = groupId.toUByteList()
        cc.createConversation(groupIdAsBytes, conf)
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
            publicGroupState.toPublicGroupStateBundle()
        )

        fun com.wire.crypto.CommitBundle.toCommitBundle() = CommitBundle(
            commit.toByteArray(),
            welcome?.toByteArray(),
            publicGroupState.toPublicGroupStateBundle()
        )

        fun ConversationInitBundle.toCommitBundle() = CommitBundle(
            commit.toByteArray(),
            null,
            publicGroupState.toPublicGroupStateBundle()
        )

        fun com.wire.crypto.PublicGroupStateBundle.toPublicGroupStateBundle() = PublicGroupStateBundle(
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
