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

import com.wire.crypto.CiphersuiteName
import com.wire.crypto.ConversationConfiguration
import com.wire.crypto.CoreCrypto
import com.wire.crypto.CustomConfiguration
import com.wire.crypto.DecryptedMessage
import com.wire.crypto.Invitee
import com.wire.crypto.MlsPublicGroupStateEncryptionType
import com.wire.crypto.MlsRatchetTreeType
import com.wire.crypto.MlsWirePolicy
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

enum class PublicGroupStateEncryptionType {
    PLAINTEXT,
    JWE_ENCRYPTED
}

enum class RatchetTreeType {
    FULL,
    DELTA,
    BY_REF
}

open class PublicGroupStateBundle(
    var encryptionType: PublicGroupStateEncryptionType,
    var ratchetTreeType: RatchetTreeType,
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
    fun getPublicKey(): ByteArray

    fun generateKeyPackages(amount: Int): List<ByteArray>

    fun validKeyPackageCount(): ULong

    fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle

    fun conversationExists(groupId: MLSGroupId): Boolean

    fun conversationEpoch(groupId: MLSGroupId): ULong

    fun joinConversation(groupId: MLSGroupId, epoch: ULong): HandshakeMessage
    fun joinByExternalCommit(publicGroupState: ByteArray): CommitBundle

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
class MLSClientImpl constructor(
    private val coreCrypto: CoreCrypto,
    clientId: String
) : MLSClient {
    private val keyRotationDuration: Duration = 30.toDuration(DurationUnit.DAYS)
    private val defaultGroupConfiguration = CustomConfiguration(java.time.Duration.ofDays(keyRotationDuration.inWholeDays), MlsWirePolicy.PLAINTEXT)
    private val defaultCiphersuiteName = CiphersuiteName.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519

    init {
        coreCrypto.mlsInit(toUByteList(clientId))
    }

    override fun getPublicKey(): ByteArray {
        return coreCrypto.clientPublicKey().toUByteArray().asByteArray()
    }

    override fun generateKeyPackages(amount: Int): List<ByteArray> {
        return coreCrypto.clientKeypackages(amount.toUInt()).map { it.toUByteArray().asByteArray() }
    }

    override fun validKeyPackageCount(): ULong {
        return coreCrypto.clientValidKeypackagesCount()
    }

    override fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle {
        return toCommitBundle(coreCrypto.updateKeyingMaterial(toUByteList(groupId)))
    }

    override fun conversationExists(groupId: MLSGroupId): Boolean {
        return coreCrypto.conversationExists(toUByteList(groupId))
    }

    override fun conversationEpoch(groupId: MLSGroupId): ULong {
        return coreCrypto.conversationEpoch(toUByteList(groupId))
    }

    override fun joinConversation(groupId: MLSGroupId, epoch: ULong): HandshakeMessage {
        return toByteArray(
            coreCrypto.newExternalAddProposal(
                conversationId = toUByteList(groupId),
                epoch = epoch
            )
        )
    }

    override fun joinByExternalCommit(publicGroupState: ByteArray): CommitBundle {
        return toCommitBundle(coreCrypto.joinByExternalCommit(toUByteList(publicGroupState), defaultGroupConfiguration))
    }

    override fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId) {
        val groupIdAsBytes = toUByteList(groupId)
        coreCrypto.mergePendingGroupFromExternalCommit(groupIdAsBytes)
    }

    override fun clearPendingGroupExternalCommit(groupId: MLSGroupId) {
        coreCrypto.clearPendingGroupFromExternalCommit(toUByteList(groupId))
    }

    override fun createConversation(
        groupId: MLSGroupId,
        externalSenders: List<Ed22519Key>
    ) {
        val conf = ConversationConfiguration(
            defaultCiphersuiteName,
            externalSenders.map { toUByteList(it) },
            defaultGroupConfiguration
        )

        val groupIdAsBytes = toUByteList(groupId)
        coreCrypto.createConversation(groupIdAsBytes, conf)
    }

    override fun wipeConversation(groupId: MLSGroupId) {
        coreCrypto.wipeConversation(toUByteList(groupId))
    }

    override fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId {
        val conversationId = coreCrypto.processWelcomeMessage(toUByteList(message), defaultGroupConfiguration)
        return toByteArray(conversationId)
    }

    override fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage {
        val applicationMessage = coreCrypto.encryptMessage(toUByteList(groupId), toUByteList(message))
        return toByteArray(applicationMessage)
    }

    override fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle {
        return toDecryptedMessageBundle(coreCrypto.decryptMessage(toUByteList(groupId), toUByteList(message)))
    }

    override fun commitAccepted(groupId: MLSGroupId) {
        coreCrypto.commitAccepted(toUByteList(groupId))
    }

    override fun commitPendingProposals(groupId: MLSGroupId): CommitBundle? {
        return coreCrypto.commitPendingProposals(toUByteList(groupId))?.let { toCommitBundle(it) }
    }

    override fun clearPendingCommit(groupId: MLSGroupId) {
        coreCrypto.clearPendingCommit(toUByteList(groupId))
    }

    override fun members(groupId: MLSGroupId): List<ClientId> {
        return coreCrypto.getClientIds(toUByteList(groupId)).map {
            String(toByteArray(it))
        }
    }

    override fun addMember(
        groupId: MLSGroupId,
        members: List<Pair<ClientId, MLSKeyPackage>>
    ): CommitBundle? {
        if (members.isEmpty()) {
            return null
        }

        val invitees = members.map {
            Invitee(toUByteList(it.first), toUByteList(it.second))
        }

        return toCommitBundle(coreCrypto.addClientsToConversation(toUByteList(groupId), invitees))
    }

    override fun removeMember(
        groupId: MLSGroupId,
        members: List<ClientId>
    ): CommitBundle {
        val clientIds = members.map {
            toUByteList(it)
        }

        return toCommitBundle(coreCrypto.removeClientsFromConversation(toUByteList(groupId), clientIds))
    }

    override fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray {
        return toByteArray(coreCrypto.exportSecretKey(toUByteList(groupId), keyLength))
    }

    companion object {
        fun toUByteList(value: ByteArray): List<UByte> = value.asUByteArray().asList()
        fun toUByteList(value: String): List<UByte> = value.encodeToByteArray().asUByteArray().asList()
        fun toByteArray(value: List<UByte>) = value.toUByteArray().asByteArray()

        fun toCommitBundle(value: com.wire.crypto.MemberAddedMessages) = CommitBundle(
            toByteArray(value.commit),
            toByteArray(value.welcome),
            toPublicGroupStateBundle(value.publicGroupState)
        )

        fun toCommitBundle(value: com.wire.crypto.CommitBundle) = CommitBundle(
            toByteArray(value.commit),
            value.welcome?.let { toByteArray(it) },
            toPublicGroupStateBundle(value.publicGroupState)
        )

        fun toCommitBundle(value: com.wire.crypto.ConversationInitBundle) = CommitBundle(
            toByteArray(value.commit),
            null,
            toPublicGroupStateBundle(value.publicGroupState)
        )

        fun toPublicGroupStateBundle(value: com.wire.crypto.PublicGroupStateBundle) = PublicGroupStateBundle(
            toEncryptionType(value.encryptionType),
            toRatchetTreeType(value.ratchetTreeType),
            toByteArray(value.payload)
        )

        fun toEncryptionType(value: MlsPublicGroupStateEncryptionType) = when (value) {
            MlsPublicGroupStateEncryptionType.PLAINTEXT -> PublicGroupStateEncryptionType.PLAINTEXT
            MlsPublicGroupStateEncryptionType.JWE_ENCRYPTED -> PublicGroupStateEncryptionType.JWE_ENCRYPTED
        }

        fun toRatchetTreeType(value: MlsRatchetTreeType) = when (value) {
            MlsRatchetTreeType.FULL -> RatchetTreeType.FULL
            MlsRatchetTreeType.DELTA -> RatchetTreeType.DELTA
            MlsRatchetTreeType.BY_REF -> RatchetTreeType.BY_REF
        }

        fun toDecryptedMessageBundle(value: DecryptedMessage) = DecryptedMessageBundle(
            value.message?.let { toByteArray(it) },
            value.commitDelay?.toLong(),
            value.senderClientId?.let { String(toByteArray(it)) },
            value.hasEpochChanged
        )
    }

}
