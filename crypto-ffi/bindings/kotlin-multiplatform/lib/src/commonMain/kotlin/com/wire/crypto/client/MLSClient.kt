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

typealias MLSGroupId = ByteArray
typealias ClientId = String
typealias Ed22519Key = ByteArray

typealias WelcomeMessage = ByteArray
typealias HandshakeMessage = ByteArray
typealias ApplicationMessage = ByteArray
typealias PlainMessage = ByteArray
typealias MLSKeyPackage = ByteArray
typealias Ciphersuite = UShort

enum class GroupInfoEncryptionType {
    PLAINTEXT,JWE_ENCRYPTED;
}

enum class RatchetTreeType {
    FULL,DELTA,BY_REF;
}

enum class CredentialType {
    BASIC,X509;
}

open class GroupInfoBundle(
    var encryptionType: GroupInfoEncryptionType,
    var ratchetTreeType: RatchetTreeType,
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
    suspend fun getPublicKey(ciphersuite: Ciphersuite): ByteArray

    suspend fun generateKeyPackages(ciphersuite: Ciphersuite, amount: Int): List<ByteArray>

    suspend fun validKeyPackageCount(ciphersuite: Ciphersuite): ULong

    suspend fun updateKeyingMaterial(groupId: MLSGroupId): CommitBundle

    suspend fun conversationExists(groupId: MLSGroupId): Boolean

    suspend fun conversationEpoch(groupId: MLSGroupId): ULong

    suspend fun joinConversation(groupId: MLSGroupId, epoch: ULong, ciphersuite: Ciphersuite, credentialType: CredentialType): HandshakeMessage
    suspend fun joinByExternalCommit(groupInfo: ByteArray, credentialType: CredentialType): CommitBundle

    suspend fun mergePendingGroupFromExternalCommit(groupId: MLSGroupId)

    suspend fun clearPendingGroupExternalCommit(groupId: MLSGroupId)

    suspend fun createConversation(
        groupId: MLSGroupId,
        creatorCredentialType: CredentialType,
        externalSenders: List<Ed22519Key> = emptyList()
    )

    suspend fun wipeConversation(groupId: MLSGroupId)

    suspend fun processWelcomeMessage(message: WelcomeMessage): MLSGroupId

    suspend fun encryptMessage(groupId: MLSGroupId, message: PlainMessage): ApplicationMessage

    suspend fun decryptMessage(groupId: MLSGroupId, message: ApplicationMessage): DecryptedMessageBundle

    suspend fun commitAccepted(groupId: MLSGroupId)

    suspend fun commitPendingProposals(groupId: MLSGroupId): CommitBundle?

    suspend fun clearPendingCommit(groupId: MLSGroupId)

    suspend fun members(groupId: MLSGroupId): List<ClientId>

    suspend fun addMember(
        groupId: MLSGroupId,
        members: List<Pair<ClientId, MLSKeyPackage>>
    ): CommitBundle?

    suspend fun removeMember(
        groupId: MLSGroupId,
        members: List<ClientId>
    ): CommitBundle

    suspend fun deriveSecret(groupId: MLSGroupId, keyLength: UInt): ByteArray
}
