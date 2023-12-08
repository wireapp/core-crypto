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

import com.wire.crypto.client.CoreCryptoCentral.Companion.DEFAULT_NB_KEY_PACKAGE
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

@Suppress("TooManyFunctions")
class MLSClient(private val cc: com.wire.crypto.CoreCrypto) {

    companion object {
        private val keyRotationDuration: Duration = 30.toDuration(DurationUnit.DAYS)
        private val defaultGroupConfiguration = com.wire.crypto.CustomConfiguration(
            java.time.Duration.ofDays(keyRotationDuration.inWholeDays),
            com.wire.crypto.MlsWirePolicy.PLAINTEXT
        )
    }

    /**
     * This is your entrypoint to initialize [com.wire.crypto.client.MLSClient] with a Basic Credential
     */
    suspend fun mlsInit(
        id: ClientId,
        ciphersuites: Ciphersuites = Ciphersuites.DEFAULT,
        nbKeyPackage: UInt? = DEFAULT_NB_KEY_PACKAGE
    ) {
        cc.mlsInit(id.lower(), ciphersuites.lower(), nbKeyPackage)
    }

    /**
     * Generates a MLS KeyPair/CredentialBundle with a temporary, random client ID.
     * This method is designed to be used in conjunction with [mlsInitWithClientId] and represents the first step in this process
     *
     * @param ciphersuites - All the ciphersuites supported by this MLS client
     * @return a list of random ClientId to use in [mlsInitWithClientId]
     */
    suspend fun mlsGenerateKeypairs(ciphersuites: Ciphersuites = Ciphersuites.DEFAULT): ExternallyGeneratedHandle {
        return cc.mlsGenerateKeypairs(ciphersuites.lower()).toExternallyGeneratedHandle()
    }

    /**
     * Updates the current temporary Client ID with the newly provided one. This is the second step in the externally-generated clients process.
     *
     * **Important:** This is designed to be called after [mlsGenerateKeypairs]
     *
     * @param clientId - The newly allocated Client ID from the MLS Authentication Service
     * @param tmpClientIds - The random clientId you obtained in [mlsGenerateKeypairs], for authentication purposes
     * @param ciphersuites - All the ciphersuites supported by this MLS client
     */
    suspend fun mlsInitWithClientId(
        clientId: ClientId,
        tmpClientIds: ExternallyGeneratedHandle,
        ciphersuites: Ciphersuites = Ciphersuites.DEFAULT
    ) {
        cc.mlsInitWithClientId(clientId.lower(), tmpClientIds.lower(), ciphersuites.lower())
    }

    /**
     * Get the client's public signature key. To upload to the DS for further backend side validation
     *
     * @param ciphersuite of the signature key to get
     * @return the client's public signature key
     */
    suspend fun getPublicKey(ciphersuite: Ciphersuite = Ciphersuite.DEFAULT): SignaturePublicKey {
        return cc.clientPublicKey(ciphersuite.lower()).toSignaturePublicKey()
    }

    /**
     * Generates the requested number of KeyPackages ON TOP of the existing ones e.g. if you already have created 100
     * KeyPackages (default value), requesting 10 will return the 10 oldest. Otherwise, if you request 200, 100 new will
     * be generated.
     * Unless explicitly deleted, KeyPackages are deleted upon [processWelcomeMessage]
     *
     * @param amount required amount
     * @param ciphersuite of the KeyPackage to create
     * @param credentialType of the KeyPackage to create
     */
    suspend fun generateKeyPackages(
        amount: UInt,
        ciphersuite: Ciphersuite = Ciphersuite.DEFAULT,
        credentialType: CredentialType = CredentialType.DEFAULT,
    ): List<MLSKeyPackage> {
        return cc.clientKeypackages(ciphersuite.lower(), credentialType.lower(), amount).map { it.toMLSKeyPackage() }
    }

    /**
     * Number of unexpired KeyPackages currently in store
     *
     * @param ciphersuite of the KeyPackage to count
     * @param credentialType of the KeyPackage to count
     */
    suspend fun validKeyPackageCount(
        ciphersuite: Ciphersuite = Ciphersuite.DEFAULT,
        credentialType: CredentialType = CredentialType.DEFAULT
    ): ULong {
        return cc.clientValidKeypackagesCount(ciphersuite.lower(), credentialType.lower())
    }

    /**
     * Prunes local KeyPackages after making sure they also have been deleted on the backend side.
     * You should only use this after [CoreCryptoCentral.e2eiRotateAll]
     *
     * @param refs KeyPackage references from the [RotateBundle]
     */
    suspend fun deleteKeyPackages(refs: List<MLSKeyPackageRef>) {
        // cannot be tested with the current API & helpers
        return cc.deleteKeypackages(refs.map { it.lower() })
    }

    /**
     * Checks if the Client is member of a given conversation and if the MLS Group is loaded up.
     *
     * @param id conversation identifier
     */
    suspend fun conversationExists(id: MLSGroupId): Boolean = cc.conversationExists(id.lower())

    /**
     * Returns the current epoch of a conversation
     *
     * @param id conversation identifier
     */
    suspend fun conversationEpoch(id: MLSGroupId): ULong = cc.conversationEpoch(id.lower())

    /**
     * Creates a new external Add proposal for self client to join a conversation.
     *
     * @param id conversation identifier
     * @param epoch conversation epoch
     * @param ciphersuite of the conversation to join
     * @param ciphersuite to join the conversation with
     */
    suspend fun joinConversation(
        id: MLSGroupId,
        epoch: ULong,
        ciphersuite: Ciphersuite = Ciphersuite.DEFAULT,
        credentialType: CredentialType = CredentialType.DEFAULT,
    ): MlsMessage {
        return cc.newExternalAddProposal(id.lower(), epoch, ciphersuite.lower(), credentialType.lower()).toMlsMessage()
    }

    /**
     * Allows to create an external commit to "apply" to join a group through its GroupInfo.
     *
     * If the DS accepts the external commit, you have to [mergePendingGroupFromExternalCommit] in order to get back
     * a functional MLS group. On the opposite, if it rejects it, you can either retry by just calling again
     * [joinByExternalCommit], no need to [clearPendingGroupFromExternalCommit]. If you want to abort the operation
     * (too many retries or the user decided to abort), you can use [clearPendingGroupFromExternalCommit] in order not
     * to bloat the user's storage but nothing bad can happen if you forget to except some storage space wasted.
     *
     * @param groupInfo a TLS encoded GroupInfo fetched from the Delivery Service
     * @param credentialType to join the group with
     */
    suspend fun joinByExternalCommit(
        groupInfo: GroupInfo,
        credentialType: CredentialType = CredentialType.DEFAULT,
        configuration: com.wire.crypto.CustomConfiguration = defaultGroupConfiguration,
    ): CommitBundle {
        // cannot be tested since the groupInfo required is not wrapped in a MlsMessage whereas the one returned
        // in Commit Bundles is... because that's the API the backend imposed
        return cc.joinByExternalCommit(groupInfo.lower(), configuration, credentialType.lower()).lift()
    }

    /**
     * This merges the commit generated by [joinByExternalCommit], persists the group permanently
     * and deletes the temporary one. This step makes the group operational and ready to encrypt/decrypt message.
     *
     * @param id conversation identifier
     * @return eventually decrypted buffered messages if any
     */
    suspend fun mergePendingGroupFromExternalCommit(id: MLSGroupId): List<BufferedDecryptedMessage>? {
        return cc.mergePendingGroupFromExternalCommit(id.lower())?.map { it.lift() }
    }

    /**
     * In case the external commit generated by [joinByExternalCommit] is rejected by the Delivery Service, and we
     * want to abort this external commit once for all, we can wipe out the pending group from the keystore in order
     * not to waste space.
     *
     * @param id conversation identifier
     */
    suspend fun clearPendingGroupFromExternalCommit(id: MLSGroupId) = cc.clearPendingGroupFromExternalCommit(id.lower())

    /**
     * Creates a new conversation with the current client being the sole member.
     * You will want to use [addMember] afterward to add clients to this conversation.
     *
     * @param id conversation identifier
     * @param ciphersuite of the conversation. A credential for the given ciphersuite must already have been created
     * @param creatorCredentialType kind of credential the creator wants to create the group with
     * @param externalSenders keys fetched from backend for validating external remove proposals
     * @param perDomainTrustAnchors 🚧 in progress. Leave empty for now
     */
    suspend fun createConversation(
        id: MLSGroupId,
        ciphersuite: Ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        creatorCredentialType: CredentialType = CredentialType.Basic,
        externalSenders: List<ExternalSenderKey> = emptyList(),
        perDomainTrustAnchors: List<com.wire.crypto.PerDomainTrustAnchor> = emptyList(),
    ) {
        val cfg = com.wire.crypto.ConversationConfiguration(
            ciphersuite.lower(),
            externalSenders.map { it.lower() },
            defaultGroupConfiguration,
            perDomainTrustAnchors
        )

        cc.createConversation(id.lower(), creatorCredentialType.lower(), cfg)
    }

    /**
     * Wipes and destroys the local storage of a given conversation / MLS group.
     *
     * @param id conversation identifier
     */
    suspend fun wipeConversation(id: MLSGroupId) = cc.wipeConversation(id.lower())

    /**
     * Ingest a TLS-serialized MLS welcome message to join an existing MLS group.
     *
     * Important: you have to catch the error `OrphanWelcome`, ignore it and then try to join this group with an external commit.
     *
     * @param welcome - TLS-serialized MLS Welcome message
     * @param configuration - configuration of the MLS group
     * @return The conversation ID of the newly joined group. You can use the same ID to decrypt/encrypt messages
     */
    suspend fun processWelcomeMessage(
        welcome: Welcome,
        configuration: com.wire.crypto.CustomConfiguration = defaultGroupConfiguration
    ): MLSGroupId {
        return cc.processWelcomeMessage(welcome.lower(), configuration).toGroupId()
    }

    /**
     * Encrypts a message for a given conversation.
     *
     * @param id conversation identifier
     * @param message - The plaintext message to encrypt
     * @return the encrypted payload for the given group. This needs to be fanned out to the other members of the group.
     */
    suspend fun encryptMessage(id: MLSGroupId, message: PlaintextMessage): MlsMessage {
        return cc.encryptMessage(id.lower(), message.lower()).toMlsMessage()
    }

    /**
     * Creates a Commit with a GroupContextExtension Proposal for updating the TrustAnchors of the group
     *
     * 🚧 Work in progress
     *
     * @param id conversation identifier
     * @param removeDomainNames domains to remove, can intersect [addTrustAnchors]]
     * @param addTrustAnchors new Anchors to add
     */
    suspend fun updateTrustAnchorsFromConversation(
        id: MLSGroupId,
        removeDomainNames: List<String>,
        addTrustAnchors: List<com.wire.crypto.PerDomainTrustAnchor>,
    ): CommitBundle {
        return cc.updateTrustAnchorsFromConversation(id.lower(), removeDomainNames, addTrustAnchors).lift()
    }

    /**
     * Decrypts a message for a given conversation
     *
     * @param id conversation identifier
     * @param message [MlsMessage] (either Application or Handshake message) from the DS
     */
    suspend fun decryptMessage(id: MLSGroupId, message: MlsMessage): DecryptedMessage {
        return cc.decryptMessage(id.lower(), message.lower()).lift()
    }

    /**
     * Adds new clients to a conversation, assuming the current client has the right to add new clients to the conversation.
     *
     * **CAUTION**: [commitAccepted] **HAS TO** be called afterward **ONLY IF** the Delivery Service responds'200 OK' to the [CommitBundle] upload.
     * It will "merge" the commit locally i.e. increment the local group epoch, use new encryption secrets etc...
     *
     * @param id conversation identifier
     * @param KeyPackages of the new clients to add
     * @return a [CommitBundle] to upload to the backend and if it succeeds call [commitAccepted]
     */
    suspend fun addMember(id: MLSGroupId, keyPackages: List<MLSKeyPackage>): CommitBundle {
        return cc.addClientsToConversation(id.lower(), keyPackages.map { it.lower() }).lift()
    }

    /**
     * Removes the provided clients from a conversation; Assuming those clients exist and the current client is allowed
     * to do so, otherwise this operation does nothing.
     *
     * **CAUTION**: [commitAccepted] **HAS TO** be called afterward **ONLY IF** the Delivery Service responds'200 OK' to the [CommitBundle] upload.
     * It will "merge" the commit locally i.e. increment the local group epoch, use new encryption secrets etc...
     *
     * @param id conversation identifier
     * @param members client identifier to delete
     * @return a [CommitBundle] to upload to the backend and if it succeeds call [commitAccepted]
     */
    suspend fun removeMember(id: MLSGroupId, members: List<ClientId>): CommitBundle {
        val clientIds = members.map { it.lower() }
        return cc.removeClientsFromConversation(id.lower(), clientIds).lift()
    }

    /**
     * Creates an update commit which forces every client to update their LeafNode in the conversation.
     *
     * **CAUTION**: [commitAccepted] **HAS TO** be called afterward **ONLY IF** the Delivery Service responds'200 OK' to the [CommitBundle] upload.
     * It will "merge" the commit locally i.e. increment the local group epoch, use new encryption secrets etc...
     *
     * @param id conversation identifier
     * @return a [CommitBundle] to upload to the backend and if it succeeds call [commitAccepted]
     */
    suspend fun updateKeyingMaterial(id: MLSGroupId) = cc.updateKeyingMaterial(id.lower()).lift()

    /**
     * Commits the local pending proposals and returns the {@link CommitBundle} object containing what can result from this operation.
     *
     * *CAUTION**: [commitAccepted] **HAS TO** be called afterward **ONLY IF** the Delivery Service responds'200 OK' to the [CommitBundle] upload.
     * It will "merge" the commit locally i.e. increment the local group epoch, use new encryption secrets etc...
     *
     * @param id conversation identifier
     * @return a [CommitBundle] to upload to the backend and if it succeeds call [commitAccepted]
     */
    suspend fun commitPendingProposals(id: MLSGroupId): CommitBundle? {
        return cc.commitPendingProposals(id.lower())?.lift()
    }

    /**
     * Creates a new proposal for adding a client to the MLS group
     *
     * @param id conversation identifier
     * @param keyPackage (TLS serialized) fetched from the DS
     * @return a [ProposalBundle] which allows to roll back this proposal with [clearPendingProposal] in case the DS rejects it
     */
    suspend fun newAddProposal(id: MLSGroupId, keyPackage: MLSKeyPackage): ProposalBundle {
        return cc.newAddProposal(id.lower(), keyPackage.lower()).lift()
    }

    /**
     * Creates a new proposal for removing a client from the MLS group
     *
     * @param id conversation identifier
     * @param clientId of the client to remove
     * @return a [ProposalBundle] which allows to roll back this proposal with [clearPendingProposal] in case the DS rejects it
     */
    suspend fun newRemoveProposal(id: MLSGroupId, clientId: ClientId): ProposalBundle {
        return cc.newRemoveProposal(id.lower(), clientId.lower()).lift()
    }

    /**
     * Creates a new proposal to update the current client LeafNode key material within the MLS group
     *
     * @param id conversation identifier
     * @return a [ProposalBundle] which allows to roll back this proposal with [clearPendingProposal] in case the DS rejects it
     */
    suspend fun newUpdateProposal(id: MLSGroupId): ProposalBundle {
        return cc.newUpdateProposal(id.lower()).lift()
    }

    /**
     * Allows to mark the latest commit produced as "accepted" and be able to safely merge it into the local group state
     *
     * @param id conversation identifier
     */
    suspend fun commitAccepted(id: MLSGroupId): List<BufferedDecryptedMessage>? {
        return cc.commitAccepted(id.lower())?.map { it.lift() }
    }

    /**
     * Allows to remove a pending proposal (rollback). Use this when backend rejects the proposal you just sent e.g. if permissions have changed meanwhile.
     *
     * **CAUTION**: only use this when you had an explicit response from the Delivery Service
     * e.g. 403 or 409. Do not use otherwise e.g. 5xx responses, timeout etc…
     *
     * @param id conversation identifier
     * @param proposalRef you get from a [ProposalBundle]
     */
    suspend fun clearPendingProposal(id: MLSGroupId, proposalRef: ProposalRef) {
        cc.clearPendingProposal(id.lower(), proposalRef.lower())
    }

    /**
     * Allows to remove a pending commit (rollback). Use this when backend rejects the commit you just sent e.g. if permissions have changed meanwhile.
     *
     * **CAUTION**: only use this when you had an explicit response from the Delivery Service
     * e.g. 403. Do not use otherwise e.g. 5xx responses, timeout etc...
     * **DO NOT** use when Delivery Service responds 409, pending state will be renewed in [decryptMessage]
     *
     * @param id conversation identifier
     */
    suspend fun clearPendingCommit(id: MLSGroupId) {
        cc.clearPendingCommit(id.lower())
    }

    /**
     * Returns all clients from group's members
     *
     * @param id conversation identifier
     * @return All the clients from the members of the group
     */
    suspend fun members(id: MLSGroupId): List<ClientId> {
        return cc.getClientIds(id.lower()).map { it.toClientId() }
    }

    /**
     * Derives a new key from the group to use with AVS
     *
     * @param id conversation identifier
     * @param keyLength the length of the key to be derived. If the value is higher than the bounds of `u16` or the context hash * 255, an error will be returned
     */
    suspend fun deriveAvsSecret(id: MLSGroupId, keyLength: UInt): AvsSecret {
        return cc.exportSecretKey(id.lower(), keyLength).toAvsSecret()
    }

    /**
     * Indicates when to mark a conversation as not verified i.e. when not all its members have a X509.
     * Credential generated by Wire's end-to-end identity enrollment
     *
     * @param id conversation identifier
     * @return the conversation state given current members
     */
    suspend fun e2eiConversationState(id: MLSGroupId): com.wire.crypto.E2eiConversationState {
        return cc.e2eiConversationState(id.lower())
    }

    /**
     * Returns true when end-to-end-identity is enabled for the given Ciphersuite
     *
     * @param ciphersuite of the credential to check
     * @returns true if end-to-end identity is enabled for the given ciphersuite
     */
    suspend fun e2eiIsEnabled(ciphersuite: Ciphersuite = Ciphersuite.DEFAULT): Boolean {
        return cc.e2eiIsEnabled(ciphersuite.lower())
    }

    /**
     * From a given conversation, get the identity of the members supplied. Identity is only present for members with a
     * Certificate Credential (after turning on end-to-end identity).
     *
     * @param id conversation identifier
     * @param deviceIds identifiers of the devices
     * @returns identities or if no member has a x509 certificate, it will return an empty List
     */
    suspend fun getDeviceIdentities(id: MLSGroupId, deviceIds: List<ClientId>): List<WireIdentity> {
        return cc.getDeviceIdentities(id.lower(), deviceIds.map { it.lower() }).map { it.lift() }
    }

    /**
     * From a given conversation, get the identity of the users (device holders) supplied.
     * Identity is only present for devices with a Certificate Credential (after turning on end-to-end identity).
     * If no member has a x509 certificate, it will return an empty Vec.
     *
     * @param id conversation identifier
     * @param userIds user identifiers hyphenated UUIDv4 e.g. 'bd4c7053-1c5a-4020-9559-cd7bf7961954'
     * @returns a Map with all the identities for a given users. Consumers are then recommended to reduce those identities to determine the actual status of a user.
     */
    suspend fun getUserIdentities(id: MLSGroupId, userIds: List<String>): Map<String, List<WireIdentity>> {
        return cc.getUserIdentities(id.lower(), userIds).mapValues { (_, v) -> v.map { it.lift() } }
    }

    /**
     * Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei
     * turned on or not before joining it.
     *
     * @param groupInfo a TLS encoded GroupInfo fetched from the Delivery Service
     * @param credentialType kind of Credential to check usage of. Defaults to X509 for now as no other value will give any result.
     */
    suspend fun getCredentialInUse(groupInfo: GroupInfo, credentialType: CredentialType = CredentialType.X509): com.wire.crypto.E2eiConversationState {
        return cc.getCredentialInUse(groupInfo.lower(), credentialType.lower())
    }
}
