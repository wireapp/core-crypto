package com.wire.crypto

import com.wire.crypto.CoreCrypto.Companion.DEFAULT_NB_KEY_PACKAGE
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

/** The CoreCrypto context used within a transaction */
@Suppress("TooManyFunctions")
class CoreCryptoContext(private val cc: com.wire.crypto.uniffi.CoreCryptoContext) {
    internal fun lower() = cc

    companion object {
        private val keyRotationDuration: Duration = 30.toDuration(DurationUnit.DAYS)
        private val defaultGroupConfiguration = CustomConfiguration(
            java.time.Duration.ofDays(keyRotationDuration.inWholeDays),
            MlsWirePolicy.PLAINTEXT
        )
    }

    /**
     * Set arbitrary data to be retrieved by [getData]. This is meant to be used as a check point at
     * the end of a transaction. The data should be limited to a reasonable size.
     */
    suspend fun setData(data: ByteArray) {
        wrapException { cc.setData(data) }
    }

    /**
     * Get the data that has previously been set by [setData], or null if no data has been set. This
     * is meant to be used as a check point at the end of a transaction.
     */
    suspend fun getData(): ByteArray? {
        return wrapException { cc.getData() }
    }

    /**
     * This is your entrypoint to initialize [CoreCrypto] with a Basic Credential
     */
    suspend fun mlsInit(
        id: ClientId,
        ciphersuites: Ciphersuites = Ciphersuites.DEFAULT,
        nbKeyPackage: UInt? = DEFAULT_NB_KEY_PACKAGE,
    ) {
        wrapException { cc.mlsInit(id.lower(), ciphersuites.lower(), nbKeyPackage) }
    }

    /**
     * Get the client's public signature key. To upload to the DS for further backend side
     * validation
     *
     * @param ciphersuite of the signature key to get
     * @param credentialType the credential type
     * @return the client's public signature key
     */
    suspend fun getPublicKey(
        ciphersuite: Ciphersuite = Ciphersuite.DEFAULT,
        credentialType: CredentialType = CredentialType.DEFAULT,
    ): SignaturePublicKey {
        return wrapException {
            cc.clientPublicKey(ciphersuite.lower(), credentialType.lower()).toSignaturePublicKey()
        }
    }

    /**
     * Generates the requested number of KeyPackages ON TOP of the existing ones e.g. if you already
     * have created 100 KeyPackages (default value), requesting 10 will return the 10 oldest.
     * Otherwise, if you request 200, 100 new will be generated. Unless explicitly deleted,
     * KeyPackages are deleted upon [processWelcomeMessage]
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
        return wrapException {
            cc.clientKeypackages(ciphersuite.lower(), credentialType.lower(), amount).map {
                it.toMLSKeyPackage()
            }
        }
    }

    /**
     * Number of unexpired KeyPackages currently in store
     *
     * @param ciphersuite of the KeyPackage to count
     * @param credentialType of the KeyPackage to count
     */
    suspend fun validKeyPackageCount(
        ciphersuite: Ciphersuite = Ciphersuite.DEFAULT,
        credentialType: CredentialType = CredentialType.DEFAULT,
    ): ULong {
        return wrapException { cc.clientValidKeypackagesCount(ciphersuite.lower(), credentialType.lower()) }
    }

    /**
     * Checks if the Client is member of a given conversation and if the MLS Group is loaded up.
     *
     * @param id conversation identifier
     */
    suspend fun conversationExists(id: MLSGroupId): Boolean = wrapException { cc.conversationExists(id.lower()) }

    /**
     * Returns the current epoch of a conversation
     *
     * @param id conversation identifier
     */
    suspend fun conversationEpoch(id: MLSGroupId): ULong = wrapException { cc.conversationEpoch(id.lower()) }

    /**
     * "Apply" to join a group through its GroupInfo.
     *
     * Sends the corresponding commit via [MlsTransport.sendCommitBundle]
     * and creates the group if the call is successful.
     *
     * @param groupInfo a TLS encoded GroupInfo fetched from the Delivery Service
     * @param credentialType to join the group with
     * @param configuration configuration of the MLS group
     */
    suspend fun joinByExternalCommit(
        groupInfo: GroupInfo,
        credentialType: CredentialType = CredentialType.DEFAULT,
        configuration: CustomConfiguration = defaultGroupConfiguration,
    ): WelcomeBundle {
        // cannot be tested since the groupInfo required is not wrapped in a MlsMessage whereas the
        // one returned
        // in Commit Bundles is... because that's the API the backend imposed
        return wrapException { cc.joinByExternalCommit(groupInfo.lower(), configuration.lower(), credentialType.lower()).lift() }
    }

    /**
     * Enable history sharing by generating a history client and adding it to the conversation.
     *
     * @param id conversation identifier
     */
    suspend fun enableHistorySharing(id: MLSGroupId) = wrapException { cc.enableHistorySharing(id.lower()) }

    /**
     * Disable history sharing by removing history clients from the conversation.
     *
     * @param id conversation identifier
     */
    suspend fun disableHistorySharing(id: MLSGroupId) = wrapException { cc.disableHistorySharing(id.lower()) }

    /**
     * Creates a new conversation with the current client being the sole member. You will want to
     * use [addMember] afterward to add clients to this conversation.
     *
     * @param id conversation identifier
     * @param ciphersuite of the conversation. A credential for the given ciphersuite must already
     *   have been created
     * @param creatorCredentialType kind of credential the creator wants to create the group with
     * @param externalSenders keys fetched from backend for validating external remove proposals
     */
    suspend fun createConversation(
        id: MLSGroupId,
        ciphersuite: Ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        creatorCredentialType: CredentialType = CredentialType.Basic,
        externalSenders: List<ExternalSenderKey> = emptyList(),
    ) {
        val cfg = com.wire.crypto.uniffi.ConversationConfiguration(
            ciphersuite.lower(),
            externalSenders.map { it.lower() },
            defaultGroupConfiguration.lower(),
        )

        wrapException { cc.createConversation(id.lower(), creatorCredentialType.lower(), cfg) }
    }

    /**
     * Wipes and destroys the local storage of a given conversation / MLS group.
     *
     * @param id conversation identifier
     */
    suspend fun wipeConversation(id: MLSGroupId) = wrapException { cc.wipeConversation(id.lower()) }

    /**
     * Ingest a TLS-serialized MLS welcome message to join an existing MLS group.
     *
     * Important: you have to catch the error `OrphanWelcome`, ignore it and then try to join this
     * group with an external commit.
     *
     * @param welcome - TLS-serialized MLS Welcome message
     * @param configuration - configuration of the MLS group
     * @return The conversation ID of the newly joined group. You can use the same ID to
     *   decrypt/encrypt messages
     */
    suspend fun processWelcomeMessage(
        welcome: Welcome,
        configuration: CustomConfiguration = defaultGroupConfiguration,
    ): WelcomeBundle {
        return wrapException { cc.processWelcomeMessage(welcome.lower(), configuration.lower()).lift() }
    }

    /**
     * Encrypts a message for a given conversation.
     *
     * @param id conversation identifier
     * @param message - The plaintext message to encrypt
     * @return the encrypted payload for the given group. This needs to be fanned out to the other
     *   members of the group.
     */
    suspend fun encryptMessage(id: MLSGroupId, message: PlaintextMessage): MlsMessage {
        return wrapException { cc.encryptMessage(id.lower(), message.lower()).toMlsMessage() }
    }

    /**
     * Decrypts a message for a given conversation
     *
     * @param id conversation identifier
     * @param message [MlsMessage] (either Application or Handshake message) from the DS
     */
    suspend fun decryptMessage(id: MLSGroupId, message: MlsMessage): DecryptedMessage {
        return wrapException { cc.decryptMessage(id.lower(), message.lower()).lift() }
    }

    /**
     * Adds new clients to a conversation, assuming the current client has the right to add new
     * clients to the conversation.
     *
     * @param id conversation identifier
     * @param keyPackages of the new clients to add
     * @return the potentially newly discovered certificate revocation list distribution points
     */
    suspend fun addMember(id: MLSGroupId, keyPackages: List<MLSKeyPackage>): List<String>? {
        return wrapException { cc.addClientsToConversation(id.lower(), keyPackages.map { it.lower() }) }
    }

    /**
     * Removes the provided clients from a conversation; Assuming those clients exist and the
     * current client is allowed to do so, otherwise this operation does nothing.
     *
     * @param id conversation identifier
     * @param members client identifier to delete
     */
    suspend fun removeMember(id: MLSGroupId, members: List<ClientId>) {
        return wrapException {
            val clientIds = members.map { it.lower() }
            cc.removeClientsFromConversation(id.lower(), clientIds)
        }
    }

    /**
     * Creates an update commit which forces every client to update their LeafNode in the
     * conversation.
     *
     * @param id conversation identifier
     */
    suspend fun updateKeyingMaterial(id: MLSGroupId) = wrapException { cc.updateKeyingMaterial(id.lower()) }

    /**
     * Commits the local pending proposals.
     *
     * @param id conversation identifier
     */
    suspend fun commitPendingProposals(id: MLSGroupId) {
        return wrapException { cc.commitPendingProposals(id.lower()) }
    }

    /**
     * Returns all clients from group's members
     *
     * @param id conversation identifier
     * @return All the clients from the members of the group
     */
    suspend fun members(id: MLSGroupId): List<ClientId> {
        return wrapException { cc.getClientIds(id.lower()).map { it.toClientId() } }
    }

    /**
     * Derives a new key from the group to use with AVS
     *
     * @param id conversation identifier
     * @param keyLength the length of the key to be derived. If the value is higher than the bounds
     *   of `u16` or the context hash * 255, an error will be returned
     */
    suspend fun deriveAvsSecret(id: MLSGroupId, keyLength: UInt): AvsSecret {
        return wrapException { cc.exportSecretKey(id.lower(), keyLength).toAvsSecret() }
    }

    /**
     * Returns the raw public key of the single external sender present in this group. This should
     * be used to initialize a subconversation
     *
     * @param id conversation identifier
     */
    suspend fun getExternalSender(id: MLSGroupId): ExternalSenderKey {
        return wrapException { cc.getExternalSender(id.lower()).toExternalSenderKey() }
    }

    /**
     * Indicates when to mark a conversation as not verified i.e. when not all its members have a
     * X509. Credential generated by Wire's end-to-end identity enrollment
     *
     * @param id conversation identifier
     * @return the conversation state given current members
     */
    suspend fun e2eiConversationState(id: MLSGroupId): E2eiConversationState {
        return wrapException { cc.e2eiConversationState(id.lower()).lift() }
    }

    /**
     * Returns true when end-to-end-identity is enabled for the given Ciphersuite
     *
     * @param ciphersuite of the credential to check
     * @returns true if end-to-end identity is enabled for the given ciphersuite
     */
    suspend fun e2eiIsEnabled(ciphersuite: Ciphersuite = Ciphersuite.DEFAULT): Boolean {
        return wrapException { cc.e2eiIsEnabled(ciphersuite.lower()) }
    }

    /**
     * From a given conversation, get the identity of the members supplied. Identity is only present
     * for members with a Certificate Credential (after turning on end-to-end identity).
     *
     * @param id conversation identifier
     * @param deviceIds identifiers of the devices
     * @returns identities or if no member has a x509 certificate, it will return an empty List
     */
    suspend fun getDeviceIdentities(id: MLSGroupId, deviceIds: List<ClientId>): List<WireIdentity> {
        return wrapException { cc.getDeviceIdentities(id.lower(), deviceIds.map { it.lower() }).map { it.lift() } }
    }

    /**
     * From a given conversation, get the identity of the users (device holders) supplied. Identity
     * is only present for devices with a Certificate Credential (after turning on end-to-end
     * identity). If no member has a x509 certificate, it will return an empty Vec.
     *
     * @param id conversation identifier
     * @param userIds user identifiers hyphenated UUIDv4 e.g. 'bd4c7053-1c5a-4020-9559-cd7bf7961954'
     * @returns a Map with all the identities for a given users. Consumers are then recommended to
     *   reduce those identities to determine the actual status of a user.
     */
    suspend fun getUserIdentities(
        id: MLSGroupId,
        userIds: List<String>,
    ): Map<String, List<WireIdentity>> {
        return wrapException { cc.getUserIdentities(id.lower(), userIds).mapValues { (_, v) -> v.map { it.lift() } } }
    }

    /**
     * Creates an enrollment instance with private key material you can use in order to fetch a new
     * x509 certificate from the acme server.
     *
     * @param clientId client identifier e.g.
     *   `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M
     *   (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param expirySec generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiMlsInitOnly]
     */
    suspend fun e2eiNewEnrollment(
        clientId: String,
        displayName: String,
        handle: String,
        expirySec: UInt,
        ciphersuite: Ciphersuite,
        team: String? = null,
    ): E2EIEnrollment {
        return wrapException {
            E2EIEnrollment(
                cc.e2eiNewEnrollment(
                    clientId,
                    displayName,
                    handle,
                    team,
                    expirySec,
                    ciphersuite.lower(),
                )
            )
        }
    }

    /**
     * Generates an E2EI enrollment instance for a "regular" client (with a Basic credential)
     * willing to migrate to E2EI. Once the enrollment is finished, use the instance in
     * [e2eiRotateAll] to do the rotation.
     *
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M
     *   (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param expirySec generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiRotateAll]
     */
    suspend fun e2eiNewActivationEnrollment(
        displayName: String,
        handle: String,
        expirySec: UInt,
        ciphersuite: Ciphersuite,
        team: String? = null,
    ): E2EIEnrollment {
        return wrapException {
            E2EIEnrollment(
                cc.e2eiNewActivationEnrollment(
                    displayName,
                    handle,
                    team,
                    expirySec,
                    ciphersuite.lower(),
                )
            )
        }
    }

    /**
     * Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
     * having to change/rotate their credential, either because the former one is expired or it has
     * been revoked. It lets you change the DisplayName or the handle if you need to. Once the
     * enrollment is finished, use the instance in [e2eiRotateAll] to do the rotation.
     *
     * @param expirySec generated x509 certificate expiry
     * @param ciphersuite for generating signing key material
     * @param displayName human-readable name displayed in the application e.g. `Smith, Alice M
     *   (QA)`
     * @param handle user handle e.g. `alice.smith.qa@example.com`
     * @param team name of the Wire team a user belongs to
     * @return The new [E2EIEnrollment] enrollment to use with [e2eiRotateAll]
     */
    suspend fun e2eiNewRotateEnrollment(
        expirySec: UInt,
        ciphersuite: Ciphersuite,
        displayName: String? = null,
        handle: String? = null,
        team: String? = null,
    ): E2EIEnrollment {
        return wrapException {
            E2EIEnrollment(cc.e2eiNewRotateEnrollment(displayName, handle, team, expirySec, ciphersuite.lower()))
        }
    }

    /**
     * Use this method to initialize end-to-end identity when a client signs up and the grace period
     * is already expired ; that means he cannot initialize with a Basic credential
     *
     * @param enrollment the enrollment instance used to fetch the certificates
     * @param certificateChain the raw response from ACME server
     * @param nbKeyPackage number of initial KeyPackage to create when initializing the client
     * @return the [CrlDistributionPoints] if any
     */
    suspend fun e2eiMlsInitOnly(
        enrollment: E2EIEnrollment,
        certificateChain: String,
        nbKeyPackage: UInt? = DEFAULT_NB_KEY_PACKAGE,
    ): CrlDistributionPoints? {
        return wrapException {
            val crlsDps = cc.e2eiMlsInitOnly(enrollment.lower(), certificateChain, nbKeyPackage)
            crlsDps?.toCrlDistributionPoint()
        }
    }

    /** Returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs) */
    suspend fun e2eiIsPKIEnvSetup(): Boolean {
        return wrapException { cc.e2eiIsPkiEnvSetup() }
    }

    /**
     * Registers a Root Trust Anchor CA for the use in E2EI processing.
     *
     * Please note that without a Root Trust Anchor, all validations *will* fail; So this is the
     * first step to perform after initializing your E2EI client
     *
     * @param trustAnchorPEM - PEM certificate to anchor as a Trust Root
     */
    suspend fun e2eiRegisterAcmeCA(trustAnchorPEM: String) {
        return wrapException { cc.e2eiRegisterAcmeCa(trustAnchorPEM) }
    }

    /**
     * Registers an Intermediate CA for the use in E2EI processing.
     *
     * Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs; You **need**
     * to have a Root CA registered before calling this
     *
     * @param certPEM PEM certificate to register as an Intermediate CA
     */
    suspend fun e2eiRegisterIntermediateCA(certPEM: String): CrlDistributionPoints? {
        return wrapException { cc.e2eiRegisterIntermediateCa(certPEM)?.toCrlDistributionPoint() }
    }

    /**
     * Registers a CRL for the use in E2EI processing.
     *
     * Please note that a Root Trust Anchor CA is needed to validate CRLs; You **need** to have a
     * Root CA registered before calling this
     *
     * @param crlDP CRL Distribution Point; Basically the URL you fetched it from
     * @param crlDER DER representation of the CRL
     * @return A [CrlRegistration] with the dirty state of the new CRL (see struct) and its
     *   expiration timestamp
     */
    suspend fun e2eiRegisterCRL(crlDP: String, crlDER: ByteArray): CRLRegistration {
        return wrapException { cc.e2eiRegisterCrl(crlDP, crlDER).lift() }
    }

    /**
     * Replaces your leaf containing basic credentials with a leaf
     * node containing x509 credentials in the conversation.
     *
     * NOTE: you can only call this after you've completed the enrollment for an end-to-end identity, and saved the
     * resulting credential with [saveX509Credential].
     * Calling this without a valid end-to-end identity will result in an error.
     *
     * @param id conversation identifier
     */
    suspend fun e2eiRotate(id: MLSGroupId) = wrapException { cc.e2eiRotate(id.lower()) }

    /**
     * Saves a new X509 credential. Requires first
     * having enrolled a new X509 certificate with either [e2eiNewActivationEnrollment]
     * or [e2eiNewRotateEnrollment]
     *
     * # Expected actions to perform after this function (in this order)
     * 1. Rotate credentials for each conversation in [e2eiRotate]
     * 2. Generate new key packages with [generateKeyPackages]
     * 3. Use these to replace the stale ones the in the backend
     * 4. Delete the stale ones locally using [deleteStaleKeyPackages]
     *      * This is the last step because you might still need the old key packages to avoid
     *        an orphan welcome message
     *
     * @param enrollment - the enrollment instance used to fetch the certificates
     * @param certificateChain - the raw response from ACME server
     * @return Potentially a list of new certificate revocation list distribution points discovered in the certificate
     * chain
     */
    suspend fun saveX509Credential(
        enrollment: E2EIEnrollment,
        certificateChain: String,
    ): List<String>? {
        return wrapException {
            cc.saveX509Credential(enrollment.lower(), certificateChain)
        }
    }

    /**
     * Deletes all key packages whose credential does not match the most recently
     * saved x509 credential and the provided signature scheme.
     * @param cipherSuite the cipher suite with the signature scheme used for the credential
     */
    suspend fun deleteStaleKeyPackages(cipherSuite: Ciphersuite) {
        return wrapException {
            cc.deleteStaleKeyPackages(cipherSuite.lower())
        }
    }

    /**
     * Allows persisting an active enrollment (for example while redirecting the user during OAuth)
     * in order to resume it later with [e2eiEnrollmentStashPop]
     *
     * @param enrollment the enrollment instance to persist
     * @return a handle to fetch the enrollment later with [e2eiEnrollmentStashPop]
     */
    @kotlin.ExperimentalUnsignedTypes
    suspend fun e2eiEnrollmentStash(enrollment: E2EIEnrollment): EnrollmentHandle {
        return wrapException { cc.e2eiEnrollmentStash(enrollment.lower()).toUByteArray().asByteArray() }
    }

    /**
     * Fetches the persisted enrollment and deletes it from the keystore
     *
     * @param handle returned by [e2eiEnrollmentStash]
     * @returns the persisted enrollment instance
     */
    suspend fun e2eiEnrollmentStashPop(handle: EnrollmentHandle): E2EIEnrollment {
        return wrapException { E2EIEnrollment(cc.e2eiEnrollmentStashPop(handle)) }
    }

    // Proteus below

    /**
     * Initialise [CoreCrypto] to be used with proteus.
     *
     * All proteus related methods will fail until this function is called.
     */
    suspend fun proteusInit() {
        cc.proteusInit()
    }

    private fun toPreKey(id: UShort, data: ByteArray): PreKey = PreKey(id, data)

    /**
     * Proteus session local fingerprint
     *
     * @return Hex-encoded public key string
     */
    suspend fun proteusGetLocalFingerprint(): ByteArray {
        return wrapException { cc.proteusFingerprint().toByteArray() }
    }

    /**
     * Proteus session remote fingerprint
     *
     * @param sessionId - ID of the Proteus session
     * @return Hex-encoded public key string
     */
    suspend fun proteusGetRemoteFingerprint(sessionId: SessionId): ByteArray {
        return wrapException { cc.proteusFingerprintRemote(sessionId).toByteArray() }
    }

    /**
     * Proteus public key fingerprint
     * It's basically the public key encoded as an hex string
     *
     * @return Hex-encoded public key string
     */
    suspend fun proteusGetPrekeyFingerprint(prekey: ByteArray): ByteArray {
        return wrapException { cc.proteusFingerprintPrekeybundle(prekey).toByteArray() }
    }

    /**
     * Creates a number of prekeys starting from the `from` index
     *
     * @param from - starting index
     * @param count - number of prekeys to generate
     * @return: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
     */
    suspend fun proteusNewPreKeys(from: Int, count: Int): ArrayList<PreKey> {
        return wrapException {
            from.until(from + count).map {
                toPreKey(it.toUShort(), cc.proteusNewPrekey(it.toUShort()))
            } as ArrayList<PreKey>
        }
    }

    /**
     * Create a new last resort prekey
     *
     * @return A CBOR-serialize version of the PreKeyBundle associated with the last resort PreKey (holding the last resort prekey id)
     */
    suspend fun proteusNewLastPreKey(): PreKey {
        return wrapException {
            toPreKey(cc.proteusLastResortPrekeyId(), cc.proteusLastResortPrekey())
        }
    }

    /**
     * Checks if a session exists
     *
     * @param sessionId - ID of the Proteus session
     * @return whether the session exists or not
     */
    suspend fun proteusDoesSessionExist(sessionId: SessionId): Boolean {
        return wrapException { cc.proteusSessionExists(sessionId) }
    }

    /**
     * Create a session using a prekey
     *
     * @param preKeyCrypto - CBOR-encoded Proteus prekey of the other client
     * @param sessionId - ID of the Proteus session
     */
    suspend fun proteusCreateSession(preKeyCrypto: PreKey, sessionId: SessionId) {
        wrapException { cc.proteusSessionFromPrekey(sessionId, preKeyCrypto.data) }
    }

    /**
     * Deletes a session
     * Note: this also deletes the persisted data within the keystore
     *
     * @param sessionId - ID of the Proteus session
     */
    suspend fun proteusDeleteSession(sessionId: SessionId) {
        wrapException { cc.proteusSessionDelete(sessionId) }
    }

    /**
     * Decrypt an incoming message for an existing session
     *
     * @param message - CBOR encoded, encrypted proteus message
     * @param sessionId - ID of the Proteus session
     * @return The decrypted payload contained within the message
     */
    suspend fun proteusDecrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        val sessionExists = proteusDoesSessionExist(sessionId)

        return wrapException {
            if (sessionExists) {
                val decryptedMessage = cc.proteusDecrypt(sessionId, message)
                cc.proteusSessionSave(sessionId)
                decryptedMessage
            } else {
                val decryptedMessage = cc.proteusSessionFromMessage(sessionId, message)
                cc.proteusSessionSave(sessionId)
                decryptedMessage
            }
        }
    }

    /**
     * Encrypt a message for a given session
     *
     * @param message - payload to encrypt
     * @param sessionId - ID of the Proteus session
     * @returns The CBOR-serialized encrypted message
     */
    suspend fun proteusEncrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        return wrapException { cc.proteusEncrypt(sessionId, message) }
    }

    /**
     * Batch encryption for proteus messages
     * This is used to minimize FFI roundtrips when used in the context of a multi-client session (i.e. conversation)
     *
     * @param sessionIds - List of Proteus session IDs to encrypt the message for
     * @param message - payload to encrypt
     * @return A map indexed by each session ID and the corresponding CBOR-serialized encrypted message for this session
     */
    suspend fun proteusEncryptBatched(
        sessionIds: List<SessionId>,
        message: ByteArray,
    ): Map<SessionId, ByteArray> {
        return wrapException {
            cc.proteusEncryptBatched(sessionIds.map { it }, message).mapNotNull { entry ->
                entry.key to entry.value
            }
        }
            .toMap()
    }

    /** Create a session and encrypt a message.
     *
     * @param message the message
     * @param preKey the prekey
     * @param sessionId the session ID to be used
     * @return The CBOR-serialized encrypted message
     */
    suspend fun proteusEncryptWithPreKey(
        message: ByteArray,
        preKey: PreKey,
        sessionId: SessionId,
    ): ByteArray {
        return wrapException {
            cc.proteusSessionFromPrekey(sessionId, preKey.data)
            val encryptedMessage = cc.proteusEncrypt(sessionId, message)
            cc.proteusSessionSave(sessionId)
            encryptedMessage
        }
    }

    /**
     * Import all the data stored by Cryptobox, located at [path], into the CoreCrypto keystore
     */
    suspend fun proteusCryptoboxMigrate(path: String) {
        return wrapException {
            cc.proteusCryptoboxMigrate(path)
        }
    }
}
