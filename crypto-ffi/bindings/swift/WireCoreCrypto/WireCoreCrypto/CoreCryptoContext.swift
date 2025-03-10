//
// Wire
// Copyright (C) 2025 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
//

internal import WireCoreCryptoUniffi

public protocol CoreCryptoContext {

    // MARK: Initialisation

    /// This is your entrypoint to initialize CoreCrypto with a Basic Credential
    ///
    func mlsInit(clientId: ClientId, ciphersuites: Ciphersuites, nbKeyPackage: UInt32?) async throws

    /// Updates the current temporary Client ID with the newly provided one. This is the second step
    /// in the externally-generated clients process.
    ///
    /// **Important:** This is designed to be called after ``mlsGenerateKeypairs(ciphersuites:)-7unis``
    ///
    /// - Parameters:
    ///      - clientId:  The newly allocated Client ID from the MLS Authentication Service
    ///      - tmpClientIds: The random clientId you obtained in [mlsGenerateKeypairs], for
    ///   authentication purposes
    ///      - ciphersuites: All the ciphersuites supported by this MLS client
    ///
    func mlsInitWithClientId(
        clientId: ClientId, tmpClientIds: [ClientId], ciphersuites: Ciphersuites)
        async throws

    /// Generates a MLS KeyPair/CredentialBundle with a temporary, random client ID. This method is
    /// designed to be used in conjunction with [mlsInitWithClientId] and represents the first step
    /// in this process
    ///
    /// - Parameter ciphersuites: All the ciphersuites supported by this MLS client
    ///
    /// - Returns: a list of random ClientId to use in ///`mlsInitWithClientId(clientId:tmpClientIds:ciphersuites:)-xgq1``
    ///
    func mlsGenerateKeypairs(ciphersuites: Ciphersuites) async throws -> [ClientId]

    /// Get the client's public signature key. To upload to the DS for further backend side
    /// validation
    ///
    /// - Parameter ciphersuite: Ciphersuite of the signature key to get
    /// - Returns: The client's public key signature
    ///
    func getPublicKey(ciphersuite: Ciphersuite, credentialType: MlsCredentialType) async throws
        -> Data

    // MARK:

    ///
    /// Set arbitrary data to be retrieved by ``getData()-2eoep``. This is meant to be used as a check point at
    /// the end of a transaction. The data should be limited to a reasonable size.
    ///
    func setData(_ data: Data) async throws

    ///
    /// Get the data that has previously been set by ``setData(_:)``, or null if no data has been set. This
    /// is meant to be used as a check point at the end of a transaction.
    ///
    func getData() async throws -> Data?

    // MARK: Conversation operations

    /// Adds new clients to a conversation, assuming the current client has the right to add new
    /// clients to the conversation.
    ///
    /// - Parameters:
    ///      - conversationId: conversation identifier
    ///      - keyPackages: of the new clients to add
    ///
    /// - Returns: the potentially newly discovered certificate revocation list distribution points
    ///
    func addClients(conversationId: ConversationId, keyPackages: [Data]) async throws
        -> NewCrlDistributionPoints

    /// Removes the provided clients from a conversation; Assuming those clients exist and the
    /// current client is allowed to do so, otherwise this operation does nothing.
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Parameter clientIds: clients to remove
    ///
    func removeClients(conversationId: ConversationId, clientsIds: [ClientId]) async throws

    /// Return all clients which are members of the conversation
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Returns:  All clients which are members of the conversation
    ///
    func getClientIds(conversationId: ConversationId) async throws -> [ClientId]

    /// Commits the local pending proposals.
    ///
    /// - Parameter conversationId: conversation identifier
    ///
    func commitPendingProposals(conversationId: ConversationId) async throws

    /// Creates an update commit which forces every client to update their LeafNode in the
    /// conversation.
    ///
    /// - Parameter conversationId: conversation identifier
    ///
    func updateKeyingMaterial(conversationId: Data) async throws

    /// "Apply" to join a group through its GroupInfo.
    ///
    /// Sends the corresponding commit via ``MlsTransport-wrca/sendCommitBundle(commitBundle:)-2nbml``
    /// and creates the group if the call is successful.
    ///
    /// - Parameter groupInfo: TLS encoded GroupInfo fetched from the delivery service
    /// - Parameter credentialType: credentialType to join the group with
    /// - Parameter configuration: configuration of the MLS group
    ///
    func joinByExternalCommit(
        groupInfo: Data, customConfiguration: CustomConfiguration, credentialType: MlsCredentialType
    ) async throws -> WelcomeBundle

    /// Ingest a TLS-serialized MLS welcome message to join an existing MLS group.
    ///
    /// Important: you have to catch the error `OrphanWelcome`, ignore it and then try to join this
    /// group with an external commit.
    ///
    /// - Parameter welcome: TLS encoded MLS welcome message
    /// - Parameter configuration: configuration of the MLS group
    /// - Returns: Conversation ID of the newly joined group. You can use the same ID to
    ///   decrypt/encrypt messages
    ///
    func processWelcomeMessage(_ welcomeMessage: Data, customConfiguration: CustomConfiguration)
        async throws -> WelcomeBundle

    ///  Returns the raw public key of the single external sender present in this group. This should
    ///  be used to initialize a subconversation
    ///
    ///  - Parameter conversationId: conversation identifier
    ///  - Returns: External sender key
    ///
    func getExternalSender(conversationId: ConversationId) async throws -> Data

    /// Return ciphersuite used in conversation
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Returns: Ciphersuite used in conversation
    ///
    func ciphersuite(conversationId: ConversationId) async throws -> Ciphersuite

    /// Return current epoch in conversation
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Returns: current epoch in conversation
    ///
    func epoch(conversationId: ConversationId) async throws -> UInt64

    /// Checks if a conversation exists locally or not
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Returns: **True** if the converstion exists locally
    ///
    func conversationExists(conversationId: Data) async throws -> Bool

    /// Creates a new conversation with the current client being the sole member. You will want to
    /// use ``addClients(conversationId:keyPackages:)`` afterwards to add clients to this conversation.
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Parameter configuration: configuration of conversation, ciphersuite etc.
    ///
    func createConversation(
        conversationId: ConversationId,
        creatorCredentialType: MlsCredentialType,
        configuration: ConversationConfiguration) async throws

    /// Encrypts a message for a given conversation.
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Parameter message: The plaintext message to encrypt
    /// - Returns: Encrypted payload for the given group. This needs to be fanned out to the other
    ///   members of the group.
    ///
    func encryptMessage(conversationId: ConversationId, message: Data) async throws -> Data

    /// Decrypts a message for a given conversation
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Parameter payload: Either Application or Handshake message from the DS
    ///
    /// - Returns: Decrypted message
    ///
    func decryptMessage(conversationId: ConversationId, payload: Data) async throws
        -> DecryptedMessage

    /// Wipes and destroys the local storage of a given conversation / MLS group.
    ///
    /// - Parameter conversationId: conversation identifier
    ///
    func wipeConversation(conversationId: Data) async throws

    /// Derives a new key from the group to use encrypting audio / video streams
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Parameter keyLength: the length of the key to be derived. If the value is higher than the bounds
    ///   of `u16` or the context hash * 255, an error will be returned
    ///
    /// - Returns: Secret key
    ///
    func exportSecretKey(conversationId: ConversationId, keyLength: UInt32) async throws -> Data

    // MARK: Key packages

    /// Generates the requested number of KeyPackages ON TOP of the existing ones e.g. if you already
    /// have created 100 KeyPackages (default value), requesting 10 will return the 10 oldest.
    /// Otherwise, if you request 200, 100 new will be generated. Unless explicitly deleted,
    /// KeyPackages are deleted when processing welcome messages using  ``processWelcomeMessage(_:customConfiguration:)``
    ///
    /// - Parameter ciphersuite: ciphersuite for generated key packages
    /// - Parameter credentialType: credential type for generated key packages
    /// - Parameter amountRequested: requested amount of key packages
    /// - Returns:List of generated key packages
    ///
    func generateKeyPackages(
        ciphersuite: Ciphersuite, credentialType: MlsCredentialType, amountRequested: UInt32
    ) async throws -> [KeyPackage]

    /// Prunes local KeyPackages after making sure they also have been deleted on the backend side.
    /// You should only use this after calling ``e2eiRotate(conversationId:)-17p0q`` on all conversations.
    ///
    func deleteKeyPackages(refs: [Data]) async throws

    /// Deletes all key packages whose credential does not match the most recently
    /// saved x509 credential and the provided signature scheme.
    ///
    /// - Parameter ciphersuite: the cipher suite with the signature scheme used for the credential
    ///
    func deleteStaleKeyPackages(ciphersuite: Ciphersuite) async throws

    /// Number of unexpired KeyPackages currently in store
    ///
    /// - Parameter ciphersuite: Ciphersuite of the key packages to count
    /// - Parameter credentialType: Credential type of the key packages to count
    ///
    func validKeyPackageCount(ciphersuite: Ciphersuite, credentialType: MlsCredentialType)
        async throws -> UInt64

    // MARK: End-to-end identity

    /// Indicates when to mark a conversation as not verified i.e. when not all its members have a
    /// X509. Credential generated by Wire's end-to-end identity enrollment
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Returns: the conversation state given current members
    ///
    func e2eiConversationState(conversationId: ConversationId) async throws -> E2eiConversationState

    /// Dumps the PKI environment as PEM
    ///
    /// - Returns: a struct with different fields representing the PKI environment as PEM strings
    ///
    func e2eiDumpPkiEnv() async throws -> E2eiDumpedPkiEnv?

    /// Returns true when end-to-end-identity is enabled for the given Ciphersuite
    ///
    /// - Parameter ciphersuite: ciphersuite of the credential to check
    /// - Returns: **True** if end-to-end identity is enabled for the given ciphersuite
    ///
    func e2eiIsEnabled(ciphersuite: Ciphersuite) async throws -> Bool

    /// Whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs)
    ///
    func e2eiIsPkiEnvSetup() async throws -> Bool

    /// Use this method to initialize end-to-end identity when a client signs up and the grace period
    /// is already expired ; that means he cannot initialize with a Basic credential
    ///
    /// - Parameter enrollment: the enrollment instance used to fetch the certificates
    /// - Parameter certificateChain: the raw response from ACME server
    /// - Parameter nbKeyPackage: number of initial KeyPackage to create when initializing the client
    /// - Returns: the ``NewCrlDistributionPoints-9i2ao`` if any
    ///
    func e2eiMlsInitOnly(
        enrollment: E2eiEnrollment, certificateChain: String, nbKeyPackage: UInt32?
    )
        async throws -> NewCrlDistributionPoints

    /// Generates an E2EI enrollment instance for a "regular" client (with a Basic credential)
    /// willing to migrate to E2EI. Once the enrollment is finished, use the instance in
    /// ``e2eiRotate(conversationId:)-17p0q`` to do the rotation.
    ///
    /// - Parameter displayName: human-readable name displayed in the application e.g. `Smith, Alice M
    ///   (QA)`
    /// - Parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - Parameter expirySec: generated x509 certificate expiry
    /// - Parameter ciphersuite: for generating signing key material
    /// - Parameter team: name of the Wire team a user belongs to
    /// - Returns: The new ``E2eiEnrollment-swift.class`` enrollment to use with ``e2eiRotate(conversationId:)-17p0q``
    ///
    func e2eiNewActivationEnrollment(
        displayName: String, handle: String, team: String?, expirySec: UInt32,
        ciphersuite: Ciphersuite
    ) async throws -> E2eiEnrollment

    /// Creates an enrollment instance with private key material you can use in order to fetch a new
    /// x509 certificate from the acme server.
    ///
    /// - Parameter clientId: client identifier e.g.
    ///   `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
    /// - Parameter displayName: human-readable name displayed in the application e.g. `Smith, Alice M
    ///   (QA)`
    /// - Parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - Parameter expirySec: generated x509 certificate expiry
    /// - Parameter ciphersuite: for generating signing key material
    /// - Parameter team: name of the Wire team a user belongs to
    /// - Returns: The new ``E2eiEnrollment-swift.class`` enrollment to use with ``e2eiMlsInitOnly(enrollment:certificateChain:nbKeyPackage:)-1wrig``
    ///
    func e2eiNewEnrollment(
        clientId: String, displayName: String, handle: String, team: String?, expirySec: UInt32,
        ciphersuite: Ciphersuite
    ) async throws -> E2eiEnrollment

    /// Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
    /// having to change/rotate their credential, either because the former one is expired or it has
    /// been revoked. It lets you change the DisplayName or the handle if you need to. Once the
    /// enrollment is finished, use the instance in ``e2eiRotate(conversationId:)-17p0q`` to do the rotation.
    ///
    /// - Parameter expirySec: generated x509 certificate expiry
    /// - Parameter ciphersuite: for generating signing key material
    /// - Parameter displayName: human-readable name displayed in the application e.g. `Smith, Alice M
    ///   (QA)`
    /// - Parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - Parameter team: name of the Wire team a user belongs to
    /// - Returns: The new ``E2eiEnrollment-swift.class`` enrollment to use with ``e2eiRotate(conversationId:)-17p0q``
    ///
    func e2eiNewRotateEnrollment(
        displayName: String?, handle: String?, team: String?, expirySec: UInt32,
        ciphersuite: Ciphersuite
    ) async throws -> E2eiEnrollment

    /// Registers a Root Trust Anchor CA for the use in E2EI processing.
    ///
    /// Please note that without a Root Trust Anchor, all validations *will* fail; So this is the
    /// first step to perform after initializing your E2EI client
    ///
    /// - Parameter trustAnchorPEM: PEM certificate to anchor as a Trust Root
    ///
    func e2eiRegisterAcmeCa(trustAnchorPem: String) async throws

    /// Registers a CRL for the use in E2EI processing.
    ///
    /// Please note that a Root Trust Anchor CA is needed to validate CRLs; You **need** to have a
    /// Root CA registered before calling this
    ///
    /// - Parameter crlDP: CRL Distribution Point; Basically the URL you fetched it from
    /// - Parameter crlDER: DER representation of the CRL
    /// - Returns: A ``CrlRegistration-5y3za`` with the dirty state of the new CRL (see struct) and its
    ///   expiration timestamp
    ///
    func e2eiRegisterCrl(crlDp: String, crlDer: Data) async throws -> CrlRegistration

    /// Registers an Intermediate CA for the use in E2EI processing.
    ///
    /// Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs; You **need**
    /// to have a Root CA registered before calling this
    ///
    /// - Parameter certPEM: PEM certificate to register as an Intermediate CA
    ///
    func e2eiRegisterIntermediateCa(certPem: String) async throws -> NewCrlDistributionPoints

    /// Replaces your leaf containing basic credentials with a leaf
    /// node containing x509 credentials in the conversation.
    ///
    /// NOTE: you can only call this after you've completed the enrollment for an end-to-end identity, and saved the
    /// resulting credential with ``saveX509Credential(enrollment:certificateChain:)-4zgui``.
    /// Calling this without a valid end-to-end identity will result in an error.
    ///
    /// - Parameter conversationId: conversation identifier
    ///
    func e2eiRotate(conversationId: ConversationId) async throws

    /// Saves a new X509 credential. Requires first
    /// having enrolled a new X509 certificate with either ``e2eiNewActivationEnrollment(displayName:handle:team:expirySec:ciphersuite:)-5xix6``
    ///  or ``e2eiNewRotateEnrollment(displayName:handle:team:expirySec:ciphersuite:)-79p60``
    ///
    /// ## Expected actions to perform after this function (in this order)
    /// 1. Rotate credentials for each conversation with ``e2eiRotate(conversationId:)-17p0q``
    /// 2. Generate new key packages with ``generateKeyPackages(ciphersuite:credentialType:amountRequested:)``
    /// 3. Use these to replace the stale ones the in the backend
    /// 4. Delete the stale ones locally using ``deleteStaleKeyPackages(ciphersuite:)-4upiz``
    ///   This is the last step because you might still need the old key packages to avoid an orphan welcome message
    ///
    /// - Parameter enrollment: the enrollment instance used to fetch the certificates
    /// - Parameter certificateChain: - the raw response from ACME server
    /// - Returns: Potentially a list of new certificate revocation list distribution points discovered in the certificate
    /// chain
    ///
    func saveX509Credential(enrollment: E2eiEnrollment, certificateChain: String) async throws
        -> NewCrlDistributionPoints

    /// Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei
    /// turned on or not before joining it.
    ///
    /// - Parameter groupInfo: a TLS encoded GroupInfo fetched from the Delivery Service
    /// - Parameter credentialType: kind of Credential to check usage of. Defaults to X509 for now as no
    ///   other value will give any result.
    /// - Returns: E2EI Conversaton state
    ///
    func getCredentialInUse(groupInfo: Data, credentialType: MlsCredentialType) async throws
        -> E2eiConversationState

    /// From a given conversation, get the identity of the members supplied. Identity is only present
    /// for members with a Certificate Credential (after turning on end-to-end identity).
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Parameter deviceIds: identifiers of the devices
    /// - Returns: identities or if no member has a x509 certificate, it will return an empty List
    ///
    func getDeviceIdentities(conversationId: ConversationId, deviceIds: [ClientId]) async throws
        -> [WireIdentity]

    /// From a given conversation, get the identity of the users (device holders) supplied. Identity
    /// is only present for devices with a Certificate Credential (after turning on end-to-end
    /// identity). If no member has a x509 certificate, it will return an empty Vec.
    ///
    /// - Parameter conversationId: conversation identifier
    /// - Parameter userIds: user identifiers hyphenated UUIDv4 e.g. 'bd4c7053-1c5a-4020-9559-cd7bf7961954'
    /// - Returns: a Map with all the identities for a given users. Consumers are then recommended to
    ///   reduce those identities to determine the actual status of a user.
    ///
    func getUserIdentities(conversationId: ConversationId, userIds: [String]) async throws
        -> [String:
        [WireIdentity]]

    // MARK: Proteus

    /// Initialise [CoreCrypto] to be used with proteus.
    ///
    /// All proteus related methods will fail until this function is called.
    ///
    func proteusInit() async throws

    /// Migrate proteus session from cryptobox into core crypto
    ///
    /// - Parameter path: location where cryptobox session files are stored
    ///
    func proteusCryptoboxMigrate(path: String) async throws

    /// Decrypt a proteus message in a given session
    ///
    /// - Parameter sessionId: session id
    /// - Parameter ciphertext: ciphertext  to decrypt
    /// - Returns: Plaintext data
    ////
    func proteusDecrypt(sessionId: String, ciphertext: Data) async throws -> Data

    /// Encrypt a proteus message in a given session
    ///
    /// - Parameter sessionId: session id
    /// - Parameter ciphertext: plaintext  to encrypt
    /// - Returns: Ciphertext data
    ///
    func proteusEncrypt(sessionId: String, plaintext: Data) async throws -> Data

    /// Encrypt a proteus message for each session provided
    ///
    /// - Parameter sessions: sessions to encrypt for
    /// - Parameter plaintext: plaintext  to encrypt
    /// - Returns: Map of session ID to ciphertext
    ///
    func proteusEncryptBatched(sessions: [String], plaintext: Data) async throws -> [String: Data]

    /// Local identity fingerprint
    ///
    /// - Returns: hex encoded fingerprint string
    ///
    func proteusFingerprint() async throws -> String

    /// Local fingerprint in a given session
    ///
    /// - Returns: hex encoded fingerprint string
    ///
    func proteusFingerprintLocal(sessionId: String) async throws -> String

    /// Remote fingerprint in a given session
    ///
    /// - Returns: hex encoded fingerprint string
    ////
    func proteusFingerprintRemote(sessionId: String) async throws -> String

    /// Fingerprint for the identity of a prekey
    ///
    /// - Returns: hex encoded fingerprint string
    ///
    func proteusFingerprintPrekeybundle(prekey: Data) throws -> String

    /// Create last resort prekey
    ///
    /// - Returns: prekey data
    ////
    func proteusLastResortPrekey() async throws -> Data

    /// Return the last resort prekey ID
    ///
    func proteusLastResortPrekeyId() throws -> UInt16

    /// Create a prekey for the given ID
    ///
    /// - Returns: prekey data
    ///
    func proteusNewPrekey(prekeyId: UInt16) async throws -> Data

    /// Create a prekey for the next unused prekey ID
    ///
    /// - Returns: prekey bundle
    ///
    func proteusNewPrekeyAuto() async throws -> ProteusAutoPrekeyBundle

    /// Delete a proteus session
    ///
    /// - Parameter sessionId: session to delete
    ///
    func proteusSessionDelete(sessionId: String) async throws

    /// Check if a proteus session exists
    ///
    /// - Parameter sessionId: session to query for existance
    ///
    func proteusSessionExists(sessionId: String) async throws -> Bool

    /// Create a proteus session from a prekey message
    ///
    /// - Parameter sessionId: session to create
    /// - Parameter envelope: prekey message
    ///
    func proteusSessionFromMessage(sessionId: String, envelope: Data) async throws -> Data

    /// Create a proteus session from a prekey
    ///
    /// - Parameter sessionId: session to create
    /// - Parameter prekey: prekey data
    ///
    func proteusSessionFromPrekey(sessionId: String, prekey: Data) async throws

    /// Save changes made to a proteus session
    ///
    /// - Parameter sessionId: session to save
    ///
    /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    ///
    func proteusSessionSave(sessionId: String) async throws

}

struct CoreCryptoContextAdapter: CoreCryptoContext {

    let context: WireCoreCryptoUniffi.CoreCryptoContext

    func mlsInit(clientId: ClientId, ciphersuites: Ciphersuites, nbKeyPackage: UInt32?) async throws
    {
        try await wrapError {
            try await context.mlsInit(
                clientId: clientId, ciphersuites: ciphersuites, nbKeyPackage: nbKeyPackage)
        }
    }

    func mlsInitWithClientId(
        clientId: ClientId, tmpClientIds: [ClientId], ciphersuites: Ciphersuites
    )
        async throws
    {
        try await wrapError {
            try await context.mlsInitWithClientId(
                clientId: clientId, tmpClientIds: tmpClientIds, ciphersuites: ciphersuites)
        }
    }

    func mlsGenerateKeypairs(ciphersuites: Ciphersuites) async throws -> [ClientId] {
        try await wrapError {
            try await context.mlsGenerateKeypairs(ciphersuites: ciphersuites)
        }
    }

    func getPublicKey(ciphersuite: Ciphersuite, credentialType: MlsCredentialType) async throws
        -> Data
    {
        try await wrapError {
            try await context.clientPublicKey(
                ciphersuite: ciphersuite, credentialType: credentialType.lower())
        }
    }

    func setData(_ data: Data) async throws {
        try await wrapError {
            try await context.setData(data: data)
        }
    }

    func getData() async throws -> Data? {
        try await wrapError {
            try await context.getData()
        }
    }

    func addClients(conversationId: ConversationId, keyPackages: [Data]) async throws
        -> NewCrlDistributionPoints
    {
        try await wrapError {
            try await context.addClientsToConversation(
                conversationId: conversationId, keyPackages: keyPackages)
        }
    }

    func removeClients(conversationId: ConversationId, clientsIds: [ClientId]) async throws {
        try await wrapError {
            try await context.removeClientsFromConversation(
                conversationId: conversationId, clients: clientsIds)
        }
    }

    func getClientIds(conversationId: ConversationId) async throws -> [ClientId] {
        try await wrapError {
            try await context.getClientIds(conversationId: conversationId)
        }
    }

    func commitPendingProposals(conversationId: ConversationId) async throws {
        try await wrapError {
            try await context.commitPendingProposals(conversationId: conversationId)
        }
    }

    func updateKeyingMaterial(conversationId: Data) async throws {
        try await wrapError {
            try await context.updateKeyingMaterial(conversationId: conversationId)
        }
    }

    func joinByExternalCommit(
        groupInfo: Data, customConfiguration: CustomConfiguration, credentialType: MlsCredentialType
    ) async throws -> WelcomeBundle {
        try await wrapError {
            try await context.joinByExternalCommit(
                groupInfo: groupInfo,
                customConfiguration: customConfiguration.lower(),
                credentialType: credentialType.lower()
            ).lift()
        }
    }

    func processWelcomeMessage(_ welcomeMessage: Data, customConfiguration: CustomConfiguration)
        async throws -> WelcomeBundle
    {
        try await wrapError {
            try await context.processWelcomeMessage(
                welcomeMessage: welcomeMessage,
                customConfiguration: customConfiguration.lower()
            ).lift()
        }
    }

    func getExternalSender(conversationId: ConversationId) async throws -> Data {
        try await wrapError {
            try await context.getExternalSender(conversationId: conversationId)
        }
    }

    func ciphersuite(conversationId: ConversationId) async throws -> Ciphersuite {
        try await wrapError {
            try await context.conversationCiphersuite(conversationId: conversationId)
        }
    }

    func epoch(conversationId: ConversationId) async throws -> UInt64 {
        try await wrapError {
            try await context.conversationEpoch(conversationId: conversationId)
        }
    }

    func conversationExists(conversationId: Data) async throws -> Bool {
        try await wrapError {
            try await context.conversationExists(conversationId: conversationId)
        }
    }

    func createConversation(
        conversationId: ConversationId, creatorCredentialType: MlsCredentialType,
        configuration: ConversationConfiguration
    ) async throws {
        try await wrapError {
            try await context.createConversation(
                conversationId: conversationId,
                creatorCredentialType: creatorCredentialType.lower(),
                config: configuration.lower())
        }
    }

    func encryptMessage(conversationId: ConversationId, message: Data) async throws -> Data {
        try await wrapError {
            try await context.encryptMessage(conversationId: conversationId, message: message)
        }
    }

    func decryptMessage(conversationId: ConversationId, payload: Data) async throws
        -> DecryptedMessage
    {
        try await wrapError {
            try await context.decryptMessage(conversationId: conversationId, payload: payload)
                .lift()
        }
    }

    func wipeConversation(conversationId: Data) async throws {
        try await wrapError {
            try await context.wipeConversation(conversationId: conversationId)
        }
    }

    func exportSecretKey(conversationId: ConversationId, keyLength: UInt32) async throws -> Data {
        try await wrapError {
            try await context.exportSecretKey(conversationId: conversationId, keyLength: keyLength)
        }
    }

    func generateKeyPackages(
        ciphersuite: Ciphersuite, credentialType: MlsCredentialType, amountRequested: UInt32
    ) async throws -> [KeyPackage] {
        try await wrapError {
            try await context.clientKeypackages(
                ciphersuite: ciphersuite,
                credentialType: credentialType.lower(),
                amountRequested: amountRequested
            )
        }
    }

    func deleteKeyPackages(refs: [Data]) async throws {
        try await wrapError {
            try await context.deleteKeypackages(refs: refs)
        }
    }

    func deleteStaleKeyPackages(ciphersuite: Ciphersuite) async throws {
        try await wrapError {
            try await context.deleteStaleKeyPackages(ciphersuite: ciphersuite)
        }
    }

    func validKeyPackageCount(ciphersuite: Ciphersuite, credentialType: MlsCredentialType)
        async throws -> UInt64
    {
        try await wrapError {
            try await context.clientValidKeypackagesCount(
                ciphersuite: ciphersuite, credentialType: credentialType.lower())
        }
    }

    func e2eiConversationState(conversationId: ConversationId) async throws -> E2eiConversationState
    {
        try await wrapError {
            try await context.e2eiConversationState(conversationId: conversationId).lift()
        }
    }

    func e2eiDumpPkiEnv() async throws -> E2eiDumpedPkiEnv? {
        try await wrapError {
            try await context.e2eiDumpPkiEnv()?.lift()
        }
    }

    func e2eiIsEnabled(ciphersuite: Ciphersuite) async throws -> Bool {
        try await wrapError {
            try await context.e2eiIsEnabled(ciphersuite: ciphersuite)
        }
    }

    func e2eiIsPkiEnvSetup() async throws -> Bool {
        try await wrapError {
            try await context.e2eiIsPkiEnvSetup()
        }
    }

    func e2eiMlsInitOnly(
        enrollment: E2eiEnrollment, certificateChain: String, nbKeyPackage: UInt32?
    )
        async throws -> NewCrlDistributionPoints
    {
        try await wrapError {
            try await context.e2eiMlsInitOnly(
                enrollment: enrollment.lower(), certificateChain: certificateChain,
                nbKeyPackage: nbKeyPackage)
        }
    }

    func e2eiNewActivationEnrollment(
        displayName: String, handle: String, team: String?, expirySec: UInt32,
        ciphersuite: Ciphersuite
    ) async throws -> E2eiEnrollment {
        try await wrapError {
            try await context.e2eiNewActivationEnrollment(
                displayName: displayName,
                handle: handle,
                team: team,
                expirySec: expirySec,
                ciphersuite: ciphersuite
            ).lift()
        }
    }

    func e2eiNewEnrollment(
        clientId: String, displayName: String, handle: String, team: String?, expirySec: UInt32,
        ciphersuite: Ciphersuite
    ) async throws -> E2eiEnrollment {
        try await wrapError {
            try await context.e2eiNewEnrollment(
                clientId: clientId,
                displayName: displayName,
                handle: handle,
                team: team,
                expirySec: expirySec,
                ciphersuite: ciphersuite
            ).lift()
        }
    }

    func e2eiNewRotateEnrollment(
        displayName: String?, handle: String?, team: String?, expirySec: UInt32,
        ciphersuite: Ciphersuite
    ) async throws -> E2eiEnrollment {
        try await wrapError {
            try await context.e2eiNewRotateEnrollment(
                displayName: displayName,
                handle: handle,
                team: team,
                expirySec: expirySec,
                ciphersuite: ciphersuite
            ).lift()
        }
    }

    func e2eiRegisterAcmeCa(trustAnchorPem: String) async throws {
        try await wrapError {
            try await context.e2eiRegisterAcmeCa(trustAnchorPem: trustAnchorPem)
        }
    }

    func e2eiRegisterCrl(crlDp: String, crlDer: Data) async throws -> CrlRegistration {
        try await wrapError {
            try await context.e2eiRegisterCrl(crlDp: crlDp, crlDer: crlDer).lift()
        }
    }

    func e2eiRegisterIntermediateCa(certPem: String) async throws -> NewCrlDistributionPoints {
        try await wrapError {
            try await context.e2eiRegisterIntermediateCa(certPem: certPem)
        }
    }

    func e2eiRotate(conversationId: ConversationId) async throws {
        try await wrapError {
            try await context.e2eiRotate(conversationId: conversationId)
        }
    }

    func saveX509Credential(enrollment: E2eiEnrollment, certificateChain: String) async throws
        -> NewCrlDistributionPoints
    {
        try await wrapError {
            try await context.saveX509Credential(
                enrollment: enrollment.lower(),
                certificateChain: certificateChain
            )
        }
    }

    func getCredentialInUse(groupInfo: Data, credentialType: MlsCredentialType) async throws
        -> E2eiConversationState
    {
        try await wrapError {
            try await context.getCredentialInUse(
                groupInfo: groupInfo,
                credentialType: credentialType.lower()
            ).lift()
        }
    }

    func getDeviceIdentities(conversationId: ConversationId, deviceIds: [ClientId]) async throws
        -> [WireIdentity]
    {
        try await wrapError {
            try await context.getDeviceIdentities(
                conversationId: conversationId,
                deviceIds: deviceIds
            ).map { $0.lift() }
        }
    }

    func getUserIdentities(conversationId: ConversationId, userIds: [String]) async throws
        -> [String:
        [WireIdentity]]
    {
        try await wrapError {
            try await context.getUserIdentities(
                conversationId: conversationId,
                userIds: userIds
            ).mapValues({ $0.map { $0.lift() } })
        }
    }

    func proteusCryptoboxMigrate(path: String) async throws {
        try await wrapError {
            try await context.proteusCryptoboxMigrate(path: path)
        }
    }

    func proteusDecrypt(sessionId: String, ciphertext: Data) async throws -> Data {
        try await wrapError {
            try await context.proteusDecrypt(sessionId: sessionId, ciphertext: ciphertext)
        }
    }

    func proteusEncrypt(sessionId: String, plaintext: Data) async throws -> Data {
        try await wrapError {
            try await context.proteusEncrypt(sessionId: sessionId, plaintext: plaintext)
        }
    }

    func proteusEncryptBatched(sessions: [String], plaintext: Data) async throws -> [String: Data] {
        try await wrapError {
            try await context.proteusEncryptBatched(sessions: sessions, plaintext: plaintext)
        }
    }

    func proteusFingerprint() async throws -> String {
        try await wrapError {
            try await context.proteusFingerprint()
        }
    }

    func proteusFingerprintLocal(sessionId: String) async throws -> String {
        try await wrapError {
            try await context.proteusFingerprintLocal(sessionId: sessionId)
        }
    }

    func proteusFingerprintPrekeybundle(prekey: Data) throws -> String {
        try wrapErrorNonAsync {
            try context.proteusFingerprintPrekeybundle(prekey: prekey)
        }
    }

    func proteusFingerprintRemote(sessionId: String) async throws -> String {
        try await wrapError {
            try await context.proteusFingerprintRemote(sessionId: sessionId)
        }
    }

    func proteusInit() async throws {
        try await wrapError {
            try await context.proteusInit()
        }
    }

    func proteusLastResortPrekey() async throws -> Data {
        try await wrapError {
            try await context.proteusLastResortPrekey()
        }
    }

    func proteusLastResortPrekeyId() throws -> UInt16 {
        try wrapErrorNonAsync {
            try context.proteusLastResortPrekeyId()
        }
    }

    func proteusNewPrekey(prekeyId: UInt16) async throws -> Data {
        try await wrapError {
            try await context.proteusNewPrekey(prekeyId: prekeyId)
        }
    }

    func proteusNewPrekeyAuto() async throws -> ProteusAutoPrekeyBundle {
        try await wrapError {
            try await context.proteusNewPrekeyAuto().lift()
        }
    }

    func proteusSessionDelete(sessionId: String) async throws {
        try await wrapError {
            try await context.proteusSessionDelete(sessionId: sessionId)
        }
    }

    func proteusSessionExists(sessionId: String) async throws -> Bool {
        try await wrapError {
            try await context.proteusSessionExists(sessionId: sessionId)
        }
    }

    func proteusSessionFromMessage(sessionId: String, envelope: Data) async throws -> Data {
        try await wrapError {
            try await context.proteusSessionFromMessage(sessionId: sessionId, envelope: envelope)
        }
    }

    func proteusSessionFromPrekey(sessionId: String, prekey: Data) async throws {
        try await wrapError {
            try await context.proteusSessionFromPrekey(sessionId: sessionId, prekey: prekey)
        }
    }

    func proteusSessionSave(sessionId: String) async throws {
        try await wrapError {
            try await context.proteusSessionSave(sessionId: sessionId)
        }
    }

}
