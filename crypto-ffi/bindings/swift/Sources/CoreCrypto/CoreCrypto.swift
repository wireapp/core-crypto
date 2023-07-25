// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

import CoreCryptoSwift
import Foundation

/// Interface to convert to ``CoreCrypto``'s internal types
private protocol ConvertToInner {
    associatedtype Inner
    func convert() -> Inner
}

extension CoreCryptoSwift.CommitBundle {
    func convertTo() -> CommitBundle {
        return CommitBundle(welcome: self.welcome, commit: self.commit, groupInfo: self.groupInfo.convertTo())
    }
}

extension CoreCryptoSwift.RotateBundle {
    func convertTo() -> RotateBundle {
        return RotateBundle(commits: self.commits, newKeyPackages: self.newKeyPackages, keyPackageRefsToRemove: self.keyPackageRefsToRemove)
    }
}

extension CoreCryptoSwift.MemberAddedMessages {
    func convertTo() -> MemberAddedMessages {
        return MemberAddedMessages(commit: self.commit, welcome: self.welcome, groupInfo: self.groupInfo.convertTo())
    }
}

extension CoreCryptoSwift.ConversationInitBundle {
    func convertTo() -> ConversationInitBundle {
        return ConversationInitBundle(conversationId: self.conversationId, commit: self.commit, groupInfo: self.groupInfo.convertTo())
    }
}

extension CoreCryptoSwift.DecryptedMessage {
    func convertTo() -> DecryptedMessage {
        return DecryptedMessage(message: self.message, proposals: self.proposals.map({ (bundle) -> ProposalBundle in
            return bundle.convertTo()
        }), isActive: self.isActive, commitDelay: self.commitDelay, senderClientId: self.senderClientId, hasEpochChanged: self.hasEpochChanged, identity: self.identity?.convertTo())
    }
}

extension CoreCryptoSwift.WireIdentity {
    func convertTo() -> WireIdentity {
        return WireIdentity(clientId: self.clientId, handle: self.handle, displayName: self.displayName, domain: self.domain)
    }
}

extension CoreCryptoSwift.ProposalBundle {
    func convertTo() -> ProposalBundle {
        return ProposalBundle(proposal: self.proposal, proposalRef: self.proposalRef)
    }
}

extension CoreCryptoSwift.GroupInfoBundle {
    func convertTo() -> GroupInfoBundle {
        return GroupInfoBundle(encryptionType: self.encryptionType.convertTo(), ratchetTreeType: self.ratchetTreeType.convertTo(), payload: self.payload)
    }
}

extension CoreCryptoSwift.MlsGroupInfoEncryptionType {
    func convertTo() -> GroupInfoEncryptionType {
        switch self {
            case .jweEncrypted: return GroupInfoEncryptionType.JweEncrypted
            case .plaintext: return GroupInfoEncryptionType.Plaintext
        }
    }
}

extension CoreCryptoSwift.ProteusAutoPrekeyBundle {
    func convertTo() -> ProteusAutoPrekeyBundle {
        return ProteusAutoPrekeyBundle(id: self.id, pkb: self.pkb)
    }
}

extension CoreCryptoSwift.MlsRatchetTreeType {
    func convertTo() -> RatchetTreeType {
        switch self {
            case .full: return RatchetTreeType.Full
            case .delta: return RatchetTreeType.Delta
            case .byRef: return RatchetTreeType.ByRef
        }
    }
}

/// Alias for conversation IDs.
/// This is a freeform, uninspected buffer.
public typealias ConversationId = [UInt8]

/// Alias for ClientId within a conversation.
public typealias ClientId = [UInt8]

/// Conversation ciphersuite variants
public enum CiphersuiteName: ConvertToInner {
    typealias Inner = CoreCryptoSwift.CiphersuiteName

    case mls128Dhkemx25519Aes128gcmSha256Ed25519
    case mls128Dhkemp256Aes128gcmSha256P256
    case mls128Dhkemx25519Chacha20poly1305Sha256Ed25519
    case mls256Dhkemx448Aes256gcmSha512Ed448
    case mls256Dhkemp521Aes256gcmSha512P521
    case mls256Dhkemx448Chacha20poly1305Sha512Ed448
    case mls256Dhkemp384Aes256gcmSha384P384
    case mls128X25519kyber768draft00Aes128gcmSha256Ed25519
}

private extension CiphersuiteName {
    func convert() -> Inner {
        switch self {
        case .mls128Dhkemx25519Aes128gcmSha256Ed25519:
            return CoreCryptoSwift.CiphersuiteName.mls128Dhkemx25519Aes128gcmSha256Ed25519
        case .mls128Dhkemp256Aes128gcmSha256P256:
            return CoreCryptoSwift.CiphersuiteName.mls128Dhkemp256Aes128gcmSha256P256
        case .mls128Dhkemx25519Chacha20poly1305Sha256Ed25519:
            return CoreCryptoSwift.CiphersuiteName.mls128Dhkemx25519Chacha20poly1305Sha256Ed25519
        case .mls256Dhkemx448Aes256gcmSha512Ed448:
            return CoreCryptoSwift.CiphersuiteName.mls256Dhkemx448Aes256gcmSha512Ed448
        case .mls256Dhkemp521Aes256gcmSha512P521:
            return CoreCryptoSwift.CiphersuiteName.mls256Dhkemp521Aes256gcmSha512P521
        case .mls256Dhkemx448Chacha20poly1305Sha512Ed448:
            return CoreCryptoSwift.CiphersuiteName.mls256Dhkemx448Chacha20poly1305Sha512Ed448
        case .mls256Dhkemp384Aes256gcmSha384P384:
            return CoreCryptoSwift.CiphersuiteName.mls256Dhkemp384Aes256gcmSha384P384
        case .mls128X25519kyber768draft00Aes128gcmSha256Ed25519:
            return CoreCryptoSwift.CiphersuiteName.mls128X25519kyber768draft00Aes128gcmSha256Ed25519
        }

    }
}

/// Type of credential: either Basic or X509 certificate (probably more to come)
public enum MlsCredentialType: ConvertToInner {
    typealias Inner = CoreCryptoSwift.MlsCredentialType

    case basic
    case x509
}

private extension MlsCredentialType {
    func convert() -> Inner {
        switch self {
        case .basic:
            return CoreCryptoSwift.MlsCredentialType.basic
        case .x509:
            return CoreCryptoSwift.MlsCredentialType.x509
        }
    }
}

public struct ProteusAutoPrekeyBundle: ConvertToInner {
    typealias Inner = CoreCryptoSwift.ProteusAutoPrekeyBundle
    func convert() -> Inner {
        return CoreCryptoSwift.ProteusAutoPrekeyBundle(id: self.id, pkb: self.preKeyBundle)
    }

    /// Proteus PreKey ID
    public var id: UInt16
    /// CBOR-serialized Proteus PreKeyBundle
    public var preKeyBundle: [UInt8]

    public init(id: UInt16, pkb: [UInt8]) {
        self.id = id
        self.preKeyBundle = pkb
    }
}

/// Configuration object for new conversations
public struct ConversationConfiguration: ConvertToInner {
    typealias Inner = CoreCryptoSwift.ConversationConfiguration
    func convert() -> Inner {
        return CoreCryptoSwift.ConversationConfiguration(ciphersuite: self.ciphersuite, externalSenders: self.externalSenders, custom: self.custom.convert(), self.perDomainTrustAnchor.convert())
    }

    /// Conversation ciphersuite
    public var ciphersuite: UInt16
    /// List of client IDs that are allowed to be external senders of commits
    public var externalSenders: [[UInt8]]
    /// Implementation specific configuration
    public var custom: CustomConfiguration
    /// Trust anchors to be added in the group's context extensions
    public var perDomainTrustAnchor: PerDomainTrustAnchor

    public init(ciphersuite: UInt16, externalSenders: [[UInt8]], custom: CustomConfiguration, perDomainTrustAnchor: PerDomainTrustAnchor) {
        self.ciphersuite = ciphersuite
        self.externalSenders = externalSenders
        self.custom = custom
        self.perDomainTrustAnchor = perDomainTrustAnchor
    }
}

/// A wrapper containing the configuration for trust anchors to be added in the group's context extensions
public struct PerDomainTrustAnchor: ConvertToInner {
    typealias Inner = CoreCryptoSwift.PerDomainTrustAnchor
    func convert() -> Inner {
        return CoreCryptoSwift.PerDomainTrustAnchor(domain_name: self.domainName, intermediate_certificate_chain: self.intermediateCertificateChain)
    }

    /// Domain name in which the trust anchor belongs to
    public var domainName: String
    /// PEM encoded certificate chain
    public var intermediateCertificateChain: String

    public init(domainName: String, intermediateCertificateChain: String) {
        self.domainName = domainName
        self.intermediateCertificateChain = intermediateCertificateChain
    }
}

/// Defines if handshake messages are encrypted or not
public enum WirePolicy: ConvertToInner {
    typealias Inner = CoreCryptoSwift.MlsWirePolicy

    case plaintext
    case ciphertext
}

private extension WirePolicy {
    func convert() -> Inner {
        switch self {
        case .plaintext:
            return CoreCryptoSwift.MlsWirePolicy.plaintext
        case .ciphertext:
            return CoreCryptoSwift.MlsWirePolicy.ciphertext
        }
    }
}

/// Implementation specific configuration object for a conversation
public struct CustomConfiguration: ConvertToInner {
    typealias Inner = CoreCryptoSwift.CustomConfiguration
    func convert() -> Inner {
        return CoreCryptoSwift.CustomConfiguration(keyRotationSpan: self.keyRotationSpan, wirePolicy: self.wirePolicy?.convert())
    }

    /// Duration in seconds after which we will automatically force a self_update commit
    /// Note: This isn't currently implemented
    public var keyRotationSpan: TimeInterval?
    /// Defines if handshake messages are encrypted or not
    /// Note: Ciphertext is not currently supported by wire-server
    public var wirePolicy: WirePolicy?

    public init(keyRotationSpan: TimeInterval?, wirePolicy: WirePolicy?) {
        self.keyRotationSpan = keyRotationSpan
        self.wirePolicy = wirePolicy
    }
}

/// Data shape for adding clients to a conversation
public struct Invitee: ConvertToInner {
    typealias Inner = CoreCryptoSwift.Invitee
    /// Client ID as a byte array
    public var id: ClientId
    /// MLS KeyPackage belonging to the aforementioned client
    public var kp: [UInt8]

    public init(id: ClientId, kp: [UInt8]) {
        self.id = id
        self.kp = kp
    }

    func convert() -> Inner {
        return CoreCryptoSwift.Invitee(id: self.id, kp: self.kp)
    }
}

/// Data shape for the returned MLS commit & welcome message tuple upon adding clients to a conversation
public struct MemberAddedMessages: ConvertToInner {
    typealias Inner = CoreCryptoSwift.MemberAddedMessages
    /// TLS-serialized MLS Welcome message that needs to be fanned out to the clients newly added to the conversation
    public var commit: [UInt8]
    /// TLS-serialized MLS Commit that needs to be fanned out to other (existing) members of the conversation
    public var welcome: [UInt8]
    /// The current group state
    public var groupInfo: GroupInfoBundle

    public init(commit: [UInt8], welcome: [UInt8], groupInfo: GroupInfoBundle) {
        self.commit = commit
        self.welcome = welcome
        self.groupInfo = groupInfo
    }

    func convert() -> Inner {
        return CoreCryptoSwift.MemberAddedMessages(commit: self.commit, welcome: self.welcome, groupInfo: self.groupInfo.convert())
    }
}

/// Represents the potential items a consumer might require after passing us an encrypted message we
/// have decrypted for him
public struct DecryptedMessage: ConvertToInner {
    typealias Inner = CoreCryptoSwift.DecryptedMessage
    /// Decrypted text message
    public var message: [UInt8]?
    /// Only when decrypted message is a commit, CoreCrypto will renew local proposal which could not make it in the commit.
    /// This will contain either:
    /// - local pending proposal not in the accepted commit
    /// - If there is a pending commit, its proposals which are not in the accepted commit
    public var proposals: [ProposalBundle]
    /// Is the conversation still active after receiving this commit
    /// aka has the user been removed from the group
    public var isActive: Bool
    /// delay time in seconds to feed caller timer for committing
    public var commitDelay: UInt64?
    /// Client identifier of the sender of the message being decrypted. Only present for application messages.
    public var senderClientId: ClientId?
    /// It is set to true if the decrypted messages resulted in a epoch change (AKA it was a commit)
    public var hasEpochChanged: Bool
    /// Identity claims present in the sender credential
    /// Only present when the credential is a x509 certificate
    /// Present for all messages
    public var identity: WireIdentity?

    public init(message: [UInt8]?, proposals: [ProposalBundle], isActive: Bool, commitDelay: UInt64?, senderClientId: ClientId?, hasEpochChanged: Bool, identity: WireIdentity?) {
        self.message = message
        self.proposals = proposals
        self.isActive = isActive
        self.commitDelay = commitDelay
        self.senderClientId = senderClientId
        self.hasEpochChanged = hasEpochChanged
        self.identity = identity
    }

    func convert() -> Inner {
        return CoreCryptoSwift.DecryptedMessage(message: self.message, proposals: self.proposals.map({ (bundle) -> CoreCryptoSwift.ProposalBundle in
            bundle.convert()
        }), isActive: self.isActive, commitDelay: self.commitDelay, senderClientId: self.senderClientId, hasEpochChanged: self.hasEpochChanged, identity: self.identity?.convert())
    }
}

/// Represents the identity claims identifying a client. Those claims are verifiable by any member in the group
public struct WireIdentity: ConvertToInner {
    typealias Inner = CoreCryptoSwift.WireIdentity

    /// Represents the identity claims identifying a client. Those claims are verifiable by any member in the group
    public var clientId: String
    /// user handle e.g. `john_wire`
    public var handle: String
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    public var displayName: String
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    public var domain: String

    public init(clientId: String, handle: String, displayName: String, domain: String) {
        self.clientId = clientId
        self.handle = handle
        self.displayName = displayName
        self.domain = domain
    }

    func convert() -> Inner {
        return CoreCryptoSwift.WireIdentity(clientId: self.clientId, handle: self.handle, displayName: self.displayName, domain: self.domain)
    }
}

/// Result of a created commit
public struct ProposalBundle: ConvertToInner {
    typealias Inner = CoreCryptoSwift.ProposalBundle
    /// The proposal message
    public var proposal: [UInt8]
    /// An identifier of the proposal to rollback it later if required
    public var proposalRef: [UInt8]

    public init(proposal: [UInt8], proposalRef: [UInt8]) {
        self.proposal = proposal
        self.proposalRef = proposalRef
    }

    func convert() -> Inner {
        return CoreCryptoSwift.ProposalBundle(proposal: self.proposal, proposalRef: self.proposalRef)
    }
}

/// Represents the result type of the external commit request.
public struct ConversationInitBundle: ConvertToInner {
    typealias Inner = CoreCryptoSwift.ConversationInitBundle
    /// Conversation id
    public var conversationId: ConversationId
    /// TLS-serialized MLS External Commit that needs to be fanned out
    public var commit: [UInt8]
    /// TLS-serialized GroupInfo (aka GroupInfo) which becomes valid when the external commit is accepted by the Delivery Service
    public var groupInfo: GroupInfoBundle

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(conversationId: ConversationId, commit: [UInt8], groupInfo: GroupInfoBundle) {
        self.conversationId = conversationId
        self.commit = commit
        self.groupInfo = groupInfo
    }

    func convert() -> Inner {
        return CoreCryptoSwift.ConversationInitBundle(conversationId: self.conversationId, commit: self.commit, groupInfo: self.groupInfo.convert())
    }
}

/// Data shape for a MLS generic commit + optional bundle (aka stapled commit & welcome)
public struct CommitBundle: ConvertToInner {
    /// Optional TLS-serialized MLS Welcome message that needs to be fanned out to the clients newly added to the conversation
    public var welcome: [UInt8]?
    /// TLS-serialized MLS Commit that needs to be fanned out to other (existing) members of the conversation
    public var commit: [UInt8]
    /// The current state of the group
    public var groupInfo: GroupInfoBundle

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(welcome: [UInt8]?, commit: [UInt8], groupInfo: GroupInfoBundle) {
        self.welcome = welcome
        self.commit = commit
        self.groupInfo = groupInfo
    }
    typealias Inner = CoreCryptoSwift.CommitBundle

    func convert() -> Inner {
        return CoreCryptoSwift.CommitBundle(welcome: self.welcome, commit: self.commit, groupInfo: self.groupInfo.convert())
    }
}

/// A GroupInfo with metadata
public struct GroupInfoBundle: ConvertToInner {
    /// Indicates if the payload is encrypted or not
    public var encryptionType: GroupInfoEncryptionType
    /// Indicates if the payload contains a full, partial or referenced GroupInfo
    public var ratchetTreeType: RatchetTreeType
    /// TLS encoded GroupInfo
    public var payload: [UInt8]

    public init(encryptionType: GroupInfoEncryptionType, ratchetTreeType: RatchetTreeType, payload: [UInt8]) {
        self.encryptionType = encryptionType
        self.ratchetTreeType = ratchetTreeType
        self.payload = payload
    }
    typealias Inner = CoreCryptoSwift.GroupInfoBundle

    func convert() -> Inner {
        return CoreCryptoSwift.GroupInfoBundle(encryptionType: self.encryptionType.convert(), ratchetTreeType: self.ratchetTreeType.convert(), payload: self.payload)
    }
}

/// In order to guarantee confidentiality of the GroupInfo on the wire a domain can request it to be encrypted when sent to the Delivery Service.
public enum GroupInfoEncryptionType: ConvertToInner {
    typealias Inner = CoreCryptoSwift.MlsGroupInfoEncryptionType

    case Plaintext
    case JweEncrypted
}

private extension GroupInfoEncryptionType {
    func convert() -> Inner {
        switch self {
        case .Plaintext:
            return CoreCryptoSwift.MlsGroupInfoEncryptionType.plaintext
        case .JweEncrypted:
            return CoreCryptoSwift.MlsGroupInfoEncryptionType.jweEncrypted
        }
    }
}

/// In order to spare some precious bytes, a GroupInfo can have different representations.
public enum RatchetTreeType: ConvertToInner {
    typealias Inner = CoreCryptoSwift.MlsRatchetTreeType

    case Full
    case Delta
    case ByRef
}

private extension RatchetTreeType {
    func convert() -> Inner {
        switch self {
        case .Full:
            return CoreCryptoSwift.MlsRatchetTreeType.full
        case .Delta:
            return CoreCryptoSwift.MlsRatchetTreeType.delta
        case .ByRef:
            return CoreCryptoSwift.MlsRatchetTreeType.byRef
        }
    }
}

/// Result returned after rotating the Credential of the current client in all the local conversations
public struct RotateBundle: ConvertToInner {
    /// An Update commit for each conversation
    public var commits: [CommitBundle]
    /// Fresh KeyPackages with the new Credential
    public var newKeyPackages: [[UInt8]]
    /// All the now deprecated KeyPackages. Once deleted remotely, delete them locally with ``CoreCrypto/deleteKeypackages``
    public var keyPackageRefsToRemove: [[UInt8]]

    public init(commits: [CommitBundle], newKeyPackages: [[UInt8]], keyPackageRefsToRemove: [[UInt8]]) {
        self.commits = commits
        self.newKeyPackages = newKeyPackages
        self.keyPackageRefsToRemove = keyPackageRefsToRemove
    }
    typealias Inner = CoreCryptoSwift.RotateBundle

    func convert() -> Inner {
        return CoreCryptoSwift.RotateBundle(commits: self.commits, newKeyPackages: self.newKeyPackages, keyPackageRefsToRemove: self.keyPackageRefsToRemove)
    }
}

/// A wrapper for the underlying ``CoreCrypto`` object.
/// Intended to avoid API breakages due to possible changes in the internal framework used to generate it
public class CoreCryptoWrapper {
    fileprivate let coreCrypto: CoreCrypto

    /// This is your entrypoint to initialize ``CoreCrypto``
    /// - parameter path: Name of the IndexedDB database
    /// - parameter key: Encryption master key
    /// - parameter clientId: MLS Client ID.
    ///
    /// # Notes #
    /// 1. ``clientId`` should stay consistent as it will be verified against the stored signature & identity to validate the persisted credential
    /// 2. ``key`` should be appropriately stored in a secure location (i.e. WebCrypto private key storage)
    ///
    public init(path: String, key: String, clientId: ClientId, ciphersuites: Array<UInt16>) async throws {
        self.coreCrypto = try await CoreCrypto(path: path, key: key, clientId: clientId, ciphersuites: ciphersuites)
    }

    /// Almost identical to ```CoreCrypto/init``` but allows a 2 phase initialization of MLS.First, calling this will
    /// set up the keystore and will allow generating proteus prekeys.Then, those keys can be traded for a clientId.
    /// Use this clientId to initialize MLS with ```CoreCrypto/mlsInit```.
    public static func deferredInit(path: String, key: String, ciphersuites: Array<UInt16>) async throws -> CoreCrypto {
        await try CoreCrypto.deferredInit(path: path, key: key, ciphersuites: ciphersuites)
    }

    /// Use this after ```CoreCrypto/deferredInit``` when you have a clientId. It initializes MLS.
    ///
    /// - parameter clientId: client identifier
    public func mlsInit(clientId: ClientId, ciphersuites: Array<UInt16>) async throws {
        await try self.coreCrypto.mlsInit(clientId: clientId, ciphersuites: ciphersuites)
    }

    /// Generates a MLS KeyPair/CredentialBundle with a temporary, random client ID.
    /// This method is designed to be used in conjunction with ```CoreCrypto/mlsInitWithClientId``` and represents the first step in this process
    ///
    /// - returns: the TLS-serialized identity key (i.e. the signature keypair's public key)
    public func mlsGenerateKeypairs(ciphersuites: Array<UInt16>) async throws -> [[UInt8]] {
        await try self.coreCrypto.mlsGenerateKeypairs(ciphersuites: ciphersuites)
    }

    /// Updates the current temporary Client ID with the newly provided one. This is the second step in the externally-generated clients process
    ///
    /// Important: This is designed to be called after ```CoreCrypto/mlsGenerateKeypair```
    ///
    /// - parameter clientId: The newly allocated Client ID from the MLS Authentication Service
    /// - parameter signaturePublicKey: The public key you obtained at step 1, for authentication purposes
    public func mlsInitWithClientId(clientId: ClientId, signaturePublicKeys: [[UInt8]], ciphersuites: Array<UInt16>) async throws {
        await try self.coreCrypto.mlsInitWithClientId(clientId: clientId, signaturePublicKeys: signaturePublicKeys, ciphersuites: ciphersuites)
    }

    /// `CoreCrypto` is supposed to be a singleton. Knowing that, it does some optimizations by
    /// keeping MLS groups in memory. Sometimes, especially on iOS, it is required to use extensions
    /// to perform tasks in the background. Extensions are executed in another process so another
    /// `CoreCrypto` instance has to be used. This method has to be used to synchronize instances.
    /// It simply fetches the MLS group from keystore in memory.
    public func restoreFromDisk() async throws {
        return try await self.coreCrypto.restoreFromDisk()
    }

    /// Sets the callback interface, required by some operations from `CoreCrypto`
    ///
    /// - parameter callbacks: the object that implements the ``CoreCryptoCallbacks`` interface
    public func setCallbacks(callbacks: CoreCryptoCallbacks) async throws {
        try await self.coreCrypto.setCallbacks(callbacks: callbacks)
    }

    /// - returns: The client's public key
    public func clientPublicKey(ciphersuite: UInt16) async throws -> [UInt8] {
        return try await self.coreCrypto.clientPublicKey(ciphersuite: ciphersuite)
    }

    /// Fetches a requested amount of keypackages
    /// - parameter amountRequested: The amount of keypackages requested
    /// - returns: An array of length `amountRequested` containing TLS-serialized KeyPackages
    public func clientKeypackages(ciphersuite: UInt16, amountRequested: UInt32) async throws -> [[UInt8]] {
        return try await self.coreCrypto.clientKeypackages(ciphersuite: ciphersuite, amountRequested: amountRequested)
    }

    /// - returns: The amount of valid, non-expired KeyPackages that are persisted in the backing storage
    public func clientValidKeypackagesCount(ciphersuite: UInt16) async throws -> UInt64 {
        return try await self.coreCrypto.clientValidKeypackagesCount(ciphersuite: ciphersuite)
    }

    /// Prunes local KeyPackages after making sure they also have been deleted on the backend side.
    /// You should only use this after ``CoreCrypto/e2eiRotateAll``
    public func deleteKeypackages(refs: [[UInt8]]) async throws {
        return try await self.coreCrypto.deleteKeypackages(refs)
    }

    /// Creates a new conversation with the current client being the sole member
    /// You will want to use ``addClientsToConversation(conversationId:clients:)`` afterwards to add clients to this conversation
    /// - parameter conversationId: conversation identifier
    /// - parameter creatorCredentialType: kind of credential the creator wants to create the group with
    /// - parameter config: the configuration for the conversation to be created
    public func createConversation(conversationId: ConversationId, creatorCredentialType: MlsCredentialType, config: ConversationConfiguration) async throws {
        try await self.coreCrypto.createConversation(conversationId: conversationId, creatorCredentialType: creatorCredentialType.convert(), config: config.convert())
    }

    /// Checks if the Client is member of a given conversation and if the MLS Group is loaded up
    /// - parameter conversationId: conversation identifier
    /// - returns: Whether the given conversation ID exists
    public func conversationExists(conversationId: ConversationId) async -> Bool {
        return await self.coreCrypto.conversationExists(conversationId: conversationId)
    }

    /// Returns the epoch of a given conversation id
    /// - parameter conversationId: conversation identifier
    /// - returns: the current epoch of the conversation
    public func conversationEpoch(conversationId: ConversationId) async throws -> UInt64 {
        return try await self.coreCrypto.conversationEpoch(conversationId: conversationId)
    }

    /// Ingest a TLS-serialized MLS welcome message to join a an existing MLS group
    /// - parameter welcomeMessage: - TLS-serialized MLS Welcome message
    /// - parameter config: - configuration of the MLS group
    /// - returns: The conversation ID of the newly joined group. You can use the same ID to decrypt/encrypt messages
    public func processWelcomeMessage(welcomeMessage: [UInt8], configuration: CustomConfiguration) async throws -> ConversationId {
        return try await self.coreCrypto.processWelcomeMessage(welcomeMessage: welcomeMessage, customConfiguration: configuration.convert())
    }

    /// Adds new clients to a conversation, assuming the current client has the right to add new clients to the conversation
    ///
    /// The returned ``CommitBundle`` is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
    /// It also contains a Welcome message the Delivery Service will forward to invited clients and
    /// an updated GroupInfo required by clients willing to join the group by an external commit.
    ///
    /// **CAUTION**: ``CoreCryptoWrapper/commitAccepted`` **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
    /// '200 OK' to the ``CommitBundle`` upload. It will "merge" the commit locally i.e. increment the local group
    /// epoch, use new encryption secrets etc...
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter clients: Array of ``Invitee`` (which are Client ID / KeyPackage pairs)
    /// - returns: A ``CommitBundle`` byte array to fan out to the Delivery Service
    public func addClientsToConversation(conversationId: ConversationId, clients: [Invitee]) async throws -> MemberAddedMessages {
        return try await self.coreCrypto.addClientsToConversation(conversationId: conversationId, clients: clients.map({ (invitee) -> CoreCryptoSwift.Invitee in
            return invitee.convert()
        })).convertTo()
    }

    /// Removes the provided clients from a conversation; Assuming those clients exist and the current client is allowed
    /// to do so, otherwise this operation does nothing.
    ///
    /// The returned ``CommitBundle`` is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
    /// It also contains a Welcome message the Delivery Service will forward to invited clients and
    /// an updated GroupInfo required by clients willing to join the group by an external commit.
    ///
    /// **CAUTION**: ``CoreCryptoWrapper/commitAccepted`` **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
    /// '200 OK' to the ``CommitBundle`` upload. It will "merge" the commit locally i.e. increment the local group
    /// epoch, use new encryption secrets etc...
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter clients: Array of Client IDs to remove.
    /// - returns: A ``CommitBundle`` byte array to fan out to the Delivery Service
    public func removeClientsFromConversation(conversationId: ConversationId, clients: [ClientId]) async throws -> CommitBundle {
        return try await self.coreCrypto.removeClientsFromConversation(conversationId: conversationId, clients: clients).convertTo()
    }

    /// Marks a conversation as child of another one
    /// This will mostly affect the behavior of the callbacks (the parentConversationClients parameter will be filled)
    ///
    /// - parameter childId: conversation identifier of the child conversation
    /// - parameter parentId: conversation identifier of the parent conversation
    public func markConversationAsChildOf(childId: ConversationId, parentId: ConversationId) async throws {
        try await self.coreCrypto.markConversationAsChildOf(childId: childId, parentId: parentId)
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited.
    ///
    /// The returned ``CommitBundle`` is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
    /// It also contains a Welcome message the Delivery Service will forward to invited clients and
    /// an updated GroupInfo required by clients willing to join the group by an external commit.
    ///
    /// **CAUTION**: ``CoreCryptoWrapper/commitAccepted`` **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
    /// '200 OK' to the ``CommitBundle`` upload. It will "merge" the commit locally i.e. increment the local group
    /// epoch, use new encryption secrets etc...
    ///
    /// - parameter conversationId: conversation identifier
    /// - returns: A ``CommitBundle`` byte array to fan out to the Delivery Service
    public func updateKeyingMaterial(conversationId: ConversationId) async throws -> CommitBundle {
        try await self.coreCrypto.updateKeyingMaterial(conversationId: conversationId).convertTo()
    }

    /// Commits all pending proposals of the group
    ///
    /// The returned ``CommitBundle`` is a TLS struct that needs to be fanned out to Delivery Service in order to validate the commit.
    /// It also contains a Welcome message the Delivery Service will forward to invited clients and
    /// an updated GroupInfo required by clients willing to join the group by an external commit.
    ///
    /// **CAUTION**: ``CoreCryptoWrapper/commitAccepted`` **HAS TO** be called afterwards **ONLY IF** the Delivery Service responds
    /// '200 OK' to the ``CommitBundle`` upload. It will "merge" the commit locally i.e. increment the local group
    /// epoch, use new encryption secrets etc...
    ///
    /// - parameter conversationId: conversation identifier
    /// - returns: A ``CommitBundle`` byte array to fan out to the Delivery Service
    public func commitPendingProposals(conversationId: ConversationId) async throws -> CommitBundle? {
        try await self.coreCrypto.commitPendingProposals(conversationId:conversationId)?.convertTo()
    }

    /// Destroys a group locally
    ///
    /// - parameter conversationId: conversation identifier
    public func wipeConversation(conversationId: ConversationId) async throws {
        try await self.coreCrypto.wipeConversation(conversationId: conversationId)
    }

    /// Deserializes a TLS-serialized message, then deciphers it
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter payload: the encrypted message as a byte array
    /// - returns an object of the type ``DecryptedMessage``
    public func decryptMessage(conversationId: ConversationId, payload: [UInt8]) async throws -> DecryptedMessage {
        return try await self.coreCrypto.decryptMessage(conversationId: conversationId, payload: payload).convertTo()
    }

    /// Encrypts a raw payload then serializes it to the TLS wire format
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter message: the message as a byte array
    /// - returns: an encrypted TLS serialized message.
    public func encryptMessage(conversationId: ConversationId, message: [UInt8]) async throws -> [UInt8] {
        return try await self.coreCrypto.encryptMessage(conversationId: conversationId, message: message)
    }

    /// Updates the trust anchors for a conversation
    ///
    /// - parameter conversationId - The ID of the conversation
    /// - parameter removeDomainNames - Domains to remove from the trust anchors
    /// - parameter addTrustAnchors - New trust anchors to add to the conversation
    ///
    /// - returns: A ``CommitBundle`` byte array to fan out to the Delivery Service
    public func updateTrustAnchorsFromConversation(conversationId: ConversationId, removeDomainNames: [string], addTrustAnchors: [PerDomainTrustAnchor]) async throws -> CommitBundle {
        return try await self.coreCrypto.update_trust_anchors_from_conversation(conversationId: conversationId, removeDomainNames: removeDomainNames, addTrustAnchors: addTrustAnchors.map({ (anchor) -> CoreCryptoSwift.PerDomainTrustAnchor in
            return anchor.convert()
        })).convertTo()
    }

    /// Creates a new add proposal within a group
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter keyPackage: the owner's `KeyPackage` to be added to the group
    /// - returns: a message (to be fanned out) will be returned with the proposal that was created
    public func newAddProposal(conversationId: ConversationId, keyPackage: [UInt8]) async throws -> ProposalBundle {
        return try await self.coreCrypto.newAddProposal(conversationId: conversationId, keyPackage: keyPackage).convertTo()
    }

    /// Creates a new update proposal within a group. It will replace the sender's `LeafNode` in the
    /// ratchet tree
    ///
    /// - parameter conversationId: conversation identifier
    /// - returns: a message (to be fanned out) will be returned with the proposal that was created
    public func newUpdateProposal(conversationId: ConversationId) async throws -> ProposalBundle {
        return try await self.coreCrypto.newUpdateProposal(conversationId: conversationId).convertTo()
    }

    /// Creates a new remove proposal within a group
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter clientId: client id to be removed from the group
    /// - returns: a message (to be fanned out) will be returned with the proposal that was created
    public func newRemoveProposal(conversationId: ConversationId, clientId: ClientId) async throws -> ProposalBundle {
        return try await self.coreCrypto.newRemoveProposal(conversationId: conversationId, clientId: clientId).convertTo()
    }

    /// Crafts a new external Add proposal. Enables a client outside a group to request addition to this group.
    /// For Wire only, the client must belong to an user already in the group
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter epoch: the current epoch of the group
    /// - returns: a message with the proposal to be add a new client
    public func newExternalAddProposal(conversationId: ConversationId, epoch: UInt64, ciphersuite: UInt16, credentialType: MlsCredentialType) async throws -> [UInt8] {
        return try await self.coreCrypto.newExternalAddProposal(conversationId: conversationId, epoch: epoch, ciphersuite: ciphersuite, credentialType: credentialType.convert())
    }

    /// Issues an external commit and stores the group in a temporary table. This method is
    /// intended for example when a new client wants to join the user's existing groups.
    ///
    /// If the Delivery Service accepts the external commit, you have to ``CoreCryptoWrapper/mergePendingGroupFromExternalCommit``
    /// in order to get back a functional MLS group. On the opposite, if it rejects it, you can either retry by just
    /// calling again ``CoreCryptoWrapper/joinByExternalCommit``, no need to ``CoreCryptoWrapper/clearPendingGroupFromExternalCommit``.
    /// If you want to abort the operation (too many retries or the user decided to abort), you can use
    /// ``CoreCryptoWrapper/clearPendingGroupFromExternalCommit`` in order not to bloat the user's storage but nothing
    /// bad can happen if you forget to except some storage space wasted.
    ///
    /// - parameter groupInfo: a TLS encoded `GroupInfo` fetched from the Delivery Service
    /// - parameter config: - configuration of the MLS group
    /// - returns: an object of type `ConversationInitBundle`
    public func joinByExternalCommit(groupInfo: [UInt8], configuration: CustomConfiguration, credentialType: MlsCredentialType) async throws -> ConversationInitBundle {
        try await self.coreCrypto.joinByExternalCommit(groupInfo: groupInfo, customConfiguration: configuration.convert(), credentialType: credentialType.convert()).convertTo()
    }

    /// This merges the commit generated by ``CoreCryptoWrapper/joinByExternalCommit``, persists the group permanently and
    /// deletes the temporary one. After merging, the group should be fully functional.
    ///
    /// - parameter conversationId: conversation identifier
    public func mergePendingGroupFromExternalCommit(conversationId: ConversationId) async throws -> [DecryptedMessage]? {
        try await self.coreCrypto.mergePendingGroupFromExternalCommit(conversationId: conversationId)
    }

    /// In case the external commit generated by ``CoreCryptoWrapper/joinByExternalCommit`` is rejected by the Delivery Service,
    /// and we want to abort this external commit once for all, we can wipe out the pending group from the keystore in
    /// order not to waste space
    ///
    /// - parameter conversationId: conversation identifier
    public func clearPendingGroupFromExternalCommit(conversationId: ConversationId) async throws {
        try await self.coreCrypto.clearPendingGroupFromExternalCommit(conversationId: conversationId)
    }

    /// Derives a new key from the group
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter keyLength: the length of the key to be derived. If the value is higher than the
    /// bounds of `u16` or the context hash * 255, an error will be thrown
    /// - returns a byte array representing the derived key
    public func exportSecretKey(conversationId: ConversationId, keyLength: UInt32) async throws -> [UInt8] {
        try await self.coreCrypto.exportSecretKey(conversationId: conversationId, keyLength: keyLength)
    }

    /// Returns all clients from group's members
    ///
    /// - parameter conversationId: conversation identifier
    /// - returns a list of `ClientId` objects
    public func getClientIds(conversationId: ConversationId) async throws -> [ClientId] {
        try await self.coreCrypto.getClientIds(conversationId: conversationId)
    }

    /// Allows ``CoreCrypto`` to act as a CSPRNG provider
    /// - parameter length: The number of bytes to be returned in the `Uint8` array
    /// - returns: A ``Uint8`` array buffer that contains ``length`` cryptographically-secure random bytes
    public func randomBytes(length: UInt32) async throws -> [UInt8] {
        try await self.coreCrypto.randomBytes(length: length)
    }

    /// Allows to reseed ``CoreCrypto``'s internal CSPRNG with a new seed.
    /// - parameter seed: **exactly 32** bytes buffer seed
    public func reseedRng(seed: [UInt8]) async throws {
        try await self.coreCrypto.reseedRng(seed: seed)
    }

    /// The commit we created has been accepted by the Delivery Service. Hence it is guaranteed
    /// to be used for the new epoch.
    /// We can now safely "merge" it (effectively apply the commit to the group) and update it
    /// in the keystore. The previous can be discarded to respect Forward Secrecy.
    ///
    /// - parameter conversationId: conversation identifier
    public func commitAccepted(conversationId: ConversationId) async throws {
        try await self.coreCrypto.commitAccepted(conversationId: conversationId)
    }

    /// Allows to remove a pending (uncommitted) proposal. Use this when backend rejects the proposal
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403 or 409. Do not use otherwise e.g. 5xx responses, timeout etc..
    ///
    /// - parameter conversation_id - the group/conversation id
    /// - parameter proposal_ref - unique proposal identifier which is present in MlsProposalBundle and
    /// returned from all operation creating a proposal
    public func clearPendingProposal(conversationId: ConversationId, proposalRef: [UInt8]) async throws {
        try await self.coreCrypto.clearPendingProposal(conversationId: conversationId, proposalRef: proposalRef)
    }

    /// Allows to remove a pending commit. Use this when backend rejects the commit
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403. Do not use otherwise e.g. 5xx responses, timeout etc..
    /// **DO NOT** use when Delivery Service responds 409, pending state will be renewed
    /// in [MlsCentral::decrypt_message]
    ///
    /// - parameter conversation_id - the group/conversation id
    public func clearPendingCommit(conversationId: ConversationId) async throws {
        try await self.coreCrypto.clearPendingCommit(conversationId: conversationId)
    }

    /// Initializes the proteus client
    public func proteusInit() async throws {
        try await self.coreCrypto.proteusInit()
    }

    /// Create a Proteus session using a prekey
    ///
    /// - parameter sessionId: ID of the Proteus session
    /// - parameter prekey: CBOR-encoded Proteus prekey of the other client
    public func proteusSessionFromPrekey(sessionId: String, prekey: [UInt8]) async throws {
        try await self.coreCrypto.proteusSessionFromPrekey(sessionId: sessionId, prekey: prekey)
    }

    /// Create a Proteus session from a handshake message
    ///
    /// - parameter sessionId: ID of the Proteus session
    /// - parameter envelope: CBOR-encoded Proteus message
    public func proteusSessionFromMessage(sessionId: String, envelope: [UInt8]) async throws -> [UInt8]{
        return try await self.coreCrypto.proteusSessionFromMessage(sessionId: sessionId, envelope: envelope)
    }

    /// Locally persists a session to the keystore
    ///
    /// - parameter sessionId: ID of the Proteus session
    public func proteusSessionSave(sessionId: String) async throws {
        try await self.coreCrypto.proteusSessionSave(sessionId: sessionId)
    }

    /// Deletes a session
    /// Note: this also deletes the persisted data within the keystore
    ///
    /// - parameter sessionId: ID of the Proteus session
    public func proteusSessionDelete(sessionId: String) async throws {
        try await self.coreCrypto.proteusSessionDelete(sessionId: sessionId)
    }

    /// Checks if a session exists
    ///
    /// - parameter sessionId: ID of the Proteus session
    public func proteusSessionExists(sessionId: String) async throws -> Bool {
        try await self.coreCrypto.proteusSessionExists(sessionId: sessionId)
    }

    /// Decrypt an incoming message for an existing Proteus session
    ///
    /// - parameter sessionId: ID of the Proteus session
    /// - parameter ciphertext: CBOR encoded, encrypted proteus message
    /// - returns: The decrypted payload contained within the message
    public func proteusDecrypt(sessionId: String, ciphertext: [UInt8]) async throws -> [UInt8] {
        try await self.coreCrypto.proteusDecrypt(sessionId: sessionId, ciphertext: ciphertext)
    }

    /// Encrypt a message for a given Proteus session
    ///
    /// - parameter sessionId: ID of the Proteus session
    /// - parameter plaintext: payload to encrypt
    /// - returns: The CBOR-serialized encrypted message
    public func proteusEncrypt(sessionId: String, plaintext: [UInt8]) async throws -> [UInt8] {
        try await self.coreCrypto.proteusEncrypt(sessionId: sessionId, plaintext: plaintext)
    }

    /// Batch encryption for proteus messages
    /// This is used to minimize FFI roundtrips when used in the context of a multi-client session (i.e. conversation)
    ///
    /// - parameter sessions: List of Proteus session IDs to encrypt the message for
    /// - parameter plaintext: payload to encrypt
    /// - returns: A map indexed by each session ID and the corresponding CBOR-serialized encrypted message for this session
    public func proteusEncryptBatched(sessions: [String], plaintext: [UInt8]) async throws -> [String: [UInt8]] {
        try await self.coreCrypto.proteusEncryptBatched(sessionId: sessions, plaintext: plaintext)
    }

    /// Creates a new prekey with the requested ID.
    ///
    /// - parameter prekeyId: ID of the PreKey to generate
    /// - returns: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
    public func proteusNewPrekey(prekeyId: UInt16) async throws -> [UInt8] {
        try await self.coreCrypto.proteusNewPrekey(prekeyId: prekeyId)
    }

    /// Creates a new prekey with an automatically incremented ID.
    ///
    /// - returns: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
    public func proteusNewPrekeyAuto() async throws -> ProteusAutoPrekeyBundle {
        try await self.coreCrypto.proteusNewPrekeyAuto().convertTo()
    }

    /// - returns: A CBOR-serialized verison of the PreKeyBundle associated to the last resort prekey ID
    public func proteusLastResortPrekey() async throws -> [UInt8] {
        try await self.coreCrypto.proteusLastResortPrekey()
    }

    /// - returns: The ID of the Proteus last resort PreKey
    public func proteusLastResortPrekeyId() throws -> UInt16 {
        try self.coreCrypto.proteusLastResortPrekeyId()
    }

    /// Note: When called, this resets the last error code to 0
    ///
    /// - returns: The last-occured Proteus error code.
    public func proteusLastErrorCode() -> UInt32 {
        try self.coreCrypto.proteusLastErrorCode()
    }


    /// Proteus public key fingerprint
    /// It's basically the public key encoded as an hex string
    ///
    /// - returns: Hex-encoded public key string
    public func proteusFingerprint() async throws -> String {
        try await self.coreCrypto.proteusFingerprint()
    }

    /// Proteus session local fingerprint
    ///
    /// - parameter sessionId: ID of the Proteus session
    /// - returns: Hex-encoded public key string
    public func proteusFingerprintLocal(sessionId: String) async throws -> String {
        try await self.coreCrypto.proteusFingerprintLocal(sessionId: sessionId)
    }

    /// Proteus session remote fingerprint
    ///
    /// - parameter sessionId: ID of the Proteus session
    /// - returns: Hex-encoded public key string
    public func proteusFingerprintRemote(sessionId: String) async throws -> String {
        try await self.coreCrypto.proteusFingerprintRemote(sessionId: sessionId)
    }

    /// Hex-encoded fingerprint of the given prekey
    ///
    /// - parameter prekey: the prekey bundle to get the fingerprint from
    /// - returns: Hex-encoded public key string
    public func proteusFingerprintPrekeybundle(prekey: [UInt8]) async throws -> String {
        try await self.coreCrypto.proteusFingerprintPrekeybundle(prekey: prekey)
    }

    /// Imports all the data stored by Cryptobox into the CoreCrypto keystore
    ///
    /// - parameter path: Path to the folder where Cryptobox things are stored
    public func proteusCryptoboxMigrate(path: String) async throws {
        try await self.coreCrypto.proteusCryptoboxMigrate(path: path)
    }

    /// Creates an enrollment instance with private key material you can use in order to fetch
    /// a new x509 certificate from the acme server.
    ///
    /// - parameter clientId: client identifier with user b64Url encoded & clientId hex encoded e.g. `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ:6add501bacd1d90e@example.com`
    /// - parameter displayName: human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// - parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - parameter expiryDays: generated x509 certificate expiry
    /// - parameter ciphersuite: For generating signing key material.
    /// - returns: The new ``CoreCryptoSwift.WireE2eIdentity`` object
    public func e2eiNewEnrollment(clientId: String, displayName: String, handle: String, expiryDays: UInt32, ciphersuite: UInt16) async throws -> CoreCryptoSwift.WireE2eIdentity {
        return try await self.coreCrypto.e2eiNewEnrollment(clientId: clientId, displayName: displayName, handle: handle, expiryDays: expiryDays, ciphersuite: ciphersuite)
    }

    /// Generates an E2EI enrollment instance for a "regular" client (with a Basic credential) willing to migrate to E2EI.
    /// Once the enrollment is finished, use the instance in ``CoreCrypto/e2eiRotateAll`` to do the rotation.
    ///
    /// - parameter clientId: client identifier with user b64Url encoded & clientId hex encoded e.g. `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ:6add501bacd1d90e@example.com`
    /// - parameter displayName: human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// - parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - parameter expiryDays: generated x509 certificate expiry
    /// - parameter ciphersuite: For generating signing key material.
    /// - returns: The new ``CoreCryptoSwift.WireE2eIdentity`` object
    public func e2eiNewActivationEnrollment(clientId: String, displayName: String, handle: String, expiryDays: UInt32, ciphersuite: UInt16) async throws -> CoreCryptoSwift.WireE2eIdentity {
        return try await self.coreCrypto.e2eiNewActivationEnrollment(clientId: clientId, displayName: displayName, handle: handle, expiryDays: expiryDays, ciphersuite: ciphersuite)
    }

    /// Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)having to change/rotate
    /// their credential, either because the former one is expired or it has been revoked. It lets you change
    /// the DisplayName or the handle if you need to. Once the enrollment is finished, use the instance in ``CoreCrypto/e2eiRotateAll`` to do the rotation.
    ///
    /// - parameter clientId: client identifier with user b64Url encoded & clientId hex encoded e.g. `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ:6add501bacd1d90e@example.com`
    /// - parameter expiryDays: generated x509 certificate expiry
    /// - parameter ciphersuite: For generating signing key material.
    /// - parameter displayName: human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// - parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - returns: The new ``CoreCryptoSwift.WireE2eIdentity`` object
    public func e2eiNewRotateEnrollment(clientId: String, expiryDays: UInt32, ciphersuite: UInt16, displayName: String? = nil, handle: String? = nil) async throws -> CoreCryptoSwift.WireE2eIdentity {
        return try await self.coreCrypto.e2eiNewRotateEnrollment(clientId: clientId, expiryDays: expiryDays, ciphersuite: ciphersuite, displayName: displayName, handle: handle)
    }

    /// Use this method to initialize end-to-end identity when a client signs up and the grace period is already expired ; that means he cannot initialize with a Basic credential
    ///
    /// - parameter e2ei: the enrollment instance used to fetch the certificates
    /// - parameter certificateChain: the raw response from ACME server
    public func e2eiMlsInitOnly(enrollment: CoreCryptoSwift.WireE2eIdentity, certificateChain: String) async throws {
        return try await self.coreCrypto.e2eiMlsInitOnly(enrollment: enrollment, certificateChain: certificateChain)
    }

    /// Creates a commit in all local conversations for changing the credential. Requires first having enrolled a new
    /// X509 certificate with either ``CoreCrypto/e2eiNewActivationEnrollment`` or ``CoreCrypto/e2eiNewRotateEnrollment``
    ///
    /// - parameter e2ei: the enrollment instance used to fetch the certificates
    /// - parameter certificateChain: the raw response from ACME server
    /// - parameter newKeyPackageCount: number of KeyPackages with new identity to generate
    public func e2eiRotateAll(enrollment: CoreCryptoSwift.WireE2eIdentity, certificateChain: String, newKeyPackageCount: UInt32) async throws -> RotateBundle {
        return try await self.coreCrypto.e2eiRotateAll(enrollment: enrollment, certificateChain: certificateChain, newKeyPackageCount: newKeyPackageCount)
    }

    /// Allows persisting an active enrollment (for example while redirecting the user during OAuth) in order to resume
    /// it later with [MlsCentral::e2eiEnrollmentStashPop]
    ///
    /// - parameter e2ei: the enrollment instance to persist
    /// - returns: a handle to fetch the enrollment later with [MlsCentral::e2eiEnrollmentStashPop]
    public func e2eiEnrollmentStash(enrollment: CoreCryptoSwift.WireE2eIdentity) async throws -> [UInt8] {
        return try await self.coreCrypto.e2eiEnrollmentStash(enrollment: enrollment)
    }

    /// Fetches the persisted enrollment and deletes it from the keystore
    ///
    /// - parameter handle: returned by [MlsCentral::e2eiEnrollmentStash]
    /// - returns: the persisted enrollment instance
    public func e2eiEnrollmentStashPop(handle: [UInt8]) async throws -> CoreCryptoSwift.WireE2eIdentity {
        return try await self.coreCrypto.e2eiEnrollmentStashPop(handle: handle)
    }

    /// Indicates when to mark a conversation as degraded i.e. when not all its members have a X509.
    /// Credential generated by Wire's end-to-end identity enrollment
    ///
    /// - parameter conversationId: the Group's ID
    /// - returns: true if all the members have valid X509 credentials
    public func e2eiIsDegraded(conversationId: ConversationId) async throws -> Bool {
        return try await self.coreCrypto.e2eiIsDegraded(conversationId: conversationId)
    }

    /// - returns: The CoreCrypto version
    public static func version() -> String {
        return CoreCryptoSwift.version()
    }
}
