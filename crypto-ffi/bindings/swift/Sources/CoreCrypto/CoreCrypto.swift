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
        return RotateBundle(commits: self.commits, newKeyPackages: self.newKeyPackages, keyPackageRefsToRemove: self.keyPackageRefsToRemove, crlNewDistributionPoints: self.crlNewDistributionPoints)
    }
}

extension CoreCryptoSwift.CrlRegistration {
    func convertTo() -> CRLRegistration {
        return CRLRegistration(dirty: self.dirty, expiration: self.expiration)
    }
}

extension CoreCryptoSwift.MemberAddedMessages {
    func convertTo() -> MemberAddedMessages {
        return MemberAddedMessages(commit: self.commit, welcome: self.welcome, groupInfo: self.groupInfo.convertTo(), crlNewDistributionPoints: self.crlNewDistributionPoints)
    }
}

extension CoreCryptoSwift.WelcomeBundle {
    func convertTo() -> WelcomeBundle {
        return WelcomeBundle(id: self.id, crlNewDistributionPoints: self.crlNewDistributionPoints)
    }
}

extension CoreCryptoSwift.ConversationInitBundle {
    func convertTo() -> ConversationInitBundle {
        return ConversationInitBundle(conversationId: self.conversationId, commit: self.commit, groupInfo: self.groupInfo.convertTo(), crlNewDistributionPoints: self.crlNewDistributionPoints)
    }
}

extension CoreCryptoSwift.DecryptedMessage {
    func convertTo() -> DecryptedMessage {
        return DecryptedMessage(
            message: self.message,
            proposals: self.proposals.map({ (bundle) -> ProposalBundle in return bundle.convertTo() }),
            isActive: self.isActive,
            commitDelay: self.commitDelay,
            senderClientId: self.senderClientId,
            hasEpochChanged: self.hasEpochChanged,
            identity: self.identity?.convertTo(),
            bufferedMessages: self.bufferedMessages.map({ (bm) -> BufferedDecryptedMessage in return bm.convertTo() }),
            crlNewDistributionPoints: self.crlNewDistributionPoints
        )
    }
}

extension CoreCryptoSwift.BufferedDecryptedMessage {
    func convertTo() -> BufferedDecryptedMessage {
        return BufferedDecryptedMessage(
            message: self.message,
            proposals: self.proposals.map({ (bundle) -> ProposalBundle in return bundle.convertTo() }),
            isActive: self.isActive,
            commitDelay: self.commitDelay,
            senderClientId: self.senderClientId,
            hasEpochChanged: self.hasEpochChanged,
            identity: self.identity?.convertTo(),
            crlNewDistributionPoints: self.crlNewDistributionPoints
        )
    }
}

extension CoreCryptoSwift.WireIdentity {
    func convertTo() -> WireIdentity {
        return WireIdentity(clientId: self.clientId, handle: self.handle, displayName: self.displayName, domain: self.domain)
    }
}

extension CoreCryptoSwift.ProposalBundle {
    func convertTo() -> ProposalBundle {
        return ProposalBundle(proposal: self.proposal, proposalRef: self.proposalRef, crlNewDistributionPoints: self.crlNewDistributionPoints)
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
        return CoreCryptoSwift.ConversationConfiguration(ciphersuite: self.ciphersuite, externalSenders: self.externalSenders, custom: self.custom.convert())
    }

    /// Conversation ciphersuite
    public var ciphersuite: UInt16
    /// List of client IDs that are allowed to be external senders of commits
    public var externalSenders: [[UInt8]]
    /// Implementation specific configuration
    public var custom: CustomConfiguration

    public init(ciphersuite: UInt16, externalSenders: [[UInt8]], custom: CustomConfiguration) {
        self.ciphersuite = ciphersuite
        self.externalSenders = externalSenders
        self.custom = custom
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

/// Data shape for the returned MLS commit & welcome message tuple upon adding clients to a conversation
public struct MemberAddedMessages: ConvertToInner {
    typealias Inner = CoreCryptoSwift.MemberAddedMessages
    /// TLS-serialized MLS Welcome message that needs to be fanned out to the clients newly added to the conversation
    public var commit: [UInt8]
    /// TLS-serialized MLS Commit that needs to be fanned out to other (existing) members of the conversation
    public var welcome: [UInt8]
    /// The current group state
    public var groupInfo: GroupInfoBundle
    /// New CRL distribution points that appeared by the introduction of a new credential
    public var crlNewDistributionPoints: [String]?

    public init(commit: [UInt8], welcome: [UInt8], groupInfo: GroupInfoBundle, crlNewDistributionPoints: [String]?) {
        self.commit = commit
        self.welcome = welcome
        self.groupInfo = groupInfo
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }

    func convert() -> Inner {
        return CoreCryptoSwift.MemberAddedMessages(commit: self.commit, welcome: self.welcome, groupInfo: self.groupInfo.convert(), crlNewDistributionPoints: self.crlNewDistributionPoints)
    }
}

/// Contains everything client needs to know after decrypting an (encrypted) Welcome message
public struct WelcomeBundle: ConvertToInner {
    typealias Inner = CoreCryptoSwift.WelcomeBundle
    /// MLS Group Id
    public var id: ConversationId
    /// New CRL distribution points that appeared by the introduction of a new credential
    public var crlNewDistributionPoints: [String]?

    public init(id: ConversationId, crlNewDistributionPoints: [String]?) {
        self.id = id
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }

    func convert() -> Inner {
        return CoreCryptoSwift.MemberAddedMessages(id: self.id, crlNewDistributionPoints: self.crlNewDistributionPoints)
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
    /// Only set when the decrypted message is a commit.
    /// Contains buffered messages for next epoch which were received before the commit creating the epoch
    /// because the DS did not fan them out in order.
    public var bufferedMessages: [BufferedDecryptedMessage]?
    /// New CRL distribution points that appeared by the introduction of a new credential
    public var crlNewDistributionPoints: [String]?

    public init(message: [UInt8]?, proposals: [ProposalBundle], isActive: Bool, commitDelay: UInt64?, senderClientId: ClientId?, hasEpochChanged: Bool, identity: WireIdentity?, bufferedMessages: [BufferedDecryptedMessage]?, crlNewDistributionPoints: [String]?) {
        self.message = message
        self.proposals = proposals
        self.isActive = isActive
        self.commitDelay = commitDelay
        self.senderClientId = senderClientId
        self.hasEpochChanged = hasEpochChanged
        self.identity = identity
        self.bufferedMessages = bufferedMessages
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }

    func convert() -> Inner {
        return CoreCryptoSwift.DecryptedMessage(
            message: self.message,
            proposals: self.proposals.map({ (bundle) -> CoreCryptoSwift.ProposalBundle in bundle.convert() }),
            isActive: self.isActive,
            commitDelay: self.commitDelay,
            senderClientId: self.senderClientId,
            hasEpochChanged: self.hasEpochChanged,
            identity: self.identity?.convert(),
            bufferedMessages: self.bufferedMessages.map({ (bm) -> CoreCryptoSwift.DecryptedMessage in bm.convert() }),
            crlNewDistributionPoints: self.crlNewDistributionPoints
        )
    }
}

/// Type safe recursion of ```DecryptedMessage```
public struct BufferedDecryptedMessage: ConvertToInner {
    typealias Inner = CoreCryptoSwift.BufferedDecryptedMessage
    /// see ```DecryptedMessage.message```
    public var message: [UInt8]?
    /// see ```DecryptedMessage.proposals```
    public var proposals: [ProposalBundle]
    /// see ```DecryptedMessage.isActive```
    public var isActive: Bool
    /// see ```DecryptedMessage.commitDelay```
    public var commitDelay: UInt64?
    /// see ```DecryptedMessage.senderClientId```
    public var senderClientId: ClientId?
    /// see ```DecryptedMessage.hasEpochChanged```
    public var hasEpochChanged: Bool
    /// see ```DecryptedMessage.identity```
    public var identity: WireIdentity?
    /// see ```DecryptedMessage.crlNewDistributionPoints```
    public var crlNewDistributionPoints: [String]?


    public init(message: [UInt8]?, proposals: [ProposalBundle], isActive: Bool, commitDelay: UInt64?, senderClientId: ClientId?, hasEpochChanged: Bool, identity: WireIdentity?, crlNewDistributionPoints: [String]?) {
        self.message = message
        self.proposals = proposals
        self.isActive = isActive
        self.commitDelay = commitDelay
        self.senderClientId = senderClientId
        self.hasEpochChanged = hasEpochChanged
        self.identity = identity
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }

    func convert() -> Inner {
        return CoreCryptoSwift.BufferedDecryptedMessage(
            message: self.message,
            proposals: self.proposals.map({ (bundle) -> CoreCryptoSwift.ProposalBundle in bundle.convert() }),
            isActive: self.isActive,
            commitDelay: self.commitDelay,
            senderClientId: self.senderClientId,
            hasEpochChanged: self.hasEpochChanged,
            identity: self.identity?.convert(),
            crlNewDistributionPoints: self.crlNewDistributionPoints
        )
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
    /// Status of the Credential at the moment T when this object is created
    public var status: DeviceStatus
    /// MLS thumbprint
    public var thumbprint: String

    public init(clientId: String, handle: String, displayName: String, domain: String, status: DeviceStatus, thumbprint: String) {
        self.clientId = clientId
        self.handle = handle
        self.displayName = displayName
        self.domain = domain
        self.status = status
        self.thumbprint = thumbprint
    }

    func convert() -> Inner {
        return CoreCryptoSwift.WireIdentity(clientId: self.clientId, handle: self.handle, displayName: self.displayName, domain: self.domain, status: self.status.convert(), thumbprint: self.thumbprint)
    }
}

/// Indicates the standalone status of a device Credential in a MLS group at a moment T. This does not represent the
/// states where a device is not using MLS or is not using end-to-end identity
public enum DeviceStatus: ConvertToInner {
    typealias Inner = CoreCryptoSwift.DeviceStatus

    case valid
    case expired
    case revoked
}

private extension DeviceStatus {
    func convert() -> Inner {
        switch self {
        case .valid:
            return CoreCryptoSwift.DeviceStatus.valid
        case .expired:
            return CoreCryptoSwift.DeviceStatus.expired
        case .revoked:
            return CoreCryptoSwift.DeviceStatus.revoked
        }
    }
}

/// Result of a created commit
public struct ProposalBundle: ConvertToInner {
    typealias Inner = CoreCryptoSwift.ProposalBundle
    /// The proposal message
    public var proposal: [UInt8]
    /// An identifier of the proposal to rollback it later if required
    public var proposalRef: [UInt8]
    /// New CRL distribution points that appeared by the introduction of a new credential
    public var crlNewDistributionPoints: [String]?

    public init(proposal: [UInt8], proposalRef: [UInt8], crlNewDistributionPoints: [String]?) {
        self.proposal = proposal
        self.proposalRef = proposalRef
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }

    func convert() -> Inner {
        return CoreCryptoSwift.ProposalBundle(proposal: self.proposal, proposalRef: self.proposalRef, crlNewDistributionPoints: self.crlNewDistributionPoints)
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
    /// New CRL distribution points that appeared by the introduction of a new credential
    public var crlNewDistributionPoints: [String]?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(conversationId: ConversationId, commit: [UInt8], groupInfo: GroupInfoBundle, crlNewDistributionPoints: [String]?) {
        self.conversationId = conversationId
        self.commit = commit
        self.groupInfo = groupInfo
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }

    func convert() -> Inner {
        return CoreCryptoSwift.ConversationInitBundle(conversationId: self.conversationId, commit: self.commit, groupInfo: self.groupInfo.convert(), crlNewDistributionPoints: self.crlNewDistributionPoints)
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
    typealias Inner = CoreCryptoSwift.RotateBundle

    /// An Update commit for each conversation
    public var commits: [String : CommitBundle]
    /// Fresh KeyPackages with the new Credential
    public var newKeyPackages: [[UInt8]]
    /// All the now deprecated KeyPackages. Once deleted remotely, delete them locally with ``CoreCrypto/deleteKeypackages``
    public var keyPackageRefsToRemove: [[UInt8]]
    /// New CRL distribution points that appeared by the introduction of a new credential
    public var crlNewDistributionPoints: [String]?

    public init(commits: [String : CommitBundle], newKeyPackages: [[UInt8]], keyPackageRefsToRemove: [[UInt8]], crlNewDistributionPoints: [String]?) {
        self.commits = commits
        self.newKeyPackages = newKeyPackages
        self.keyPackageRefsToRemove = keyPackageRefsToRemove
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }

    func convert() -> Inner {
        return CoreCryptoSwift.RotateBundle(commits: self.commits, newKeyPackages: self.newKeyPackages, keyPackageRefsToRemove: self.keyPackageRefsToRemove, crlNewDistributionPoints: self.crlNewDistributionPoints)
    }
}

/// Supporting struct for CRL registration result
public struct CRLRegistration: ConvertToInner {
    /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
    public var dirty: Bool
    /// Optional expiration timestamp
    public var expiration: UInt64?

    public init(dirty: Bool, expiration: UInt64?) {
        self.dirty = dirty
        self.expiration = expiration
    }
    typealias Inner = CoreCryptoSwift.CrlRegistration

    func convert() -> Inner {
        return CoreCryptoSwift.CrlRegistration(dirty: self.dirty, expiration: self.expiration)
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
    /// - parameter ciphersuites: supported by this client
    /// - parameter nbKeyPackage: number of initial KeyPackage to create when initializing the client
    ///
    /// # Notes #
    /// 1. ``clientId`` should stay consistent as it will be verified against the stored signature & identity to validate the persisted credential
    /// 2. ``key`` should be appropriately stored in a secure location (i.e. WebCrypto private key storage)
    ///
    public init(path: String, key: String, clientId: ClientId, ciphersuites: Array<UInt16>, nbKeyPackage: UInt32 = 100) async throws {
        self.coreCrypto = try await CoreCrypto(path: path, key: key, clientId: clientId, ciphersuites: ciphersuites, nbKeyPackage: nbKeyPackage)
    }

    /// Almost identical to ```CoreCrypto/init``` but allows a 2 phase initialization of MLS.First, calling this will
    /// set up the keystore and will allow generating proteus prekeys.Then, those keys can be traded for a clientId.
    /// Use this clientId to initialize MLS with ```CoreCrypto/mlsInit```.
    public static func deferredInit(path: String, key: String, ciphersuites: Array<UInt16>, nbKeyPackage: UInt32 = 100) async throws -> CoreCrypto {
        try await CoreCrypto.deferredInit(path: path, key: key, ciphersuites: ciphersuites, nbKeyPackage: nbKeyPackage)
    }

    /// Use this after ```CoreCrypto/deferredInit``` when you have a clientId. It initializes MLS.
    ///
    /// - parameter clientId: client identifier
    /// - parameter nbKeyPackage: number of initial KeyPackage to create when initializing the client
    public func mlsInit(clientId: ClientId, ciphersuites: Array<UInt16>, nbKeyPackage: UInt32 = 100) async throws {
        try await self.coreCrypto.mlsInit(clientId: clientId, ciphersuites: ciphersuites, nbKeyPackage: nbKeyPackage)
    }

    /// Generates a MLS KeyPair/CredentialBundle with a temporary, random client ID.
    /// This method is designed to be used in conjunction with ```CoreCrypto/mlsInitWithClientId``` and represents the first step in this process
    ///
    /// - returns: a list of random ClientId to use in ```CoreCrypto/mlsInitWithClientId```
    public func mlsGenerateKeypairs(ciphersuites: Array<UInt16>) async throws -> [[ClientId]] {
        try await self.coreCrypto.mlsGenerateKeypairs(ciphersuites: ciphersuites)
    }

    /// Updates the current temporary Client ID with the newly provided one. This is the second step in the externally-generated clients process
    ///
    /// Important: This is designed to be called after ```CoreCrypto/mlsGenerateKeypairs```
    ///
    /// - parameter clientId: The newly allocated Client ID from the MLS Authentication Service
    /// - parameter tmpClientIds: The random clientId you obtained in ```CoreCrypto/mlsGenerateKeypairs```, for authentication purposes
    /// - parameter ciphersuites: To initialize the Client with
    public func mlsInitWithClientId(clientId: ClientId, tmpClientIds: [[ClientId]], ciphersuites: Array<UInt16>) async throws {
        try await self.coreCrypto.mlsInitWithClientId(clientId: clientId, tmpClientIds: tmpClientIds, ciphersuites: ciphersuites)
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
    ///
    /// Important: you have to catch the error "OrphanWelcome", ignore it and then try
    /// to join this group with an external commit.
    ///
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
    /// - parameter keyPackages: of the clients to add
    /// - returns: A ``CommitBundle`` byte array to fan out to the Delivery Service
    public func addClientsToConversation(conversationId: ConversationId, keyPackages: [[UInt8]]) async throws -> MemberAddedMessages {
        return try await self.coreCrypto.addClientsToConversation(conversationId: conversationId, keyPackages: keyPackages).convertTo()
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
    /// Note: you should catch & ignore the following error:
    /// - `DuplicateMessage`
    /// - `UnmergedPendingGroup`
    /// - `BufferedFutureMessage`
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
    /// - returns the messages from current epoch which had been buffered, if any
    public func mergePendingGroupFromExternalCommit(conversationId: ConversationId) async throws -> [BufferedDecryptedMessage]? {
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
    /// - returns the messages from current epoch which had been buffered, if any
    public func commitAccepted(conversationId: ConversationId) async throws -> [BufferedDecryptedMessage]? {
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
    /// - parameter clientId: client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
    /// - parameter displayName: human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// - parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - parameter expirySec: generated x509 certificate expiry
    /// - parameter ciphersuite: For generating signing key material.
    /// - parameter team: name of the Wire team a user belongs to
    /// - returns: The new ``CoreCryptoSwift.WireE2eIdentity`` object
    public func e2eiNewEnrollment(clientId: String, displayName: String, handle: String, expirySec: UInt32, ciphersuite: UInt16, handle: String? = nil) async throws -> E2eiEnrollment {
        return try await self.coreCrypto.e2eiNewEnrollment(clientId: clientId, displayName: displayName, handle: handle, team: team, expirySec: expirySec, ciphersuite: ciphersuite).lift()
    }

    /// Generates an E2EI enrollment instance for a "regular" client (with a Basic credential) willing to migrate to E2EI.
    /// Once the enrollment is finished, use the instance in ``CoreCrypto/e2eiRotateAll`` to do the rotation.
    ///
    /// - parameter displayName: human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// - parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - parameter expirySec: generated x509 certificate expiry
    /// - parameter ciphersuite: For generating signing key material.
    /// - parameter team: name of the Wire team a user belongs to
    /// - returns: The new ``CoreCryptoSwift.WireE2eIdentity`` object
    public func e2eiNewActivationEnrollment(displayName: String, handle: String, expirySec: UInt32, ciphersuite: UInt16, handle: String? = nil) async throws -> E2eiEnrollment {
        return try await self.coreCrypto.e2eiNewActivationEnrollment(displayName: displayName, handle: handle, team: team, expirySec: expirySec, ciphersuite: ciphersuite).lift()
    }

    /// Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)having to change/rotate
    /// their credential, either because the former one is expired or it has been revoked. It lets you change
    /// the DisplayName or the handle if you need to. Once the enrollment is finished, use the instance in ``CoreCrypto/e2eiRotateAll`` to do the rotation.
    ///
    /// - parameter expirySec: generated x509 certificate expiry
    /// - parameter ciphersuite: For generating signing key material.
    /// - parameter displayName: human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// - parameter handle: user handle e.g. `alice.smith.qa@example.com`
    /// - parameter team: name of the Wire team a user belongs to
    /// - returns: The new ``CoreCryptoSwift.WireE2eIdentity`` object
    public func e2eiNewRotateEnrollment(expirySec: UInt32, ciphersuite: UInt16, displayName: String? = nil, handle: String? = nil, team: String? = nil) async throws -> E2eiEnrollment {
        return try await self.coreCrypto.e2eiNewRotateEnrollment(expirySec: expirySec, ciphersuite: ciphersuite, displayName: displayName, handle: handle, team: team).lift()
    }

    /// Use this method to initialize end-to-end identity when a client signs up and the grace period is already expired ; that means he cannot initialize with a Basic credential
    ///
    /// - parameter e2ei: the enrollment instance used to fetch the certificates
    /// - parameter certificateChain: the raw response from ACME server
    /// - parameter nbKeyPackage: number of initial KeyPackage to create when initializing the client
    public func e2eiMlsInitOnly(enrollment: E2eiEnrollment, certificateChain: String, nbKeyPackage: UInt32 = 100) async throws {
        return try await self.coreCrypto.e2eiMlsInitOnly(enrollment: enrollment.lower(), certificateChain: certificateChain, nbKeyPackage: nbKeyPackage)
    }

    /// Registers a Root Trust Anchor CA for the use in E2EI processing.
    ///
    /// Please note that without a Root Trust Anchor, all validations *will* fail;
    /// So this is the first step to perform after initializing your E2EI client
    ///
    /// - parameter trustAnchorPEM: PEM certificate to anchor as a Trust Root
    public func e2eiRegisterAcmeCA(trustAnchorPEM: String) async throws {
        return try await self.coreCrypto.e2eiRegisterAcmeCa(trustAnchorPem: trustAnchorPEM)
    }

    /// Registers an Intermediate CA for the use in E2EI processing.
    ///
    /// Please note that a Root Trust Anchor CA is needed to validate Intermediate CAs;
    /// You **need** to have a Root CA registered before calling this
    ///
    /// - parameter cert_pem: PEM certificate to register as an Intermediate CA
    public func e2eiRegisterIntermediateCA(certPEM: String) async throws -> [string]? {
        return try await self.coreCrypto.e2eiRegisterIntermediateCa(certPem: certPEM)
    }

    /// Registers a CRL for the use in E2EI processing.
    ///
    /// Please note that a Root Trust Anchor CA is needed to validate CRLs;
    /// You **need** to have a Root CA registered before calling this
    ///
    /// - parameter: crlDP: CRL Distribution Point; Basically the URL you fetched it from
    /// - parameter crlDER: DER representation of the CRL
    /// - returns: A [CrlRegistration] with the dirty state of the new CRL (see struct) and its expiration timestamp
    public func e2eiRegisterCRL(crlDP: String, crlDER: [UInt8]) async throws -> CRLRegistration {
        return try await self.coreCrypto.e2eiRegisterCrl(crlDp: crlDP, crlDer: crlDER).convertTo()
    }


    /// Creates a commit in all local conversations for changing the credential. Requires first having enrolled a new
    /// X509 certificate with either ``CoreCrypto/e2eiNewActivationEnrollment`` or ``CoreCrypto/e2eiNewRotateEnrollment``
    ///
    /// - parameter e2ei: the enrollment instance used to fetch the certificates
    /// - parameter certificateChain: the raw response from ACME server
    /// - parameter newKeyPackageCount: number of KeyPackages with new identity to generate
    public func e2eiRotateAll(enrollment: E2eiEnrollment, certificateChain: String, newKeyPackageCount: UInt32) async throws -> RotateBundle {
        return try await self.coreCrypto.e2eiRotateAll(enrollment: enrollment.lower(), certificateChain: certificateChain, newKeyPackageCount: newKeyPackageCount)
    }

    /// Allows persisting an active enrollment (for example while redirecting the user during OAuth) in order to resume
    /// it later with [MlsCentral::e2eiEnrollmentStashPop]
    ///
    /// - parameter e2ei: the enrollment instance to persist
    /// - returns: a handle to fetch the enrollment later with [MlsCentral::e2eiEnrollmentStashPop]
    public func e2eiEnrollmentStash(enrollment: E2eiEnrollment) async throws -> [UInt8] {
        return try await self.coreCrypto.e2eiEnrollmentStash(enrollment: enrollment.lower())
    }

    /// Fetches the persisted enrollment and deletes it from the keystore
    ///
    /// - parameter handle: returned by [MlsCentral::e2eiEnrollmentStash]
    /// - returns: the persisted enrollment instance
    public func e2eiEnrollmentStashPop(handle: [UInt8]) async throws -> E2eiEnrollment {
        return try await self.coreCrypto.e2eiEnrollmentStashPop(handle: handle).lift()
    }

    /// Indicates when to mark a conversation as not verified i.e. when not all its members have a X509.
    /// Credential generated by Wire's end-to-end identity enrollment
    ///
    /// - parameter conversationId: the Group's ID
    /// - returns: the conversation state given current members
    public func e2eiConversationState(conversationId: ConversationId) async throws -> E2eiConversationState {
        return try await self.coreCrypto.e2eiConversationState(conversationId: conversationId)
    }

    /// Returns true when end-to-end-identity is enabled for the given Ciphersuite
    ///
    /// - parameter ciphersuite: of the credential to check
    /// - returns: true end-to-end identity is enabled for the given ciphersuite
    public func e2eiIsEnabled(ciphersuite: UInt16) async throws -> Bool {
        return try await self.coreCrypto.e2eiIsEnabled(ciphersuite: ciphersuite)
    }

    /// From a given conversation, get the identity of the members supplied. Identity is only present for members with a
    /// Certificate Credential (after turning on end-to-end identity).
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter deviceIds: identifiers of the user
    /// - returns: identities or if no member has a x509 certificate, it will return an empty List
    public func getDeviceIdentities(conversationId: ConversationId, deviceIds: [ClientId]) async throws -> [WireIdentity] {
        return try await self.coreCrypto.getDeviceIdentities(conversationId: conversationId, deviceIds: deviceIds)
    }

    /// From a given conversation, get the identity of the users (device holders) supplied.
    /// Identity is only present for devices with a Certificate Credential (after turning on end-to-end identity).
    /// If no member has a x509 certificate, it will return an empty Vec.
    ///
    /// - parameter conversationId: conversation identifier
    /// - parameter userIds: user identifiers hyphenated UUIDv4 e.g. 'bd4c7053-1c5a-4020-9559-cd7bf7961954'
    /// - returns: a Map with all the identities for a given users. Consumers are then recommended to reduce those identities to determine the actual status of a user.
    public func getUserIdentities(conversationId: ConversationId, userIds: [String]) async throws -> [String: [WireIdentity]] {
        return try await self.coreCrypto.getUserIdentities(conversationId: conversationId, userIds: userIds)
    }

    /// Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei turned on or not
    /// before joining it.
    ///
    /// - parameter groupInfo: a TLS encoded `GroupInfo` fetched from the Delivery Service
    /// - parameter credentialType: kind of Credential to check usage of. Defaults to X509 for now as no other value will give any result.
    public func getCredentialInUse(groupInfo: [UInt8], credentialType: MlsCredentialType) async throws -> E2eiConversationState {
        try await self.coreCrypto.getCredentialInUse(groupInfo: groupInfo, credentialType: credentialType.convert()).convertTo()
    }

    /// - returns: The CoreCrypto version
    public static func version() -> String {
        return CoreCryptoSwift.version()
    }
}

/// Instance for enrolling a certificate with the ACME server
public struct E2eiEnrollment: ConvertToInner {
    public var delegate: CoreCryptoSwift.WireE2eIdentity

    public init(delegate: CoreCryptoSwift.WireE2eIdentity) {
        self.delegate = delegate
    }
    typealias Inner = CoreCryptoSwift.WireE2eIdentity

    func lower() -> Inner {
        return CoreCryptoSwift.WireE2eIdentity(delegate: self.delegate)
    }

    /// Parses the response from `GET /acme/{provisioner-name}/directory`.
    /// Use this ``AcmeDirectory`` in the next step to fetch the first nonce from the acme server. Use
    /// ``AcmeDirectory/newNonce``.
    /// - Parameter directory: HTTP response body
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
    public func directoryResponse(directory: JsonRawData) async throws -> AcmeDirectory {
        return try await self.delegate.directoryResponse(directory: directory)
    }

    /// For creating a new acme account. This returns a signed JWS-alike request body to send to `POST /acme/{provisioner-name}/new-account`.
    /// - Parameter previousNonce: you got from calling HEAD ``AcmeDirectory/newNonce``
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
    public func newAccountRequest(previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.newAccountRequest(previousNonce: previousNonce)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-account`.
    /// - Parameter account: HTTP response body
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
    public func newAccountResponse(account: JsonRawData) async throws {
        return try await self.delegate.newAccountResponse(account: account)
    }

    /// Creates a new acme order for the handle (userId + display name) and the clientId.
    /// - Parameter previousNonce: `replay-nonce` response header from `POST /acme/{provisioner-name}/new-account`
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
    public func newOrderRequest(previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.newOrderRequest(previousNonce: previousNonce)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-order`.
    /// - Parameter account: HTTP response body
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
    public func newOrderResponse(order: JsonRawData) async throws -> NewAcmeOrder {
        return try await self.delegate.newOrderResponse(order: order)
    }

    /// Creates a new authorization request.
    /// - Parameter url: one of the URL in new order's authorizations (use ``NewAcmeOrder/authorizations`` from ``E2eiEnrollment/newOrderResponse``)
    /// - Parameter previousNonce: `replay-nonce` response header from `POST /acme/{provisioner-name}/new-order` (or from the previous to this method if you are creating the second authorization)
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
    public func newAuthzRequest(url: String, previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.newAuthzRequest(url: url, previousNonce: previousNonce)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
    /// - Parameter authz: HTTP response body
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
    public func newAuthzResponse(authz: JsonRawData) async throws -> NewAcmeAuthz {
        return try await self.delegate.newAuthzResponse(authz: authz)
    }

    /// Generates a new client Dpop JWT token. It demonstrates proof of possession of the nonces
    /// (from wire-server & acme server) and will be verified by the acme server when verifying the
    /// challenge (in order to deliver a certificate).
    /// Then send it to `POST /clients/{id}/access-token` ``https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token`` on wire-server.
    /// - Parameter expirySecs: of the client Dpop JWT. This should be equal to the grace period set in Team Management
    /// - Parameter backendNonce: you get by calling `GET /clients/token/nonce` on wire-server as defined here ``https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce``
    public func createDpopToken(expirySecs: UInt16, backendNonce: String) async throws -> [UInt8] {
        return try await self.delegate.createDpopToken(expirySecs: expirySecs, backendNonce: backendNonce)
    }

    /// Creates a new challenge request for Wire Dpop challenge.
    /// - Parameter accessToken: returned by wire-server from https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token
    /// - Parameter previousNonce: `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
    public func newDpopChallengeRequest(url: String, previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.newDpopChallengeRequest(url: url, previousNonce: previousNonce)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for DPoP challenge.
    /// - Parameter challenge: HTTP response body
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
    public func newDpopChallengeResponse(challenge: JsonRawData) async throws {
        return try await self.delegate.newDpopChallengeResponse(challenge: challenge)
    }

    /// Creates a new challenge request for Wire Oidc challenge.
    /// - Parameter idToken: you get back from Identity Provider
    /// - Parameter refreshToken: you get back from Identity Provider to renew the access token
    /// - Parameter previousNonce: `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
    public func newOidcChallengeRequest(idToken: String, refreshToken: String, previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.newOidcChallengeRequest(idToken: idToken, refreshToken: refreshToken, previousNonce: previousNonce)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for OIDC challenge.
    /// - Parameter challenge: HTTP response body
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
    public func newOidcChallengeResponse(cc: CoreCryptoWrapper, challenge: JsonRawData) async throws {
        return try await self.delegate.newOidcChallengeResponse(cc: cc.coreCrypto, challenge: challenge)
    }

    /// Verifies that the previous challenge has been completed.
    /// - Parameter orderUrl: `location` header from http response you got from ``E2eiEnrollment/newOrderResponse``
    /// - Parameter previousNonce: `replay-nonce` response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
    public func checkOrderRequest(orderUrl: String, previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.checkOrderRequest(orderUrl: orderUrl, previousNonce: previousNonce)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
    /// - Parameter order: HTTP response body
    /// - Returns: url to use with ``E2eiEnrollment/finalizeRequest``
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
    public func checkOrderResponse(order: JsonRawData) async throws -> String {
        return try await self.delegate.checkOrderResponse(order: order)
    }

    /// Final step before fetching the certificate.
    /// - Parameter previousNonce: `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}`
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
    public func finalizeRequest(previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.finalizeRequest(previousNonce: previousNonce)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
    /// - Parameter finalize: HTTP response body
    /// - Returns: the certificate url to use with ``E2eiEnrollment/certificateRequest``
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
    public func finalizeResponse(finalize: JsonRawData) async throws -> String {
        return try await self.delegate.finalizeResponse(finalize: finalize)
    }

    /// Creates a request for finally fetching the x509 certificate.
    /// - Parameter previousNonce: `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}/finalize`
    /// - SeeAlso:
    /// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
    public func certificateRequest(previousNonce: String) async throws -> JsonRawData {
        return try await self.delegate.certificateRequest(previousNonce: previousNonce)
    }

    /// Lets clients retrieve the OIDC refresh token to try to renew the user's authorization.
    /// If it's expired, the user needs to reauthenticate and they will update the refresh token
    /// in ``E2eiEnrollment/newOidcChallengeRequest``
    public func getRefreshToken() async throws -> String {
        return try await self.delegate.getRefreshToken()
    }
}

extension CoreCryptoSwift.WireE2eIdentity {
    func lift() -> CommitBundle {
        return E2eiEnrollment.init(delegate: self)
    }
}

/// Indicates the state of a Conversation regarding end-to-end identity.
/// Note: this does not check pending state (pending commit, pending proposals) so it does not consider members about to be added/removed
public enum E2eiConversationState: ConvertToInner {
    typealias Inner = CoreCryptoSwift.E2eiConversationState

    case verified
    case notVerified
    case notEnabled
}

private extension E2eiConversationState {
    func convert() -> Inner {
        switch self {
        case .verified:
            return CoreCryptoSwift.E2eiConversationState.verified
        case .notVerified:
            return CoreCryptoSwift.E2eiConversationState.notVerified
        case .notEnabled:
            return CoreCryptoSwift.E2eiConversationState.notEnabled
        }
    }
}

public typealias JsonRawData = [UInt8]

/// Holds URLs of all the standard ACME endpoint supported on an ACME server.
/// - SeeAlso:
/// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
public struct AcmeDirectory: ConvertToInner {
    /// URL for fetching a new nonce. Use this only for creating a new account.
    public var newNonce: String
    /// URL for creating a new account.
    public var newAccount: String
    /// URL for creating a new order.
    public var newOrder: String
    /// Revocation URL
    public var revokeCert: String

    public init(newNonce: String, newAccount: String, newOrder: String, revokeCert: String) {
        self.newNonce = newNonce
        self.newAccount = newAccount
        self.newOrder = newOrder
        self.revokeCert = revokeCert
    }

    typealias Inner = CoreCryptoSwift.AcmeDirectory

    func convert() -> Inner {
        return CoreCryptoSwift.AcmeDirectory(newNonce: self.newNonce, newAccount: self.newAccount, newOrder: self.newOrder, revokeCert: self.revokeCert)
    }
}

/// Result of an order creation
/// - SeeAlso:
/// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
public struct NewAcmeOrder: ConvertToInner {
    /// Contains raw JSON data of this order. This is parsed by the underlying Rust library hence should not be accessed
    public var delegate: [UInt8]
    /// An authorization for each domain to create
    public var authorizations: [[UInt8]]

    public init(delegate: [UInt8], authorizations: [[UInt8]]) {
        self.delegate = delegate
        self.authorizations = authorizations
    }

    typealias Inner = CoreCryptoSwift.NewAcmeOrder

    func convert() -> Inner {
        return CoreCryptoSwift.NewAcmeOrder(delegate: self.delegate, authorizations: self.authorizations)
    }
}

/// Result of an authorization creation.
/// - SeeAlso:
/// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
public struct NewAcmeAuthz: ConvertToInner {
    /// DNS entry associated with those challenge
    public var identifier: String
    /// To use in the OAuth authorization request
    public var keyauth: String?
    /// ACME Challenge
    public var challenge: AcmeChallenge

    public init(identifier: String, keyauth: String, challenge: AcmeChallenge) {
        self.identifier = identifier
        self.keyauth = keyauth
        self.challenge = challenge
    }

    typealias Inner = CoreCryptoSwift.NewAcmeAuthz

    func convert() -> Inner {
        return CoreCryptoSwift.NewAcmeAuthz(identifier: self.identifier, keyauth: self.keyauth, challenge: self.challenge)
    }
}

/// For creating a challenge
/// - SeeAlso:
/// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
public struct AcmeChallenge: ConvertToInner {
    /// Contains raw JSON data of this challenge. This is parsed by the underlying Rust library hence should not be accessed
    public var delegate: [UInt8]
    /// URL of this challenge
    public var url: String
    /// Non-standard, Wire specific claim. Indicates the consumer from where it should get the challenge proof.
    /// Either from wire-server "/access-token" endpoint in case of a DPoP challenge, or from an OAuth token endpoint for an OIDC challenge
    public var target: String

    public init(delegate: [UInt8], url: String, target: String) {
        self.delegate = delegate
        self.url = url
        self.target = target
    }

    typealias Inner = CoreCryptoSwift.AcmeChallenge

    func convert() -> Inner {
        return CoreCryptoSwift.AcmeChallenge(delegate: self.delegate, url: self.url, target: self.target)
    }
}
