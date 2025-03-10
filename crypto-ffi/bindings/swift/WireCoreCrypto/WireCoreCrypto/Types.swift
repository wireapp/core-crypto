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

public typealias ClientId = Data

public typealias ConversationId = Data

public typealias KeyPackage = Data

public typealias Ciphersuite = UInt16

public typealias Ciphersuites = [UInt16]

public typealias NewCrlDistributionPoints = [String]?

public enum MlsCredentialType: UInt8 {

    /// Basic credential i.e. a KeyPair
    ///
    case basic = 1
    /// A x509 certificate generally obtained through e2e identity enrollment process
    ///
    case x509 = 2

    func lower() -> WireCoreCryptoUniffi.MlsCredentialType {
        switch self {
        case .basic: .basic
        case .x509: .x509
        }
    }
}

extension WireCoreCryptoUniffi.MlsCredentialType {

    func lift() -> MlsCredentialType {
        switch self {
        case .basic: .basic
        case .x509: .x509
        }
    }

}

public enum MlsRatchetTreeType: UInt8 {

    /// Plain old and complete `GroupInfo`
    ///
    case full = 1
    /// Contains `GroupInfo` changes since previous epoch (not yet implemented)
    /// (see [draft](https://github.com/rohan-wire/ietf-drafts/blob/main/mahy-mls-ratchet-tree-delta/draft-mahy-mls-ratchet-tree-delta.md))
    ///
    case delta = 2
    case byRef = 3

    func lower() -> WireCoreCryptoUniffi.MlsRatchetTreeType {
        switch self {
        case .full: .full
        case .delta: .delta
        case .byRef: .byRef
        }
    }
}

extension WireCoreCryptoUniffi.MlsRatchetTreeType {
    func lift() -> MlsRatchetTreeType {
        switch self {
        case .full: .full
        case .delta: .delta
        case .byRef: .byRef
        }
    }
}

public enum MlsGroupInfoEncryptionType: UInt8 {

    /// Unencrypted `GroupInfo`
    ///
    case plaintext = 1
    /// `GroupInfo` encrypted in a JWE
    ///
    case jweEncrypted = 2

    func lower() -> WireCoreCryptoUniffi.MlsGroupInfoEncryptionType {
        switch self {
        case .plaintext: .plaintext
        case .jweEncrypted: .jweEncrypted
        }
    }
}

extension WireCoreCryptoUniffi.MlsGroupInfoEncryptionType {
    func lift() -> MlsGroupInfoEncryptionType {
        switch self {
        case .plaintext: .plaintext
        case .jweEncrypted: .jweEncrypted
        }
    }
}

public struct GroupInfoBundle {
    public var encryptionType: MlsGroupInfoEncryptionType
    public var ratchetTreeType: MlsRatchetTreeType
    public var payload: Data

    func lower() -> WireCoreCryptoUniffi.GroupInfoBundle {
        WireCoreCryptoUniffi.GroupInfoBundle(
            encryptionType: encryptionType.lower(),
            ratchetTreeType: ratchetTreeType.lower(),
            payload: payload
        )
    }
}

extension WireCoreCryptoUniffi.GroupInfoBundle {

    func lift() -> GroupInfoBundle {
        GroupInfoBundle(
            encryptionType: encryptionType.lift(),
            ratchetTreeType: ratchetTreeType.lift(),
            payload: payload
        )
    }
}

public struct CommitBundle {
    public var welcome: Data?
    public var commit: Data
    public var groupInfo: GroupInfoBundle

    internal func lower() -> WireCoreCryptoUniffi.CommitBundle {
        WireCoreCryptoUniffi.CommitBundle(
            welcome: welcome,
            commit: commit,
            groupInfo: groupInfo.lower()
        )
    }
}

extension WireCoreCryptoUniffi.CommitBundle {
    func lift() -> CommitBundle {
        CommitBundle(welcome: welcome, commit: commit, groupInfo: groupInfo.lift())
    }
}

public enum MlsTransportResponse {

    /// The message was accepted by the distribution service
    ///
    case success
    /// A client should have consumed all incoming messages before re-trying.
    ///
    case retry
    /// The message was rejected by the delivery service and there's no recovery.
    ///
    case abort(
        reason: String
    )
}

extension MlsTransportResponse {
    func lower() -> WireCoreCryptoUniffi.MlsTransportResponse {
        switch self {
        case .success: .success
        case .retry: .retry
        case .abort(let reason): .abort(reason: reason)
        }
    }
}

/// Used by core crypto to send commits or application messages to the delivery service.
/// This trait must be implemented before calling any functions that produce commits.
public protocol MlsTransport: AnyObject {

    func sendCommitBundle(commitBundle: CommitBundle) async -> MlsTransportResponse

    func sendMessage(mlsMessage: Data) async -> MlsTransportResponse

}

public enum DeviceStatus: UInt8 {

    /// All is fine
    ///
    case valid = 1
    /// The Credential's certificate is expired
    ///
    case expired = 2
    /// The Credential's certificate is revoked (not implemented yet)
    ///
    case revoked = 3
}

extension WireCoreCryptoUniffi.DeviceStatus {

    func lift() -> DeviceStatus {
        switch self {
        case .valid: .valid
        case .expired: .expired
        case .revoked: .revoked
        }
    }

}

public struct X509Identity {
    public var handle: String
    public var displayName: String
    public var domain: String
    public var certificate: String
    public var serialNumber: String
    public var notBefore: UInt64
    public var notAfter: UInt64

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        handle: String, displayName: String, domain: String, certificate: String,
        serialNumber: String,
        notBefore: UInt64, notAfter: UInt64
    ) {
        self.handle = handle
        self.displayName = displayName
        self.domain = domain
        self.certificate = certificate
        self.serialNumber = serialNumber
        self.notBefore = notBefore
        self.notAfter = notAfter
    }
}

extension WireCoreCryptoUniffi.X509Identity {

    func lift() -> X509Identity {
        X509Identity(
            handle: handle,
            displayName: displayName,
            domain: domain,
            certificate: certificate,
            serialNumber: serialNumber,
            notBefore: notBefore,
            notAfter: notAfter
        )
    }

}

/// See [core_crypto::prelude::WireIdentity]
public struct WireIdentity {
    public var clientId: String
    public var status: DeviceStatus
    public var thumbprint: String
    public var credentialType: MlsCredentialType
    public var x509Identity: X509Identity?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        clientId: String, status: DeviceStatus, thumbprint: String,
        credentialType: MlsCredentialType,
        x509Identity: X509Identity?
    ) {
        self.clientId = clientId
        self.status = status
        self.thumbprint = thumbprint
        self.credentialType = credentialType
        self.x509Identity = x509Identity
    }
}

extension WireCoreCryptoUniffi.WireIdentity {

    func lift() -> WireIdentity {
        WireIdentity(
            clientId: clientId,
            status: status.lift(),
            thumbprint: thumbprint,
            credentialType: credentialType.lift(),
            x509Identity: x509Identity?.lift()
        )
    }

}

public struct BufferedDecryptedMessage {
    public var message: Data?
    public var isActive: Bool
    public var commitDelay: UInt64?
    public var senderClientId: ClientId?
    public var hasEpochChanged: Bool
    public var identity: WireIdentity
    public var crlNewDistributionPoints: [String]?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        message: Data?, isActive: Bool, commitDelay: UInt64?, senderClientId: ClientId?,
        hasEpochChanged: Bool, identity: WireIdentity, crlNewDistributionPoints: [String]?
    ) {
        self.message = message
        self.isActive = isActive
        self.commitDelay = commitDelay
        self.senderClientId = senderClientId
        self.hasEpochChanged = hasEpochChanged
        self.identity = identity
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }
}

extension WireCoreCryptoUniffi.BufferedDecryptedMessage {

    func lift() -> BufferedDecryptedMessage {
        BufferedDecryptedMessage(
            message: message,
            isActive: isActive,
            commitDelay: commitDelay,
            senderClientId: senderClientId,
            hasEpochChanged: hasEpochChanged,
            identity: identity.lift(),
            crlNewDistributionPoints: crlNewDistributionPoints
        )
    }

}

public struct DecryptedMessage {
    public var message: Data?
    public var isActive: Bool
    public var commitDelay: UInt64?
    public var senderClientId: ClientId?
    public var hasEpochChanged: Bool
    public var identity: WireIdentity
    public var bufferedMessages: [BufferedDecryptedMessage]?
    public var crlNewDistributionPoints: [String]?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        message: Data?, isActive: Bool, commitDelay: UInt64?, senderClientId: ClientId?,
        hasEpochChanged: Bool, identity: WireIdentity,
        bufferedMessages: [BufferedDecryptedMessage]?,
        crlNewDistributionPoints: [String]?
    ) {
        self.message = message
        self.isActive = isActive
        self.commitDelay = commitDelay
        self.senderClientId = senderClientId
        self.hasEpochChanged = hasEpochChanged
        self.identity = identity
        self.bufferedMessages = bufferedMessages
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }
}

extension WireCoreCryptoUniffi.DecryptedMessage {

    func lift() -> DecryptedMessage {
        DecryptedMessage(
            message: message,
            isActive: isActive,
            commitDelay: commitDelay,
            senderClientId: senderClientId,
            hasEpochChanged: hasEpochChanged,
            identity: identity.lift(),
            bufferedMessages: bufferedMessages?.map { $0.lift() },
            crlNewDistributionPoints: crlNewDistributionPoints
        )
    }

}

public enum MlsWirePolicy: UInt8 {

    /// Handshake messages are never encrypted
    ///
    case plaintext = 1
    /// Handshake messages are always encrypted
    ///
    case ciphertext = 2

    func lower() -> WireCoreCryptoUniffi.MlsWirePolicy {
        switch self {
        case .plaintext: .plaintext
        case .ciphertext: .ciphertext
        }
    }
}

public struct CustomConfiguration {
    public var keyRotationSpan: TimeInterval?
    public var wirePolicy: MlsWirePolicy?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(keyRotationSpan: TimeInterval?, wirePolicy: MlsWirePolicy?) {
        self.keyRotationSpan = keyRotationSpan
        self.wirePolicy = wirePolicy
    }

    func lower() -> WireCoreCryptoUniffi.CustomConfiguration {
        WireCoreCryptoUniffi.CustomConfiguration(
            keyRotationSpan: keyRotationSpan,
            wirePolicy: wirePolicy?.lower()
        )
    }
}

public struct ConversationConfiguration {
    public var ciphersuite: Ciphersuite
    public var externalSenders: [Data]
    public var custom: CustomConfiguration

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(ciphersuite: Ciphersuite, externalSenders: [Data], custom: CustomConfiguration) {
        self.ciphersuite = ciphersuite
        self.externalSenders = externalSenders
        self.custom = custom
    }

    func lower() -> WireCoreCryptoUniffi.ConversationConfiguration {
        WireCoreCryptoUniffi.ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: externalSenders,
            custom: custom.lower()
        )
    }
}

public struct WelcomeBundle {
    public var id: Data
    public var crlNewDistributionPoints: [String]?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: Data, crlNewDistributionPoints: [String]?) {
        self.id = id
        self.crlNewDistributionPoints = crlNewDistributionPoints
    }
}

extension WireCoreCryptoUniffi.WelcomeBundle {

    func lift() -> WelcomeBundle {
        WelcomeBundle(id: id, crlNewDistributionPoints: crlNewDistributionPoints)
    }

}

public struct ProteusAutoPrekeyBundle {
    public var id: UInt16
    public var pkb: Data

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: UInt16, pkb: Data) {
        self.id = id
        self.pkb = pkb
    }
}

extension WireCoreCryptoUniffi.ProteusAutoPrekeyBundle {

    func lift() -> ProteusAutoPrekeyBundle {
        ProteusAutoPrekeyBundle(id: id, pkb: pkb)
    }

}

// MARK: - E2EI

public enum E2eiConversationState: UInt8 {

    /// All clients have a valid E2EI certificate
    ///
    case verified = 1
    /// Some clients are either still Basic or their certificate is expired
    ///
    case notVerified = 2
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    ///
    case notEnabled = 3
}

extension WireCoreCryptoUniffi.E2eiConversationState {

    func lift() -> E2eiConversationState {
        switch self {
        case .verified: .verified
        case .notVerified: .notVerified
        case .notEnabled: .notEnabled
        }
    }

}

public struct E2eiDumpedPkiEnv {
    public var rootCa: String
    public var intermediates: [String]
    public var crls: [String]

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(rootCa: String, intermediates: [String], crls: [String]) {
        self.rootCa = rootCa
        self.intermediates = intermediates
        self.crls = crls
    }
}

extension WireCoreCryptoUniffi.E2eiDumpedPkiEnv {

    func lift() -> E2eiDumpedPkiEnv {
        E2eiDumpedPkiEnv(rootCa: rootCa, intermediates: intermediates, crls: crls)
    }

}

public struct E2eiEnrollment {

    let inner: WireCoreCryptoUniffi.E2eiEnrollment

    func lower() -> WireCoreCryptoUniffi.E2eiEnrollment {
        inner
    }

}

extension WireCoreCryptoUniffi.E2eiEnrollment {

    func lift() -> E2eiEnrollment {
        E2eiEnrollment(inner: self)
    }

}

/// Supporting struct for CRL registration result
public struct CrlRegistration {
    /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
    ///
    public var dirty: Bool
    /// Optional expiration timestamp
    ///
    public var expiration: UInt64?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
        ///
        dirty: Bool,
        /// Optional expiration timestamp
        ///
        expiration: UInt64?
    ) {
        self.dirty = dirty
        self.expiration = expiration
    }
}

extension WireCoreCryptoUniffi.CrlRegistration {

    func lift() -> CrlRegistration {
        CrlRegistration(dirty: dirty, expiration: expiration)
    }

}

public enum CoreCryptoLogLevel {
    case off
    case trace
    case debug
    case info
    case warn
    case error

    func lower() -> WireCoreCryptoUniffi.CoreCryptoLogLevel {
        switch self {
        case .off: .off
        case .trace: .trace
        case .debug: .debug
        case .info: .info
        case .warn: .warn
        case .error: .error
        }
    }
}

extension WireCoreCryptoUniffi.CoreCryptoLogLevel {

    func lift() -> CoreCryptoLogLevel {
        switch self {
        case .off: .off
        case .trace: .trace
        case .debug: .debug
        case .info: .info
        case .warn: .warn
        case .error: .error
        }
    }

}

/// This trait is used to provide a callback mechanism to hook up the rerspective platform logging system
public protocol CoreCryptoLogger {

    /// Function to setup a hook for the logging messages. Core Crypto will call this method
    /// whenever it needs to log a message.
    ///
    func log(level: CoreCryptoLogLevel, message: String, context: String?)

}

/// Metadata describing the conditions of the build of this software.
public struct BuildMetadata {
    /// Build Timestamp
    ///
    public var timestamp: String
    /// Whether this build was in Debug mode (true) or Release mode (false)
    ///
    public var cargoDebug: String
    /// Features enabled for this build
    ///
    public var cargoFeatures: String
    /// Optimization level
    ///
    public var optLevel: String
    /// Build target triple
    ///
    public var targetTriple: String
    /// Git branch
    ///
    public var gitBranch: String
    /// Output of `git describe`
    ///
    public var gitDescribe: String
    /// Hash of current git commit
    ///
    public var gitSha: String
    ///`true` when the source code differed from the commit at the most recent git hash
    ///
    public var gitDirty: String
}

extension WireCoreCryptoUniffi.BuildMetadata {

    func lift() -> BuildMetadata {
        BuildMetadata(
            timestamp: timestamp,
            cargoDebug: cargoDebug,
            cargoFeatures: cargoFeatures,
            optLevel: optLevel,
            targetTriple: targetTriple,
            gitBranch: gitBranch,
            gitDescribe: gitDescribe,
            gitSha: gitSha,
            gitDirty: gitDirty
        )
    }
}
