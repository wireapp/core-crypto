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

import WireCoreCryptoUniffi

@_exported public import struct WireCoreCryptoUniffi.BufferedDecryptedMessage
@_exported public import struct WireCoreCryptoUniffi.BuildMetadata
@_exported public import typealias WireCoreCryptoUniffi.Ciphersuite
@_exported public import typealias WireCoreCryptoUniffi.Ciphersuites
@_exported public import typealias WireCoreCryptoUniffi.ClientId
@_exported public import struct WireCoreCryptoUniffi.CommitBundle
@_exported public import struct WireCoreCryptoUniffi.ConversationConfiguration
@_exported public import protocol WireCoreCryptoUniffi.CoreCryptoContextProtocol
@_exported public import enum WireCoreCryptoUniffi.CoreCryptoError
@_exported public import enum WireCoreCryptoUniffi.CoreCryptoLogLevel
@_exported public import protocol WireCoreCryptoUniffi.CoreCryptoLogger
@_exported public import struct WireCoreCryptoUniffi.CrlRegistration
@_exported public import struct WireCoreCryptoUniffi.CustomConfiguration
@_exported public import struct WireCoreCryptoUniffi.DecryptedMessage
@_exported public import enum WireCoreCryptoUniffi.DeviceStatus
@_exported public import enum WireCoreCryptoUniffi.E2eiConversationState
@_exported public import struct WireCoreCryptoUniffi.E2eiDumpedPkiEnv
@_exported public import class WireCoreCryptoUniffi.E2eiEnrollment
@_exported public import struct WireCoreCryptoUniffi.GroupInfoBundle
@_exported public import enum WireCoreCryptoUniffi.MlsCredentialType
@_exported public import enum WireCoreCryptoUniffi.MlsError
@_exported public import enum WireCoreCryptoUniffi.MlsGroupInfoEncryptionType
@_exported public import enum WireCoreCryptoUniffi.MlsRatchetTreeType
@_exported public import protocol WireCoreCryptoUniffi.MlsTransport
@_exported public import enum WireCoreCryptoUniffi.MlsTransportResponse
@_exported public import enum WireCoreCryptoUniffi.MlsWirePolicy
@_exported public import typealias WireCoreCryptoUniffi.NewCrlDistributionPoints
@_exported public import struct WireCoreCryptoUniffi.ProteusAutoPrekeyBundle
@_exported public import enum WireCoreCryptoUniffi.ProteusError
@_exported public import struct WireCoreCryptoUniffi.WelcomeBundle
@_exported public import struct WireCoreCryptoUniffi.WireIdentity
@_exported public import struct WireCoreCryptoUniffi.X509Identity

public protocol CoreCryptoProtocol {

    /// Starts a transaction in Core Crypto. If the closure succeeds without throwing an error, it will be committed, otherwise, every operation
    /// performed with the context will be discarded.
    ///
    /// - Parameter block: the closure to be executed within the transaction context. A ``CoreCryptoContext-swift.protocol``
    ///  is provided on which any operations should be performed.
    ///
    /// - Returns: Result value returned from the closure if any.
    ///
    func transaction<Result>(
        _ block: @escaping (_ context: CoreCryptoContextProtocol) async throws -> Result
    ) async throws -> Result

    /// Register a callback which will be called when performing MLS operations which require communication with the delivery service.
    ///
    func provideTransport(transport: any MlsTransport) async throws

    /// Register CoreCrypto a logger
    ///
    static func setLogger(_ logger: CoreCryptoLogger)

    /// Set the log level limit for logs which should be forwarded to the registered ``CoreCryptoLogger-5nvug``
    ///
    /// The default log level is `info`.
    ///
    static func setMaxLogLevel(_ level: CoreCryptoLogLevel)

    /// CoreCrypto build version number
    ///
    static func version() -> String

    /// Build metadata describing under which conditions this version of CoreCrypto was build.
    ///
    static func buildMetadata() -> BuildMetadata
}

/// CoreCrypto client which manages one cryptographic client for proteus and MLS.
///
public class CoreCrypto: CoreCryptoProtocol {

    let coreCrypto: WireCoreCryptoUniffi.CoreCrypto

    ///
    /// Initialise CoreCrypto with an encrypted key store.
    ///
    /// - Parameter keystorePath: path to the encrypted key store
    /// - Parameter keystoreSecret: secret key to for the encrypted key store
    ///
    public init(keystorePath: String, keystoreSecret: Data) async throws {
        self.coreCrypto =
            try await WireCoreCryptoUniffi.coreCryptoDeferredInit(
                path: keystorePath,
                key: String(data: keystoreSecret, encoding: .utf8)!
            )
    }

    public func transaction<Result>(
        _ block: @escaping (_ context: CoreCryptoContextProtocol) async throws -> Result
    ) async throws -> Result {
        let transactionExecutor = TransactionExecutor<Result>(block)
        try await coreCrypto.transaction(command: transactionExecutor)
        return transactionExecutor.result!
    }

    public func provideTransport(transport: any MlsTransport) async throws {
        try await coreCrypto.provideTransport(
            callbacks: transport)
    }

    public static func setLogger(_ logger: CoreCryptoLogger) {
        WireCoreCryptoUniffi.setLoggerOnly(logger: logger)
    }

    public static func setMaxLogLevel(_ level: CoreCryptoLogLevel) {
        WireCoreCryptoUniffi.setMaxLogLevel(level: level)
    }

    public static func version() -> String {
        return WireCoreCryptoUniffi.version()
    }

    public static func buildMetadata() -> BuildMetadata {
        WireCoreCryptoUniffi.buildMetadata()
    }

}

class TransactionExecutor<Result>: WireCoreCryptoUniffi.CoreCryptoCommand {

    let block: (_ context: CoreCryptoContextProtocol) async throws -> Result
    var result: Result?

    init(
        _ block: @escaping (_ context: CoreCryptoContextProtocol) async throws -> Result
    ) {
        self.block = block
    }

    func execute(context: WireCoreCryptoUniffi.CoreCryptoContext) async throws {
        result = try await block(context)
    }

}
