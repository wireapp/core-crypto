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
        _ block: @escaping (_ context: CoreCryptoContext) async throws -> Result
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
        self.coreCrypto = try await wrapError {
            try await WireCoreCryptoUniffi.coreCryptoDeferredInit(
                path: keystorePath,
                key: String(data: keystoreSecret, encoding: .utf8)!
            )
        }
    }

    public func transaction<Result>(
        _ block: @escaping (_ context: CoreCryptoContext) async throws -> Result
    ) async throws -> Result {
        let transactionExecutor = TransactionExecutor<Result>(block)
        try await wrapError { try await coreCrypto.transaction(command: transactionExecutor) }
        return transactionExecutor.result!
    }

    public func provideTransport(transport: any MlsTransport) async throws {
        try await wrapError {
            try await coreCrypto.provideTransport(
                callbacks: MlsTransportAdapter(transport: transport))
        }
    }

    public static func setLogger(_ logger: CoreCryptoLogger) {
        WireCoreCryptoUniffi.setLoggerOnly(logger: CoreCryptoLoggerAdapter(logger: logger))
    }

    public static func setMaxLogLevel(_ level: CoreCryptoLogLevel) {
        WireCoreCryptoUniffi.setMaxLogLevel(level: level.lower())
    }

    public static func version() -> String {
        return WireCoreCryptoUniffi.version()
    }

    public static func buildMetadata() -> BuildMetadata {
        WireCoreCryptoUniffi.buildMetadata().lift()
    }

}

class MlsTransportAdapter: WireCoreCryptoUniffi.MlsTransport {

    let transport: MlsTransport

    init(transport: MlsTransport) {
        self.transport = transport
    }

    func sendCommitBundle(commitBundle: WireCoreCryptoUniffi.CommitBundle) async
        -> WireCoreCryptoUniffi.MlsTransportResponse
    {
        await transport.sendCommitBundle(commitBundle: commitBundle.lift()).lower()
    }

    func sendMessage(mlsMessage: Data) async -> WireCoreCryptoUniffi.MlsTransportResponse {
        await transport.sendMessage(mlsMessage: mlsMessage).lower()
    }

}

class CoreCryptoLoggerAdapter: WireCoreCryptoUniffi.CoreCryptoLogger {

    let logger: CoreCryptoLogger

    init(logger: CoreCryptoLogger) {
        self.logger = logger
    }

    func log(level: WireCoreCryptoUniffi.CoreCryptoLogLevel, message: String, context: String?) {
        logger.log(level: level.lift(), message: message, context: context)
    }

}

class TransactionExecutor<Result>: WireCoreCryptoUniffi.CoreCryptoCommand {

    let block: (_ context: CoreCryptoContext) async throws -> Result
    var result: Result?

    init(
        _ block: @escaping (_ context: CoreCryptoContext) async throws -> Result
    ) {
        self.block = block
    }

    func execute(context: WireCoreCryptoUniffi.CoreCryptoContext) async throws {
        result = try await block(CoreCryptoContextAdapter(context: context))
    }

}
