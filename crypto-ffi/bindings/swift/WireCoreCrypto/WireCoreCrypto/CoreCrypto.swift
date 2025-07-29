import System
@_exported public import WireCoreCryptoUniffi

public protocol CoreCryptoProtocol {

    /// Instantiate a history client.
    ///
    /// This client exposes the full interface of ``Self``, but it should only be used to decrypt messages.
    /// Other use is a logic error.
    static func historyClient(_ historySecret: HistorySecret) async throws -> Self

    /// Starts a transaction in Core Crypto. If the closure succeeds without throwing an error,
    /// it will be committed, otherwise, every operation performed with the context will be discarded.
    ///
    /// - Parameter block: the closure to be executed within the transaction context.
    /// A ``CoreCryptoContext-swift.protocol`` is provided on which any operations should be performed.
    ///
    /// - Returns: Result value returned from the closure if any.
    ///
    func transaction<Result>(
        _ block: @escaping (_ context: CoreCryptoContextProtocol) async throws -> Result
    ) async throws -> Result

    /// Register a callback which will be called when performing MLS operations which require communication
    /// with the delivery service.
    ///
    func provideTransport(transport: any MlsTransport) async throws

    ///
    /// Register an Epoch Observer which will be notified every time a conversation's epoch changes.
    ///
    /// - Parameter epochObserver: epoch observer to register
    ///
    /// This function should be called 0 or 1 times in the lifetime of CoreCrypto,
    /// regardless of the number of transactions.
    ///
    func registerEpochObserver(_ epochObserver: EpochObserver) async throws

    ///
    /// Register a History Observer which will be notified every time a new history secret is created locally.
    ///
    /// - Parameter historyObserver: history observer to register
    ///
    /// This function should be called 0 or 1 times in the lifetime of CoreCrypto,
    /// regardless of the number of transactions.
    ///
    func registerHistoryObserver(_ historyObserver: HistoryObserver) async throws

    /// Check if history sharing is enabled, i.e., if any of the conversation members have a ``ClientId`` starting
    /// with the specific history client prefix.
    func isHistorySharingEnabled(conversationId: ConversationId) async throws -> Bool

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
public final class CoreCrypto: CoreCryptoProtocol {

    let coreCrypto: WireCoreCryptoUniffi.CoreCrypto
    let keystorePath: FilePath?

    /// Initialize CoreCrypto with a Ffi instance
    private init(_ coreCrypto: WireCoreCryptoUniffi.CoreCrypto, keystorePath: FilePath? = nil) {
        self.coreCrypto = coreCrypto
        self.keystorePath = keystorePath
    }

    ///
    /// Initialise CoreCrypto with an encrypted key store.
    ///
    /// - Parameter keystorePath: path to the encrypted key store
    /// - Parameter key: secret key to unlock the encrypted key store
    ///
    public convenience init(keystorePath: String, key: DatabaseKey) async throws {
        let coreCrypto =
            try await WireCoreCryptoUniffi.coreCryptoDeferredInit(
                path: keystorePath,
                key: key,
                entropySeed: nil
            )
        self.init(coreCrypto, keystorePath: FilePath(stringLiteral: keystorePath))
    }

    /// Instantiate a history client.
    ///
    /// This client exposes the full interface of `CoreCrypto`, but it should only be used to decrypt messages.
    /// Other use is a logic error.
    public static func historyClient(_ historySecret: HistorySecret) async throws -> CoreCrypto {
        let coreCrypto =
            try await WireCoreCryptoUniffi.coreCryptoHistoryClient(historySecret: historySecret)
        return self.init(coreCrypto)
    }

    public func transaction<Result>(
        _ block: @escaping (_ context: CoreCryptoContextProtocol) async throws -> Result
    ) async throws -> Result {
        let transactionExecutor = try TransactionExecutor<Result>(keystorePath: keystorePath, block)
        do {
            try await coreCrypto.transaction(command: transactionExecutor)
        } catch {
            throw await transactionExecutor.innerError ?? error
        }
        return await transactionExecutor.result!
    }

    public func provideTransport(transport: any MlsTransport) async throws {
        try await coreCrypto.provideTransport(
            callbacks: transport)
    }

    public func registerEpochObserver(_ epochObserver: EpochObserver) async throws {
        // we want to wrap the observer here to provide async indirection, so that no matter what
        // the observer that makes its way to the Rust side of things doesn't end up blocking
        try await coreCrypto.registerEpochObserver(
            epochObserver: EpochObserverIndirector(epochObserver))
    }

    public func registerHistoryObserver(_ historyObserver: HistoryObserver) async throws {
        // we want to wrap the observer here to provide async indirection, so that no matter what
        // the observer that makes its way to the Rust side of things doesn't end up blocking
        try await coreCrypto.registerHistoryObserver(
            historyObserver: HistoryObserverIndirector(historyObserver))
    }

    public func isHistorySharingEnabled(conversationId: ConversationId) async throws -> Bool {
        try await coreCrypto.isHistorySharingEnabled(conversationId: conversationId)
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

final class EpochObserverIndirector: EpochObserver {

    let epochObserver: EpochObserver

    init(_ epochObserver: EpochObserver) {
        self.epochObserver = epochObserver
    }

    func epochChanged(conversationId: ConversationId, epoch: UInt64) async throws {
        Task {
            try await epochObserver.epochChanged(conversationId: conversationId, epoch: epoch)
        }
    }

}

final class HistoryObserverIndirector: HistoryObserver {

    let historyObserver: HistoryObserver

    init(_ historyObserver: HistoryObserver) {
        self.historyObserver = historyObserver
    }

    func historyClientCreated(conversationId: ConversationId, secret: HistorySecret) async throws {
        Task {
            try await historyObserver.historyClientCreated(
                conversationId: conversationId, secret: secret)
        }
    }
}

final actor TransactionExecutor<Result>: WireCoreCryptoUniffi.CoreCryptoCommand {

    let block: (_ context: CoreCryptoContextProtocol) async throws -> Result
    var result: Result?
    var innerError: Error?
    var fileDescriptor: FileDescriptor?

    init(
        keystorePath: FilePath?,
        _ block: @escaping (_ context: CoreCryptoContextProtocol) async throws -> Result
    ) throws {
        self.block = block

        if let keystorePath {
            let path = keystorePath.absolutePath().removingLastComponent()
            self.fileDescriptor = try FileDescriptor.open(path, .readOnly, options: .directory)
        }
    }

    deinit {
        try? fileDescriptor?.close()
    }

    func execute(context: WireCoreCryptoUniffi.CoreCryptoContext) async throws {
        // Only aquire lock if we are using an instance which persists to disk
        if fileDescriptor != nil {
            acquireFileLock()

            // Reload any cached proteus sessions from disk since they may be invalid
            try await context.proteusReloadSessions()
        }

        defer {
            releaseFileLock()
        }

        do {
            result = try await block(context)
        } catch {
            innerError = error
            throw error
        }
    }

    func acquireFileLock() {
        guard let fileDescriptor else { return }
        let result = flock(fileDescriptor.rawValue, LOCK_EX)
        if result != 0 {
            fatalError("Failed aquire lock: \(errno))")
        }
    }

    func releaseFileLock() {
        guard let fileDescriptor else { return }
        let result = flock(fileDescriptor.rawValue, LOCK_UN)
        if result != 0 {
            fatalError("Failed release lock: \(errno))")
        }
    }

}

public func migrateDatabaseKeyTypeToBytes(path: String, oldKey: String, newKey: DatabaseKey)
    async throws
{
    try await WireCoreCryptoUniffi.migrateDbKeyTypeToBytes(
        name: path, oldKey: oldKey, newKey: newKey)
}
