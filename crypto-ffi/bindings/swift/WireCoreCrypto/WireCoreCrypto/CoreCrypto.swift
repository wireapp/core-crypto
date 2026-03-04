import System
@_exported public import WireCoreCryptoUniffi

/// Defines the protocol for a client.
///
public protocol CoreCryptoProtocol: CoreCryptoFfiProtocol {

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
}

/// CoreCrypto client which manages one cryptographic client for proteus and MLS.
///
public final class CoreCrypto: CoreCryptoFfi, CoreCryptoProtocol, @unchecked Sendable {
    let database: Database?

    /// Initialize CoreCrypto with an Ffi instance
    private init(_ coreCrypto: WireCoreCryptoUniffi.CoreCryptoFfi, database: Database? = nil) {
        self.database = database
        // Due to Swift limitations, we can't use the `super` convenience intializer inside a child initializer, we
        // have to call the default `super` initializer. Luckily, we can do this meaningfully by cloning the pointer of
        // the instance that is passed in here.
        super.init(unsafeFromRawPointer: coreCrypto.uniffiClonePointer())
    }

    ///
    /// Initialise CoreCrypto with an encrypted key store.
    ///
    /// - Parameter keystorePath: path to the encrypted key store
    /// - Parameter key: secret key to unlock the encrypted key store
    ///
    public convenience init(database: Database) throws {
        let coreCrypto = try coreCryptoNew(database: database)
        self.init(coreCrypto, database: database)
    }

    @_documentation(visibility: private) required init(
        unsafeFromRawPointer pointer: UnsafeMutableRawPointer
    ) {
        self.database = nil
        super.init(unsafeFromRawPointer: pointer)
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
        let dbLocation = try await database?.getLocation()
        let filePath = dbLocation.map { FilePath(stringLiteral: $0) }
        let transactionExecutor = try TransactionExecutor<Result>(
            keystorePath: filePath, block)
        do {
            try await self.transaction(command: transactionExecutor)
        } catch {
            throw await transactionExecutor.innerError ?? error
        }
        return await transactionExecutor.result!
    }

    public func registerEpochObserver(_ epochObserver: EpochObserver) async throws {
        // we want to wrap the observer here to provide async indirection, so that no matter what
        // the observer that makes its way to the Rust side of things doesn't end up blocking
        try await self.registerEpochObserver(
            epochObserver: EpochObserverIndirector(epochObserver))
    }

    public func registerHistoryObserver(_ historyObserver: HistoryObserver) async throws {
        // we want to wrap the observer here to provide async indirection, so that no matter what
        // the observer that makes its way to the Rust side of things doesn't end up blocking
        try await self.registerHistoryObserver(
            historyObserver: HistoryObserverIndirector(historyObserver))
    }

    /// Returns the last resort PreKey id
    public static func proteusLastResortPrekeyId() throws -> UInt16 {
        return try WireCoreCryptoUniffi.proteusLastResortPrekeyIdFfi()
    }

    /// Proteus public key fingerprint
    /// It's basically the public key encoded as an hex string
    ///
    /// Returns Hex-encoded public key string
    public static func proteusFingerprintPrekeybundle(prekey: Data) throws -> String {
        return try WireCoreCryptoUniffi.proteusFingerprintPrekeybundleFfi(prekey: prekey)
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

extension Credential {
    /// Construct a new Credential from ciphersuite and client id
    public static func basic(
        ciphersuite: Ciphersuite,
        clientId: ClientId
    ) throws -> Credential {
        return try credentialBasic(ciphersuite: ciphersuite, clientId: clientId)
    }
}

extension Database {
    /// Initialise or open a Database.
    ///
    /// - Parameter location: path to the database
    /// - Parameter key: secret key to unlock the database
    ///
    public static func open(location: String, key: DatabaseKey) async throws -> Database {
        return try await openDatabase(location: location, key: key)
    }

    /// Initialise an in-memory Database whose data will be lost when the instance is dropped.
    ///
    /// - Parameter key: secret key to unlock the database
    public static func open(key: DatabaseKey) async throws -> Database {
        return try await inMemoryDatabase(key: key)
    }
}
