import CryptoKit
import Foundation
import XCTest

@testable import WireCoreCrypto

final class WireCoreCryptoTests: XCTestCase {

    var mockMlsTransport: MockMlsTransport = MockMlsTransport()

    override func setUpWithError() throws {
        mockMlsTransport = MockMlsTransport()
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testSetClientDataPersists() async throws {
        let coreCrypto = try await createCoreCrypto()
        let data = "my message processing checkpoint".data(using: .utf8)!

        try await coreCrypto.transaction { context in
            let previousData = try await context.getData()
            XCTAssertNil(previousData)
            try await context.setData(data: data)
        }

        try await coreCrypto.transaction { context in
            let updatedData = try await context.getData()
            XCTAssertEqual(updatedData, data)
        }
    }

    func testMigratingKeyTypeToBytesWorks() async throws {
        let databaseName = "migrating-key-types-to-bytes-test-E4D08634-D1AE-40C8-ADF4-34CCC472AC38"
        let databaseFile = "\(databaseName).sqlite"

        // Store salt in keychain
        let digest = SHA256.hash(data: Data(databaseFile.utf8))
        let keychainAccount = "keystore_salt_\(digest.map { String(format: "%02x", $0) }.joined())"
        let saltHex = "d94268ec2a83415b40702a14bb50e2c3"
        let saltData = Data(hex: saltHex)!

        let keychainQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "wire.com",
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: saltData,
        ]
        SecItemDelete(keychainQuery as CFDictionary)
        SecItemAdd(keychainQuery as CFDictionary, nil)

        // Copy test database with the old key format to a temporary directory
        let tmpdir = FileManager.default.temporaryDirectory.appendingPathComponent(
            "cc-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpdir, withIntermediateDirectories: true)
        let resourceURL = Bundle(for: type(of: self))
            .url(
                forResource: databaseName,
                withExtension: "sqlite"
            )!
        let targetPath = tmpdir.appendingPathComponent(resourceURL.lastPathComponent)
        try FileManager.default.copyItem(at: resourceURL, to: targetPath)

        // The keystore path has to be the same over different instances of the test, because of handle_ios_wal_compat().
        // Change the working directory so that we can use a relative path for the keystore path.
        let oldWorkingDirectory = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tmpdir.path())

        // Now migrate the database to the new key format
        let oldKey = "secret"
        let newKey = genDatabaseKey()
        try await migrateDatabaseKeyTypeToBytes(
            path: targetPath.lastPathComponent, oldKey: oldKey, newKey: newKey)

        // Check if we can read the conversation from the migrated database
        let alice = try await CoreCrypto(
            keystorePath: targetPath.lastPathComponent, key: newKey)
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let epoch = try await alice.transaction {
            try await $0.conversationEpoch(conversationId: conversationId)
        }
        XCTAssertEqual(1, epoch)

        // The file manager is a singleton used for the entire process, so we better switch back
        FileManager.default.changeCurrentDirectoryPath(oldWorkingDirectory)
        try FileManager.default.removeItem(at: tmpdir)
    }

    func testInteractionWithInvalidContextThrowsError() async throws {
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let aliceId = ClientId(bytes: "alice1".data(using: .utf8)!)
        let coreCrypto = try await createCoreCrypto()
        var context: CoreCryptoContextProtocol? = nil

        try await coreCrypto.transaction { context = $0 }

        await XCTAssertThrowsErrorAsync {
            try await context?.mlsInit(
                clientId: aliceId,
                ciphersuites: [ciphersuite],
                nbKeyPackage: nil
            )
        }
    }

    func testErrorIsPropagatedByTransaction() async throws {
        struct MyError: Error, Equatable {}

        let coreCrypto = try await createCoreCrypto()
        let expectedError = MyError()

        await XCTAssertThrowsErrorAsync(
            expectedError,
            when: {
                try await coreCrypto.transaction { _ in
                    throw expectedError
                }
            })
    }

    func testTransactionRollsBackOnError() async throws {
        struct MyError: Error, Equatable {}

        let aliceId = ClientId(bytes: "alice1".data(using: .utf8)!)
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let configuration = ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: [],
            custom: CustomConfiguration(
                keyRotationSpan: nil,
                wirePolicy: nil
            )
        )
        let coreCrypto = try await createCoreCrypto()
        let expectedError = MyError()

        try await coreCrypto.transaction {
            try await $0.mlsInit(
                clientId: aliceId,
                ciphersuites: [ciphersuite],
                nbKeyPackage: nil
            )
        }

        await XCTAssertThrowsErrorAsync(
            expectedError,
            when: {
                try await coreCrypto.transaction { ctx in
                    try await ctx.createConversation(
                        conversationId: conversationId,
                        creatorCredentialType: .basic,
                        config: configuration
                    )
                    throw expectedError
                }
            })

        // This would fail with a "Conversation already exists" exception, if the above
        // transaction hadn't been rolled back.
        try await coreCrypto.transaction { ctx in
            try await ctx.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }
    }

    func testParallelTransactionsArePerformedSerially() async throws {
        let coreCrypto = try await createCoreCrypto()
        let token = "t"
        let transactionCount = 3

        // How this test ensures that transactions are performed serially:
        // Each transaction gets the previous token string, adds one token at the end and stores it.
        // If, for instance, the second and third transaction run in parallel they will both get same current
        // token string "tt" and store "ttt".
        // If they execute serially, one will store "ttt" and the other "tttt" (this is what we assert).

        let result = try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<transactionCount {
                group.addTask {
                    try await coreCrypto.transaction { ctx in
                        try await Task.sleep(for: .milliseconds(100))
                        let data =
                            try await ctx.getData().map { String(data: $0, encoding: .utf8)! }?
                            .appending(token)
                            ?? token
                        try await ctx.setData(data: data.data(using: .utf8)!)
                    }
                }
            }

            try await group.waitForAll()

            let result = try await coreCrypto.transaction { ctx in
                try await ctx.getData().map { String(data: $0, encoding: .utf8)! }
            }

            return result
        }

        XCTAssertEqual(
            String(repeating: token, count: transactionCount), result,
            "Expected all transactions to complete")
    }

    func testErrorTypeMappingShouldWork() async throws {
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let alice = try await createClients("alice1")[0]
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let configuration = ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: [],
            custom: CustomConfiguration(
                keyRotationSpan: nil,
                wirePolicy: nil
            )
        )
        try await alice.transaction {
            try await $0.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }

        let expectedError = CoreCryptoError.Mls(
            MlsError.ConversationAlreadyExists(
                conversationId.copyBytes()
            )
        )

        try await alice.transaction { ctx in
            await self.XCTAssertThrowsErrorAsync(expectedError) {
                try await ctx.createConversation(
                    conversationId: conversationId,
                    creatorCredentialType: .basic,
                    config: configuration
                )
            }
        }
    }

    func testGetPublicKeyShouldReturnNonEmptyResult() async throws {
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let alice = try await createClients("alice1")[0]
        let publicKey = try await alice.transaction {
            try await $0.clientPublicKey(
                ciphersuite: ciphersuite,
                credentialType: .basic
            )
        }
        XCTAssertNotNil(publicKey)
    }

    func testConversationExistsShouldReturnTrue() async throws {
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let configuration = ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: [],
            custom: CustomConfiguration(
                keyRotationSpan: nil,
                wirePolicy: nil
            )
        )
        let alice = try await createClients("alice1")[0]
        let resultBefore = try await alice.transaction {
            try await $0.conversationExists(conversationId: conversationId)
        }
        let resultAfter = try await alice.transaction {
            try await $0.createConversation(
                conversationId: conversationId, creatorCredentialType: .basic,
                config: configuration)
            return try await $0.conversationExists(conversationId: conversationId)
        }
        XCTAssertFalse(resultBefore)
        XCTAssertTrue(resultAfter)
    }

    func testUpdateKeyingMaterialShouldProcessTheCommitMessage() async throws {
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let configuration = ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: [],
            custom: CustomConfiguration(
                keyRotationSpan: nil,
                wirePolicy: nil
            )
        )
        let clients = try await createClients("alice1", "bob1")
        let alice = clients[0]
        let bob = clients[1]

        try await bob.transaction {
            try await $0.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }
        let aliceKp = try await alice.transaction {
            try await $0.clientKeypackages(
                ciphersuite: ciphersuite,
                credentialType: .basic,
                amountRequested: 1
            ).first!
        }
        try await bob.transaction {
            _ = try await $0.addClientsToConversation(
                conversationId: conversationId, keyPackages: [aliceKp])
        }
        let welcome = mockMlsTransport.lastCommitBundle?.welcome
        let groupId = try await alice.transaction {
            try await $0.processWelcomeMessage(
                welcomeMessage: welcome!,
                customConfiguration: configuration.custom
            ).id
        }
        try await bob.transaction {
            try await $0.updateKeyingMaterial(conversationId: conversationId)
        }
        let commit = mockMlsTransport.lastCommitBundle?.commit
        let decrypted = try await alice.transaction {
            try await $0.decryptMessage(conversationId: conversationId, payload: commit!)
        }
        XCTAssertNil(decrypted.message)
        XCTAssertNil(decrypted.commitDelay)
        XCTAssertNil(decrypted.senderClientId)
        XCTAssertTrue(decrypted.hasEpochChanged)
    }

    func testEncryptMessageCanBeDecryptedByReceiver() async throws {
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let configuration = ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: [],
            custom: CustomConfiguration(
                keyRotationSpan: nil,
                wirePolicy: nil
            )
        )
        let clients = try await createClients("alice1", "bob1")
        let alice = clients[0]
        let bob = clients[1]

        try await bob.transaction {
            try await $0.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }

        let aliceKp = try await alice.transaction {
            try await $0.clientKeypackages(
                ciphersuite: ciphersuite,
                credentialType: .basic,
                amountRequested: 1
            ).first!
        }
        try await bob.transaction {
            _ = try await $0.addClientsToConversation(
                conversationId: conversationId, keyPackages: [aliceKp])
        }
        let welcome = mockMlsTransport.lastCommitBundle?.welcome
        let groupId = try await alice.transaction {
            try await $0.processWelcomeMessage(
                welcomeMessage: welcome!,
                customConfiguration: configuration.custom
            ).id
        }
        let message = "Hello World !".data(using: .utf8)!
        let ciphertext = try await alice.transaction {
            try await $0.encryptMessage(
                conversationId: conversationId,
                message: message
            )
        }
        XCTAssertNotEqual(ciphertext, message)

        let plaintext = try await bob.transaction {
            try await $0.decryptMessage(conversationId: conversationId, payload: ciphertext).message
        }
        XCTAssertEqual(plaintext, message)

        try await bob.transaction { context in
            await self.XCTAssertThrowsErrorAsync(CoreCryptoError.Mls(.DuplicateMessage)) {
                _ = try await context.decryptMessage(
                    conversationId: conversationId, payload: ciphertext)
            }
        }
    }

    func testRegisterEpochObserverShouldNotifyObserverOnNewEpoch() async throws {
        struct Epoch: Equatable {
            let conversationId: ConversationId
            let epoch: UInt64
        }

        class EpochRecoder: EpochObserver {
            var epochs: [Epoch] = []
            func epochChanged(conversationId: ConversationId, epoch: UInt64) async throws {
                epochs.append(Epoch(conversationId: conversationId, epoch: epoch))
            }
        }

        let aliceId = ClientId(bytes: "alice1".data(using: .utf8)!)
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let configuration = ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: [],
            custom: CustomConfiguration(
                keyRotationSpan: nil,
                wirePolicy: nil
            )
        )

        // set up the conversation in one transaction
        let coreCrypto = try await createCoreCrypto()
        try await coreCrypto.transaction { context in
            try await context.mlsInit(
                clientId: aliceId,
                ciphersuites: [ciphersuite],
                nbKeyPackage: nil
            )
            try await context.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }

        // register the observer
        let epochRecorder = EpochRecoder()
        try await coreCrypto.registerEpochObserver(epochRecorder)

        // in another transaction, change the epoch
        try await coreCrypto.transaction { context in
            try await context.updateKeyingMaterial(conversationId: conversationId)
        }

        XCTAssertEqual(epochRecorder.epochs, [Epoch(conversationId: conversationId, epoch: 1)])
    }

    func testRegisterHistoryObserverShouldNotifyObserverOnNewSecret() async throws {
        struct Secret {
            let conversationId: ConversationId
            let clientId: ClientId
        }

        class HistoryRecoder: HistoryObserver {
            var secrets: [Secret] = []
            func historyClientCreated(conversationId: ConversationId, secret: HistorySecret)
                async throws
            {
                secrets.append(Secret(conversationId: conversationId, clientId: secret.clientId))
            }
        }

        let aliceId = ClientId(bytes: "alice1".data(using: .utf8)!)
        let conversationId = ConversationId(bytes: "conversation1".data(using: .utf8)!)
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let configuration = ConversationConfiguration(
            ciphersuite: ciphersuite,
            externalSenders: [],
            custom: CustomConfiguration(
                keyRotationSpan: nil,
                wirePolicy: nil
            )
        )

        // set up the conversation in one transaction
        let coreCrypto = try await createCoreCrypto()
        try await coreCrypto.transaction {
            try await $0.mlsInit(
                clientId: aliceId,
                ciphersuites: [ciphersuite],
                nbKeyPackage: nil
            )
            try await $0.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }

        // register the observer
        let historyRecorder = HistoryRecoder()
        try await coreCrypto.registerHistoryObserver(historyRecorder)

        // in another transaction, enable history sharing
        try await coreCrypto.transaction {
            try await $0.enableHistorySharing(conversationId: conversationId)
        }

        XCTAssertEqual(historyRecorder.secrets.count, 1)
        XCTAssertEqual(historyRecorder.secrets.first!.conversationId, conversationId)
    }

    // MARK - helpers

    class MockMlsTransport: MlsTransport {

        var lastCommitBundle: CommitBundle?
        var lastMlsMessage: Data?
        var lastHistorySecret: HistorySecret?

        func sendCommitBundle(commitBundle: CommitBundle) async -> MlsTransportResponse {
            lastCommitBundle = commitBundle
            return .success
        }

        func sendMessage(mlsMessage: Data) async -> MlsTransportResponse {
            lastMlsMessage = mlsMessage
            return .success
        }

        func prepareForTransport(historySecret: WireCoreCryptoUniffi.HistorySecret) async
            -> WireCoreCryptoUniffi.MlsTransportData
        {
            lastHistorySecret = historySecret
            return "secret".data(using: .utf8)!
        }

    }

    private func createCoreCrypto() async throws -> CoreCrypto {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let coreCrypto = try await CoreCrypto(
            keystorePath: keystore.absoluteString,
            key: genDatabaseKey()
        )
        try await coreCrypto.provideTransport(transport: mockMlsTransport)
        return coreCrypto
    }

    private func createClients(_ clientIds: String...) async throws -> [CoreCrypto] {
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        var clients: [CoreCrypto] = []
        for clientId in clientIds {
            let coreCrypto = try await createCoreCrypto()
            try await coreCrypto.transaction({
                try await $0.mlsInit(
                    clientId: ClientId(bytes: clientId.data(using: .utf8)!),
                    ciphersuites: [ciphersuite],
                    nbKeyPackage: nil)
            }
            )
            clients.append(coreCrypto)
        }
        return clients
    }

    private func genDatabaseKey() -> DatabaseKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return DatabaseKey(bytes)
    }

    /// Assert that an error is thrown when a block is performed.
    ///
    /// - Parameters:
    ///   - expectedError: The expected error.
    ///   - expression: The expression that should throw the error.
    ///   - message: The error message to show when no error is thrown.
    ///   - file: The file name of the invoking test.
    ///   - line: The line number when this assertion is made.

    // swift-format-ignore: AlwaysUseLowerCamelCase
    func XCTAssertThrowsErrorAsync<E: Error & Equatable>(
        _ expectedError: E,
        when expression: @escaping () async throws -> some Any,
        _ message: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        await XCTAssertThrowsErrorAsync(
            expression,
            message,
            file: file,
            line: line
        ) { error in
            if let error = error as? E {
                XCTAssertEqual(
                    error,
                    expectedError,
                    file: file,
                    line: line
                )
            } else {
                XCTFail(
                    "unexpected error: \(error)",
                    file: file,
                    line: line
                )
            }
        }
    }

    /// Assert that an error is thrown when a block is performed.
    ///
    /// - Parameters:
    ///   - expression: The expression that should throw the error.
    ///   - message: The error message to show when no error is thrown.
    ///   - file: The file name of the invoking test.
    ///   - line: The line number when this assertion is made.
    ///   - errorHandler: A handler for the thrown error.

    // swift-format-ignore: AlwaysUseLowerCamelCase
    func XCTAssertThrowsErrorAsync(
        _ expression: () async throws -> some Any,
        _ message: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line,
        errorHandler: (_ error: any Error) -> Void = { _ in }
    ) async {
        do {
            _ = try await expression()
            XCTFail(
                message ?? "expected an error but none was thrown",
                file: file,
                line: line
            )
        } catch {
            errorHandler(error)
        }
    }

}

// Extension to convert hex string to Data
// https://stackoverflow.com/a/64351862
extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else {
            return nil
        }

        let chars = hex.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        guard hex.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }
}
