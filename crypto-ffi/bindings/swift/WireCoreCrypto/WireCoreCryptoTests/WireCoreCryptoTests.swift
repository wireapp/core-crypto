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

    func testExternallyGeneratedClientIdShouldInitTheMLSClient() async throws {
        let ciphersuite: Ciphersuite = 2
        let alice = try await createCoreCrypto()
        let aliceId = "alice1".data(using: .utf8)!
        let handle = try await alice.transaction {
            try await $0.mlsGenerateKeypairs(ciphersuites: [ciphersuite])
        }
        try await alice.transaction {
            try await $0.mlsInitWithClientId(
                clientId: aliceId,
                tmpClientIds: handle,
                ciphersuites: [ciphersuite]
            )
        }
    }

    func testInteractionWithInvalidContextThrowsError() async throws {
        let ciphersuite: Ciphersuite = 2
        let aliceId = "alice1".data(using: .utf8)!
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
        struct MyError: Error {}

        let coreCrypto = try await createCoreCrypto()
        let expectedError = MyError()

        await XCTAssertThrowsErrorAsync({
            try await coreCrypto.transaction { _ in
                throw expectedError
            }
        })
    }

    func testTransactionRollsBackOnError() async throws {
        struct MyError: Error {}

        let aliceId = "alice1".data(using: .utf8)!
        let conversationId = "conversation1".data(using: .utf8)!
        let ciphersuite: Ciphersuite = 2
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
            try await $0.mlsInit(clientId: aliceId, ciphersuites: [ciphersuite], nbKeyPackage: nil)
        }

        await XCTAssertThrowsErrorAsync({
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
        let conversationId = "conversation1".data(using: .utf8)!
        let alice = try await createClients("alice1")[0]
        let ciphersuite: Ciphersuite = 2
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

        let expectedError = CoreCryptoError.Mls(MlsError.ConversationAlreadyExists(conversationId))

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
        let ciphersuite: Ciphersuite = 2
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
        let conversationId = "conversation1".data(using: .utf8)!
        let ciphersuite: Ciphersuite = 2
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
        let conversationId = "conversation1".data(using: .utf8)!
        let ciphersuite: Ciphersuite = 2
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
        let conversationId = "conversation1".data(using: .utf8)!
        let ciphersuite: Ciphersuite = 2
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
            let conversationId: Data
            let epoch: UInt64
        }

        class EpochRecoder: EpochObserver {
            var epochs: [Epoch] = []
            func epochChanged(conversationId: Data, epoch: UInt64) async throws {
                epochs.append(Epoch(conversationId: conversationId, epoch: epoch))
            }
        }

        let clientId = "client1".data(using: .utf8)!
        let conversationId = "conversation1".data(using: .utf8)!
        let ciphersuite: Ciphersuite = 2
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
                clientId: clientId, ciphersuites: [ciphersuite], nbKeyPackage: nil)
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

    // MARK - helpers

    class MockMlsTransport: MlsTransport {

        var lastCommitBundle: CommitBundle?
        var lastMlsMessage: Data?

        func sendCommitBundle(commitBundle: CommitBundle) async -> MlsTransportResponse {
            lastCommitBundle = commitBundle
            return .success
        }

        func sendMessage(mlsMessage: Data) async -> MlsTransportResponse {
            lastMlsMessage = mlsMessage
            return .success
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
        let ciphersuite: Ciphersuite = 2
        var clients: [CoreCrypto] = []
        for clientId in clientIds {
            let coreCrypto = try await createCoreCrypto()
            try await coreCrypto.transaction({
                try await $0.mlsInit(
                    clientId: clientId.data(using: .utf8)!,
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
