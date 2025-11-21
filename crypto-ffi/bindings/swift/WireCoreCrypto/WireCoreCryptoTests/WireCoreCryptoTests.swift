import CryptoKit
import Foundation
import WireCoreCrypto
import XCTest

// swiftlint:disable file_length
// swiftlint:disable:next type_body_length
final class WireCoreCryptoTests: XCTestCase {
    var mockMlsTransport: MockMlsTransport = .init()

    override func setUpWithError() throws {
        mockMlsTransport = MockMlsTransport()
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testSetClientDataPersists() async throws {
        let coreCrypto = try await createCoreCrypto()
        let data = Data("my message processing checkpoint".utf8)

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

    func testOpenExistingDbWorks() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let key = genDatabaseKey()

        let database = try await openDatabase(name: keystore.path, key: key)

        let database2 = try await openDatabase(name: keystore.path, key: key)

        XCTAssertNotNil(database)
        XCTAssertNotNil(database2)
    }

    func testOpenExistingDbWithInvalidKeyFails() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let key = genDatabaseKey()

        try await _ = openDatabase(name: keystore.path, key: key)

        let invalidKey = genDatabaseKey()

        await XCTAssertThrowsErrorAsync {
            try await openDatabase(
                name: keystore.path, key: invalidKey
            )
        }
    }

    func testUpdatingDatabaseKeyWorks() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let key1 = genDatabaseKey()
        let database1 = try await Database(keystorePath: keystore.path, key: key1)
        var coreCrypto = try await CoreCrypto(database: database1)

        let clientId = ClientId(bytes: UUID().uuidString.data(using: .utf8)!)
        let ciphersuite = Ciphersuite.mls128Dhkemx25519Chacha20poly1305Sha256Ed25519

        let credential = try Credential.basic(ciphersuite: ciphersuite, clientId: clientId)

        let pubkey1 = try await coreCrypto.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuite])
            try await $0.addCredential(credential: credential)
            return try await $0.clientPublicKey(
                ciphersuite: ciphersuite, credentialType: CredentialType.basic
            )
        }

        let key2 = genDatabaseKey()
        XCTAssertNotEqual(key1, key2)

        try await updateDatabaseKey(name: keystore.path, oldKey: key1, newKey: key2)
        let database2 = try await Database(keystorePath: keystore.path, key: key2)

        coreCrypto = try await CoreCrypto(database: database2)
        let pubkey2 = try await coreCrypto.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuite])
            return try await $0.clientPublicKey(
                ciphersuite: ciphersuite, credentialType: CredentialType.basic
            )
        }
        XCTAssertEqual(pubkey1, pubkey2)
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

        // The keystore path has to be the same over different instances of the test,
        // because of handle_ios_wal_compat().
        // Change the working directory so that we can use a relative path for the keystore path.
        let oldWorkingDirectory = FileManager.default.currentDirectoryPath
        FileManager.default.changeCurrentDirectoryPath(tmpdir.path())

        // Now migrate the database to the new key format
        let oldKey = "secret"
        let newKey = genDatabaseKey()
        try await migrateDatabaseKeyTypeToBytes(
            path: targetPath.lastPathComponent, oldKey: oldKey, newKey: newKey
        )

        let database = try await Database(keystorePath: targetPath.lastPathComponent, key: newKey)

        // Check if we can read the conversation from the migrated database
        let alice = try await CoreCrypto(database: database)
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
        let aliceId = ClientId(bytes: Data("alice1".utf8))
        let coreCrypto = try await createCoreCrypto()
        var context: CoreCryptoContextProtocol?

        try await coreCrypto.transaction { context = $0 }

        await XCTAssertThrowsErrorAsync {
            try await context?.mlsInit(
                clientId: aliceId,
                ciphersuites: [ciphersuite]
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
            }
        )
    }

    func testTransactionRollsBackOnError() async throws {
        struct MyError: Error, Equatable {}

        let aliceId = ClientId(bytes: Data("alice1".utf8))
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
                ciphersuites: [ciphersuite]
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
            }
        )

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
            "Expected all transactions to complete"
        )
    }

    func testParallelTransactionsArePerformedSeriallyAcrossMultipleCoreCryptoInstances()
        async throws
    {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        let keystoreKey = genDatabaseKey()
        let token = "t"
        let transactionCount = 3
        var coreCryptoInstances: [CoreCrypto] = []

        for _ in 0..<transactionCount {
            try coreCryptoInstances.append(
                await CoreCrypto(
                    database: Database(keystorePath: keystore.path, key: keystoreKey)
                )
            )
        }

        // How this test ensures that transactions are performed serially:
        // Each transaction gets the previous token string, adds one token at the end and stores it.
        // If, for instance, the second and third transaction run in parallel they will both get same current
        // token string "tt" and store "ttt".
        // If they execute serially, one will store "ttt" and the other "tttt" (this is what we assert).

        let result = try await withThrowingTaskGroup(of: Void.self) { group in
            for idx in 0..<transactionCount {
                group.addTask {
                    try await coreCryptoInstances[idx].transaction { ctx in
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

            let result = try await coreCryptoInstances[0].transaction { ctx in
                try await ctx.getData().map { String(data: $0, encoding: .utf8)! }
            }

            return result
        }

        XCTAssertEqual(
            String(repeating: token, count: transactionCount), result,
            "Expected all transactions to complete"
        )
    }

    func testErrorTypeMappingShouldWork() async throws {
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
            mlsError: MlsError.ConversationAlreadyExists(
                conversationId: conversationId.copyBytes()
            ))

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

    func testCanConstructBasicCredential() async throws {
        let credential = try Credential.basic(
            ciphersuite: ciphersuiteDefault(), clientId: genClientId()
        )
        XCTAssertEqual(try credential.type(), CredentialType.basic)
        XCTAssertEqual(credential.earliestValidity(), 0)
    }

    func testCanAddBasicCredential() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let ref = try await alice.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuiteDefault()])
            return try await $0.addCredential(credential: credential)
        }

        XCTAssertEqual(try ref.type(), CredentialType.basic)
        XCTAssertNotEqual(ref.earliestValidity(), 0)

        let allCredentials = try await alice.transaction { ctx in
            try await ctx.getCredentials()
        }
        XCTAssertEqual(allCredentials.count, 1)
    }

    func testCanRemoveBasicCredential() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let ref = try await alice.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuiteDefault()])
            return try await $0.addCredential(credential: credential)
        }

        try await alice.transaction {
            try await $0.removeCredential(credentialRef: ref)
        }

        let allCredentials = try await alice.transaction {
            try await $0.getCredentials()
        }
        XCTAssertEqual(allCredentials.count, 0)
    }

    func testCanSearchCredentialsByCiphersuite() async throws {
        let clientId = genClientId()
        let ciphersuite1 = Ciphersuite.mls128Dhkemp256Aes128gcmSha256P256
        let credential1 = try Credential.basic(ciphersuite: ciphersuite1, clientId: clientId)

        let ciphersuite2 = Ciphersuite.mls128Dhkemx25519Chacha20poly1305Sha256Ed25519
        let credential2 = try Credential.basic(ciphersuite: ciphersuite2, clientId: clientId)

        let alice = try await createCoreCrypto()
        try await alice.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuiteDefault()])
            try await $0.addCredential(credential: credential1)
            try await $0.addCredential(credential: credential2)
        }

        let results1 = try await alice.transaction {
            try await $0.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite1,
                credentialType: nil,
                earliestValidity: nil
            )
        }
        let results2 = try await alice.transaction {
            try await $0.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite2,
                credentialType: nil,
                earliestValidity: nil
            )
        }

        XCTAssertEqual(results1.count, 1)
        XCTAssertEqual(results2.count, 1)
        XCTAssertNotEqual(results1[0].publicKey(), results2[0].publicKey())
    }

    func testConversationExistsShouldReturnTrue() async throws {
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
                config: configuration
            )
            return try await $0.conversationExists(conversationId: conversationId)
        }
        XCTAssertFalse(resultBefore)
        XCTAssertTrue(resultAfter)
    }

    func testUpdateKeyingMaterialShouldProcessTheCommitMessage() async throws {
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
                conversationId: conversationId, keyPackages: [aliceKp]
            )
        }
        let welcome = await mockMlsTransport.lastCommitBundle?.welcome
        _ = try await alice.transaction {
            try await $0.processWelcomeMessage(
                welcomeMessage: welcome!,
                customConfiguration: configuration.custom
            ).id
        }
        try await bob.transaction {
            try await $0.updateKeyingMaterial(conversationId: conversationId)
        }
        let commit = await mockMlsTransport.lastCommitBundle?.commit
        let decrypted = try await alice.transaction {
            try await $0.decryptMessage(conversationId: conversationId, payload: commit!)
        }
        XCTAssertNil(decrypted.message)
        XCTAssertNil(decrypted.commitDelay)
        XCTAssertNil(decrypted.senderClientId)
        XCTAssertTrue(decrypted.hasEpochChanged)
    }

    // swiftlint:disable:next function_body_length
    func testEncryptMessageCanBeDecryptedByReceiver() async throws {
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
                conversationId: conversationId, keyPackages: [aliceKp]
            )
        }
        let welcome = await mockMlsTransport.lastCommitBundle?.welcome
        _ = try await alice.transaction {
            try await $0.processWelcomeMessage(
                welcomeMessage: welcome!,
                customConfiguration: configuration.custom
            ).id
        }
        let message = Data("Hello World !".utf8)
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
            await self.XCTAssertThrowsErrorAsync(CoreCryptoError.Mls(mlsError: .DuplicateMessage)) {
                _ = try await context.decryptMessage(
                    conversationId: conversationId, payload: ciphertext
                )
            }
        }
    }

    func testRegisterEpochObserverShouldNotifyObserverOnNewEpoch() async throws {
        struct Epoch: Equatable {
            let conversationId: ConversationId
            let epoch: UInt64
        }

        final actor EpochRecorder: EpochObserver {
            var epochs: [Epoch] = []
            func epochChanged(conversationId: ConversationId, epoch: UInt64) async throws {
                epochs.append(Epoch(conversationId: conversationId, epoch: epoch))
            }
        }

        let aliceId = ClientId(bytes: Data("alice1".utf8))
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
                ciphersuites: [ciphersuite]
            )
            try await context.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }

        // register the observer
        let epochRecorder = EpochRecorder()
        try await coreCrypto.registerEpochObserver(epochRecorder)

        // in another transaction, change the epoch
        try await coreCrypto.transaction { context in
            try await context.updateKeyingMaterial(conversationId: conversationId)
        }

        let recordedEpochs = await epochRecorder.epochs

        XCTAssertEqual(recordedEpochs, [Epoch(conversationId: conversationId, epoch: 1)])
    }

    func testRegisterHistoryObserverShouldNotifyObserverOnNewSecret() async throws {
        struct Secret {
            let conversationId: ConversationId
            let clientId: ClientId
        }

        final actor HistoryRecorder: HistoryObserver {
            var secrets: [Secret] = []
            func historyClientCreated(conversationId: ConversationId, secret: HistorySecret)
                async throws
            {
                secrets.append(Secret(conversationId: conversationId, clientId: secret.clientId))
            }
        }

        let aliceId = ClientId(bytes: Data("alice1".utf8))
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
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
                ciphersuites: [ciphersuite]
            )
            try await $0.createConversation(
                conversationId: conversationId,
                creatorCredentialType: .basic,
                config: configuration
            )
        }

        // register the observer
        let historyRecorder = HistoryRecorder()
        try await coreCrypto.registerHistoryObserver(historyRecorder)

        // in another transaction, enable history sharing
        try await coreCrypto.transaction {
            try await $0.enableHistorySharing(conversationId: conversationId)
        }

        let recordedSecrets = await historyRecorder.secrets

        XCTAssertEqual(recordedSecrets.count, 1)
        XCTAssertEqual(recordedSecrets.first!.conversationId, conversationId)
    }

    func testCanCreateKeypackage() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuiteDefault()])
            return try await $0.addCredential(credential: credential)
        }

        let keyPackage = try await alice.transaction {
            try await $0.generateKeypackage(credentialRef: credentialRef, lifetime: nil)
        }

        XCTAssertNotNil(keyPackage)
    }

    func testCanSerializeKeypackage() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuiteDefault()])
            return try await $0.addCredential(credential: credential)
        }

        let keyPackage = try await alice.transaction {
            try await $0.generateKeypackage(credentialRef: credentialRef, lifetime: nil)
        }

        let bytes = try keyPackage.serialize()
        XCTAssertFalse(bytes.isEmpty)

        // roundtrip
        let kp2 = try Keypackage(bytes: bytes)
        let bytes2 = try kp2.serialize()

        XCTAssertEqual(bytes, bytes2)
    }

    func testCanRetrieveKeypackagesInBulk() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuiteDefault()])
            return try await $0.addCredential(credential: credential)
        }

        _ = try await alice.transaction {
            try await $0.generateKeypackage(credentialRef: credentialRef, lifetime: nil)
        }

        let keyPackages = try await alice.transaction { ctx in
            try await ctx.getKeypackages()
        }

        XCTAssertEqual(keyPackages.count, 1)
        XCTAssertNotNil(keyPackages.first)
    }

    func testCanRemoveKeypackage() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction {
            try await $0.mlsInit(clientId: clientId, ciphersuites: [ciphersuiteDefault()])
            return try await $0.addCredential(credential: credential)
        }

        // add a kp which will not be removed
        _ = try await alice.transaction {
            try await $0.generateKeypackage(credentialRef: credentialRef, lifetime: nil)
        }

        // add a kp which will be removed
        let keyPackage = try await alice.transaction {
            try await $0.generateKeypackage(credentialRef: credentialRef, lifetime: nil)
        }

        // remove the keypackage
        try await alice.transaction {
            try await $0.removeKeypackage(kpRef: try keyPackage.ref())
        }

        let keyPackages = try await alice.transaction { ctx in
            try await ctx.getKeypackages()
        }

        XCTAssertEqual(keyPackages.count, 1)
    }

    func testCanRemoveKeypackagesByCredentialRef() async throws {
        let clientId = genClientId()
        let credential1 = try Credential.basic(
            ciphersuite: .mls128Dhkemx25519Aes128gcmSha256Ed25519,
            clientId: clientId
        )
        let credential2 = try Credential.basic(
            ciphersuite: .mls128Dhkemp256Aes128gcmSha256P256,
            clientId: clientId
        )

        let alice = try await createCoreCrypto()

        try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                ciphersuites: [
                    .mls128Dhkemx25519Aes128gcmSha256Ed25519,
                    .mls128Dhkemp256Aes128gcmSha256P256,
                ])
            let cref1 = try await ctx.addCredential(credential: credential1)
            let cref2 = try await ctx.addCredential(credential: credential2)

            let keypackagesPerCredential = 2
            for cref in [cref1, cref2] {
                for _ in 0..<keypackagesPerCredential {
                    _ = try await ctx.generateKeypackage(credentialRef: cref, lifetime: nil)
                }
            }

            let kpsBeforeRemoval = try await ctx.getKeypackages()
            XCTAssertEqual(kpsBeforeRemoval.count, keypackagesPerCredential * 2)

            // remove all keypackages for one of the credentials
            try await ctx.removeKeypackagesFor(credentialRef: cref1)

            let kps = try await ctx.getKeypackages()
            XCTAssertEqual(kps.count, keypackagesPerCredential)
        }
    }

    // MARK: - helpers

    final actor MockMlsTransport: MlsTransport {
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
            return Data("secret".utf8)
        }
    }

    private func createCoreCrypto() async throws -> CoreCrypto {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let database = try await Database(keystorePath: keystore.path, key: genDatabaseKey())
        let coreCrypto = try await CoreCrypto(
            database: database
        )
        try await coreCrypto.provideTransport(transport: mockMlsTransport)
        return coreCrypto
    }

    private func createClients(_ clientIds: String...) async throws -> [CoreCrypto] {
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        var clients: [CoreCrypto] = []
        for clientId in clientIds {
            var clientId = ClientId(bytes: clientId.data(using: .utf8)!)
            let coreCrypto = try await createCoreCrypto()
            try await coreCrypto.transaction({
                try await $0.mlsInit(
                    clientId: clientId,
                    ciphersuites: [ciphersuite]
                )
                try await $0.addCredential(
                    credential: Credential.basic(
                        ciphersuite: ciphersuite,
                        clientId: clientId
                    )
                )
            }
            )
            clients.append(coreCrypto)
        }
        return clients
    }

    private func genDatabaseKey() -> DatabaseKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        // constructor only fails if we have other than 32 bytes
        // swiftlint:disable:next force_try
        return try! DatabaseKey(key: Data(bytes))
    }

    func genClientId() -> ClientId {
        ClientId(bytes: withUnsafeBytes(of: UUID().uuid) { Data($0) })
    }

    // swift-format-ignore: AlwaysUseLowerCamelCase
    /// Assert that an error is thrown when a block is performed.
    ///
    /// - Parameters:
    ///   - expectedError: The expected error.
    ///   - expression: The expression that should throw the error.
    ///   - message: The error message to show when no error is thrown.
    ///   - file: The file name of the invoking test.
    ///   - line: The line number when this assertion is made.
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

    // swift-format-ignore: AlwaysUseLowerCamelCase
    /// Assert that an error is thrown when a block is performed.
    ///
    /// - Parameters:
    ///   - expression: The expression that should throw the error.
    ///   - message: The error message to show when no error is thrown.
    ///   - file: The file name of the invoking test.
    ///   - line: The line number when this assertion is made.
    ///   - errorHandler: A handler for the thrown error.
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
