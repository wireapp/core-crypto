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

        let database = try await openDatabase(location: keystore.path, key: key)

        let database2 = try await openDatabase(location: keystore.path, key: key)

        XCTAssertNotNil(database)
        XCTAssertNotNil(database2)
    }

    func testDbGetLocationWorks() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let key = genDatabaseKey()

        let database = try await openDatabase(location: keystore.path, key: key)
        let location = try await database.getLocation()
        XCTAssertEqual(keystore.path, location)
    }

    func testOpenExistingDbWithInvalidKeyFails() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let key = genDatabaseKey()

        try await _ = openDatabase(location: keystore.path, key: key)

        let invalidKey = genDatabaseKey()

        await XCTAssertThrowsErrorAsync {
            try await openDatabase(
                location: keystore.path, key: invalidKey
            )
        }
    }

    func testUpdatingDatabaseKeyWorks() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let key1 = genDatabaseKey()
        let database = try await Database.open(location: keystore.path, key: key1)
        var coreCrypto = try CoreCrypto(database: database)

        let clientId = ClientId(bytes: UUID().uuidString.data(using: .utf8)!)
        let ciphersuite = CipherSuite.mls128Dhkemx25519Chacha20poly1305Sha256Ed25519

        let credential = try Credential.basic(ciphersuite: ciphersuite, clientId: clientId)

        let pubkey1 = try await coreCrypto.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId, transport: self.mockMlsTransport)
            let credentialRef = try await ctx.addCredential(credential: credential)
            return credentialRef.publicKeyHash()
        }

        let key2 = genDatabaseKey()
        XCTAssertNotEqual(key1, key2)

        try await database.updateKey(key: key2)

        coreCrypto = try CoreCrypto(database: database)
        let pubkey2 = try await coreCrypto.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId, transport: self.mockMlsTransport)
            return try await ctx.findCredentials(
                clientId: clientId, publicKey: nil, ciphersuite: nil, credentialType: nil,
                earliestValidity: nil
            ).first?.publicKeyHash()

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

        let database = try await Database.open(
            location: targetPath.lastPathComponent, key: newKey)

        // Check if we can read the conversation from the migrated database
        let alice = try CoreCrypto(database: database)
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
        let epoch = try await alice.transaction { ctx in
            try await ctx.conversationEpoch(conversationId: conversationId)
        }
        XCTAssertEqual(1, epoch)

        // The file manager is a singleton used for the entire process, so we better switch back
        FileManager.default.changeCurrentDirectoryPath(oldWorkingDirectory)
        try FileManager.default.removeItem(at: tmpdir)
    }

    func testInteractionWithInvalidContextThrowsError() async throws {
        let aliceId = ClientId(bytes: Data("alice1".utf8))
        let coreCrypto = try await createCoreCrypto()
        var context: CoreCryptoContextProtocol?

        try await coreCrypto.transaction { context = $0 }

        await XCTAssertThrowsErrorAsync {
            try await context?.mlsInit(
                clientId: aliceId,
                transport: mockMlsTransport
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

        let coreCrypto = try await createClients("alice1")[0]
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let expectedError = MyError()

        let credentialRef = try await coreCrypto.transaction { ctx in
            return try await ctx.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite,
                credentialType: nil,
                earliestValidity: nil
            ).first!
        }

        await XCTAssertThrowsErrorAsync(
            expectedError,
            when: {
                try await coreCrypto.transaction { ctx in
                    try await ctx.createConversation(
                        conversationId: conversationId, credentialRef: credentialRef,
                        externalSender: nil)
                    throw expectedError
                }
            }
        )

        // This would fail with a "Conversation already exists" exception, if the above
        // transaction hadn't been rolled back.
        try await coreCrypto.transaction { ctx in
            await ctx.createConversationShort(
                conversationId: conversationId
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
                    database: Database.open(location: keystore.path, key: keystoreKey)
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
        let credentialRef = try await alice.transaction { ctx in
            await ctx.createConversationShort(
                conversationId: conversationId
            )
            return try await ctx.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite,
                credentialType: nil,
                earliestValidity: nil
            ).first!
        }

        let expectedError = CoreCryptoError.Mls(
            mlsError: MlsError.ConversationAlreadyExists(
                conversationId: conversationId.copyBytes()
            ))

        try await alice.transaction { ctx in
            await self.XCTAssertThrowsErrorAsync(expectedError) {
                try await ctx.createConversation(
                    conversationId: conversationId,
                    credentialRef: credentialRef,
                    externalSender: nil
                )
            }
        }
    }

    func testFindCredentialsShouldReturnNonEmptyResult() async throws {
        let alice = try await createClients("alice1")[0]
        let publicKey = try await alice.transaction { ctx in
            try await ctx.findCredentials(
                clientId: nil, publicKey: nil, ciphersuite: nil,
                credentialType: .basic, earliestValidity: nil
            )
        }.first!.publicKeyHash()
        XCTAssertNotNil(publicKey)
    }

    func testCanConstructBasicCredential() async throws {
        let credential = try Credential.basic(
            ciphersuite: ciphersuiteDefault(), clientId: genClientId()
        )
        XCTAssertEqual(credential.type(), CredentialType.basic)
        XCTAssertEqual(credential.earliestValidity(), 0)
    }

    func testCanAddBasicCredential() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let ref = try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                transport: self.mockMlsTransport)
            return try await ctx.addCredential(credential: credential)
        }

        XCTAssertEqual(ref.type(), CredentialType.basic)
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
        let ref = try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                transport: self.mockMlsTransport)
            return try await ctx.addCredential(credential: credential)
        }

        try await alice.transaction { ctx in
            try await ctx.removeCredential(credentialRef: ref)
        }

        let allCredentials = try await alice.transaction { ctx in
            try await ctx.getCredentials()
        }
        XCTAssertEqual(allCredentials.count, 0)
    }

    func testCanSearchCredentialsByCiphersuite() async throws {
        let clientId = genClientId()
        let ciphersuite1 = CipherSuite.mls128Dhkemp256Aes128gcmSha256P256
        let credential1 = try Credential.basic(ciphersuite: ciphersuite1, clientId: clientId)

        let ciphersuite2 = CipherSuite.mls128Dhkemx25519Chacha20poly1305Sha256Ed25519
        let credential2 = try Credential.basic(ciphersuite: ciphersuite2, clientId: clientId)

        let alice = try await createCoreCrypto()
        try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                transport: self.mockMlsTransport
            )
            _ = try await ctx.addCredential(credential: credential1)
            _ = try await ctx.addCredential(credential: credential2)
        }

        let results1 = try await alice.transaction { ctx in
            try await ctx.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite1,
                credentialType: nil,
                earliestValidity: nil
            )
        }
        let results2 = try await alice.transaction { ctx in
            try await ctx.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite2,
                credentialType: nil,
                earliestValidity: nil
            )
        }

        XCTAssertEqual(results1.count, 1)
        XCTAssertEqual(results2.count, 1)
        XCTAssertNotEqual(results1[0].publicKeyHash(), results2[0].publicKeyHash())
    }

    func testConversationExistsShouldReturnTrue() async throws {
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let alice = try await createClients("alice1")[0]

        let credentialRef = try await alice.transaction { ctx in
            return try await ctx.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite,
                credentialType: nil,
                earliestValidity: nil
            ).first!
        }

        let resultBefore = try await alice.transaction { ctx in
            try await ctx.conversationExists(conversationId: conversationId)
        }
        let resultAfter = try await alice.transaction { ctx in
            try await ctx.createConversation(
                conversationId: conversationId, credentialRef: credentialRef, externalSender: nil
            )
            return try await ctx.conversationExists(conversationId: conversationId)
        }
        XCTAssertFalse(resultBefore)
        XCTAssertTrue(resultAfter)
    }

    func testUpdateKeyingMaterialShouldProcessTheCommitMessage() async throws {
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let clients = try await createClients("alice1", "bob1")
        let alice = clients[0]
        let bob = clients[1]

        try await bob.transaction { ctx in
            await ctx.createConversationShort(
                conversationId: conversationId
            )
        }
        let aliceKp = try await alice.transaction { ctx in
            let credential = try await ctx.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite,
                credentialType: .basic,
                earliestValidity: nil
            ).first!

            return try await ctx.generateKeyPackage(
                credentialRef: credential,
                lifetime: nil
            )
        }
        try await bob.transaction { ctx in
            _ = try await ctx.addClientsToConversation(
                conversationId: conversationId, keyPackages: [aliceKp]
            )
        }
        let welcome = await mockMlsTransport.lastCommitBundle?.welcome
        _ = try await alice.transaction { ctx in
            try await ctx.processWelcomeMessage(
                welcomeMessage: welcome!
            )
        }
        try await bob.transaction { ctx in
            try await ctx.updateKeyingMaterial(conversationId: conversationId)
        }
        let commit = await mockMlsTransport.lastCommitBundle?.commit
        let decrypted = try await alice.transaction { ctx in
            try await ctx.decryptMessage(conversationId: conversationId, payload: commit!)
        }
        XCTAssertNil(decrypted.message)
        XCTAssertNil(decrypted.commitDelay)
        XCTAssertNil(decrypted.senderClientId)
    }

    // swiftlint:disable:next function_body_length
    func testEncryptMessageCanBeDecryptedByReceiver() async throws {
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        let clients = try await createClients("alice1", "bob1")
        let alice = clients[0]
        let bob = clients[1]

        try await bob.transaction { ctx in
            await ctx.createConversationShort(
                conversationId: conversationId
            )
        }

        let aliceKp = try await alice.transaction { ctx in
            let credential = try await ctx.findCredentials(
                clientId: nil,
                publicKey: nil,
                ciphersuite: ciphersuite,
                credentialType: .basic,
                earliestValidity: nil
            ).first!

            return try await ctx.generateKeyPackage(
                credentialRef: credential,
                lifetime: nil
            )
        }
        try await bob.transaction { ctx in
            _ = try await ctx.addClientsToConversation(
                conversationId: conversationId, keyPackages: [aliceKp]
            )
        }
        let welcome = await mockMlsTransport.lastCommitBundle?.welcome
        _ = try await alice.transaction { ctx in
            try await ctx.processWelcomeMessage(
                welcomeMessage: welcome!
            )
        }
        let message = Data("Hello World !".utf8)
        let ciphertext = try await alice.transaction { ctx in
            try await ctx.encryptMessage(
                conversationId: conversationId,
                message: message
            )
        }
        XCTAssertNotEqual(ciphertext, message)

        let plaintext = try await bob.transaction { ctx in
            try await ctx.decryptMessage(conversationId: conversationId, payload: ciphertext)
                .message
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

        let coreCrypto = try await createClients("alice")[0]
        let conversationId = ConversationId(bytes: Data("conversation1".utf8))

        // set up the conversation in one transaction
        try await coreCrypto.transaction { context in
            await context.createConversationShort(
                conversationId: conversationId
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

        let conversationId = ConversationId(bytes: Data("conversation1".utf8))
        let coreCrypto = try await createClients("alice")[0]

        // set up the conversation in one transaction
        try await coreCrypto.transaction { ctx in
            await ctx.createConversationShort(
                conversationId: conversationId
            )
        }

        // register the observer
        let historyRecorder = HistoryRecorder()
        try await coreCrypto.registerHistoryObserver(historyRecorder)

        // in another transaction, enable history sharing
        try await coreCrypto.transaction { ctx in
            try await ctx.enableHistorySharing(conversationId: conversationId)
        }

        let recordedSecrets = await historyRecorder.secrets

        XCTAssertEqual(recordedSecrets.count, 1)
        XCTAssertEqual(recordedSecrets.first!.conversationId, conversationId)
    }

    func testCanCreateKeypackage() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                transport: self.mockMlsTransport

            )
            return try await ctx.addCredential(credential: credential)
        }

        let keyPackage = try await alice.transaction { ctx in
            try await ctx.generateKeyPackage(credentialRef: credentialRef, lifetime: nil)
        }

        XCTAssertNotNil(keyPackage)
    }

    func testCanSerializeKeypackage() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                transport: self.mockMlsTransport

            )
            return try await ctx.addCredential(credential: credential)
        }

        let keyPackage = try await alice.transaction { ctx in
            try await ctx.generateKeyPackage(credentialRef: credentialRef, lifetime: nil)
        }

        let bytes = try keyPackage.serialize()
        XCTAssertFalse(bytes.isEmpty)

        // roundtrip
        let kp2 = try KeyPackage(bytes: bytes)
        let bytes2 = try kp2.serialize()

        XCTAssertEqual(bytes, bytes2)
    }

    func testCanRetrieveKeypackagesInBulk() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                transport: self.mockMlsTransport

            )
            return try await ctx.addCredential(credential: credential)
        }

        _ = try await alice.transaction { ctx in
            try await ctx.generateKeyPackage(credentialRef: credentialRef, lifetime: nil)
        }

        let keyPackages = try await alice.transaction { ctx in
            try await ctx.getKeyPackages()
        }

        XCTAssertEqual(keyPackages.count, 1)
        XCTAssertNotNil(keyPackages.first)
    }

    func testCanRemoveKeypackage() async throws {
        let clientId = genClientId()
        let credential = try Credential.basic(ciphersuite: ciphersuiteDefault(), clientId: clientId)

        let alice = try await createCoreCrypto()
        let credentialRef = try await alice.transaction { ctx in
            try await ctx.mlsInit(
                clientId: clientId,
                transport: self.mockMlsTransport
            )
            return try await ctx.addCredential(credential: credential)
        }

        // add a kp which will not be removed
        _ = try await alice.transaction { ctx in
            try await ctx.generateKeyPackage(credentialRef: credentialRef, lifetime: nil)
        }

        // add a kp which will be removed
        let keyPackage = try await alice.transaction { ctx in
            try await ctx.generateKeyPackage(credentialRef: credentialRef, lifetime: nil)
        }

        // remove the keypackage
        try await alice.transaction { ctx in
            try await ctx.removeKeyPackage(kpRef: try keyPackage.ref())
        }

        let keyPackages = try await alice.transaction { ctx in
            try await ctx.getKeyPackages()
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
                transport: self.mockMlsTransport

            )
            let cref1 = try await ctx.addCredential(credential: credential1)
            let cref2 = try await ctx.addCredential(credential: credential2)

            let keypackagesPerCredential = 2
            for cref in [cref1, cref2] {
                for _ in 0..<keypackagesPerCredential {
                    _ = try await ctx.generateKeyPackage(credentialRef: cref, lifetime: nil)
                }
            }

            let kpsBeforeRemoval = try await ctx.getKeyPackages()
            XCTAssertEqual(kpsBeforeRemoval.count, keypackagesPerCredential * 2)

            // remove all keypackages for one of the credentials
            try await ctx.removeKeyPackagesFor(credentialRef: cref1)

            let kps = try await ctx.getKeyPackages()
            XCTAssertEqual(kps.count, keypackagesPerCredential)
        }
    }

    func testCanSetPkiEnvironment() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "pki-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let database = try await Database.open(location: keystore.path, key: genDatabaseKey())

        let pkiEnvironment = try await PkiEnvironment(
            hooks: MockPkiEnvironmentHooks(), database: database)
        let coreCrypto = try CoreCrypto(database: database)
        try await coreCrypto.setPkiEnvironment(pkiEnvironment: pkiEnvironment)
        let pkiEnvironment2 = await coreCrypto.getPkiEnvironment()
        XCTAssertNotNil(pkiEnvironment2)

        try await coreCrypto.setPkiEnvironment(pkiEnvironment: nil)
        let pkiEnvironment3 = await coreCrypto.getPkiEnvironment()
        XCTAssertNil(pkiEnvironment3)
    }

    func testCanInstantiateX509CredentialAcquisition() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "pki-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let database = try await Database.open(location: keystore.path, key: genDatabaseKey())

        let pkiEnvironment = try await PkiEnvironment(
            hooks: MockPkiEnvironmentHooks(), database: database)
        let clientId = ClientId(
            bytes: Data("LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com".utf8))

        let acquisition = try X509CredentialAcquisition(
            pkiEnvironment: pkiEnvironment,
            config: X509CredentialAcquisitionConfiguration(
                acmeUrl: "acme.example.com",
                idpUrl: "https://idp.example.com",
                ciphersuite: ciphersuiteDefault(),
                displayName: "Alice Smith",
                clientId: clientId,
                handle: "alice_wire",
                domain: "world.com",
                team: nil,
                validityPeriodSecs: 3600
            )
        )

        XCTAssertNotNil(acquisition)
    }

    func testParseJwkProducesSenderUsableInCreateConversation() async throws {
        let jwk = generateEd25519Jwk()
        let externalSender = try ExternalSender.parseJwk(jwk: jwk)
        let alice = try await createClients("alice1")[0]
        let conversationId = ConversationId(bytes: Data("ext-sender-jwk".utf8))

        let retrievedKey = try await alice.transaction { ctx -> ExternalSenderKey in
            let credentialRef = try await ctx.findCredentials(
                clientId: nil, publicKey: nil, ciphersuite: nil,
                credentialType: nil, earliestValidity: nil
            ).first!
            try await ctx.createConversation(
                conversationId: conversationId,
                credentialRef: credentialRef,
                externalSender: externalSender
            )
            return try await ctx.getExternalSender(conversationId: conversationId)
        }

        XCTAssertEqual(retrievedKey.copyBytes(), externalSender.serialize())
    }

    func testParsePublicKeyAcceptsBytesProducedBySerialize() throws {
        let fromJwk = try ExternalSender.parseJwk(jwk: generateEd25519Jwk())
        let fromBytes = try ExternalSender.parsePublicKey(
            key: fromJwk.serialize(),
            signatureScheme: .ed25519
        )
        XCTAssertEqual(fromJwk, fromBytes)
    }

    func testParseJwkRejectsMalformedBytes() {
        XCTAssertThrowsError(try ExternalSender.parseJwk(jwk: Data([0, 1, 2, 3])))
    }

    // MARK: - helpers

    final actor MockMlsTransport: MlsTransport {
        var lastCommitBundle: CommitBundle?
        var lastMlsMessage: Data?
        var lastHistorySecret: HistorySecret?

        func sendCommitBundle(commitBundle: CommitBundle) async {
            lastCommitBundle = commitBundle
        }

        func sendMessage(mlsMessage: Data) async {
            lastMlsMessage = mlsMessage
        }

        func prepareForTransport(historySecret: WireCoreCryptoUniffi.HistorySecret) async
            -> WireCoreCryptoUniffi.MlsTransportData
        {
            lastHistorySecret = historySecret
            return Data("secret".utf8)
        }
    }

    final actor MockPkiEnvironmentHooks: PkiEnvironmentHooks {
        func httpRequest(
            method: HttpMethod,
            url: String,
            headers: [HttpHeader],
            body: Data
        ) async -> HttpResponse {
            return HttpResponse(
                status: 200,
                headers: [],
                body: Data()
            )
        }

        func authenticate(
            idp: String,
            keyAuth: String,
            acmeAud: String
        ) async -> String {
            return "mock-id-token"
        }

        func getBackendNonce() async -> String {
            return "mock-backend-nonce"
        }

        func fetchBackendAccessToken(
            dpop: String
        ) async -> String {
            return "mock-backend-access-token"
        }
    }

    private func createCoreCrypto() async throws -> CoreCrypto {
        let root = FileManager.default.temporaryDirectory.appending(path: "mls")
        let keystore = root.appending(path: "keystore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let database = try await Database.open(location: keystore.path, key: genDatabaseKey())
        let coreCrypto = try CoreCrypto(
            database: database
        )
        return coreCrypto
    }

    private func createClients(_ clientIds: String...) async throws -> [CoreCrypto] {
        let ciphersuite = try ciphersuiteFromU16(discriminant: 2)
        var clients: [CoreCrypto] = []
        for clientId in clientIds {
            let clientId = ClientId(bytes: clientId.data(using: .utf8)!)
            let coreCrypto = try await createCoreCrypto()
            try await coreCrypto.transaction({ ctx in
                try await ctx.mlsInit(
                    clientId: clientId,
                    transport: self.mockMlsTransport
                )
                _ = try await ctx.addCredential(
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
        return try! DatabaseKey(bytes: Data(bytes))
    }

    func genClientId() -> ClientId {
        ClientId(bytes: withUnsafeBytes(of: UUID().uuid) { Data($0) })
    }

    private func generateEd25519Jwk() -> Data {
        let base64PublicKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
            .base64URLEncodedString()
        return Data(#"{"kty":"OKP","crv":"Ed25519","x":"\#(base64PublicKey)"}"#.utf8)
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

extension CoreCryptoContextProtocol {
    func createConversationShort(conversationId: ConversationId) async {
        // swiftlint:disable:next force_try
        let ciphersuite = try! ciphersuiteFromU16(discriminant: 2)
        // swiftlint:disable:next force_try
        let credential = try! await self.findCredentials(
            clientId: nil,
            publicKey: nil,
            ciphersuite: ciphersuite,
            credentialType: .basic,
            earliestValidity: nil
        ).first!

        // swiftlint:disable:next force_try
        try! await self.createConversation(
            conversationId: conversationId, credentialRef: credential, externalSender: nil)
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

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
