import Foundation
import SwiftUI
import WireCoreCrypto

final class TransportProvider: MlsTransport {

    func sendCommitBundle(
        commitBundle: CommitBundle
    ) async {
    }

    func sendMessage(
        mlsMessage: Data
    ) async {
    }

    func prepareForTransport(historySecret: WireCoreCryptoUniffi.HistorySecret) async
        -> WireCoreCryptoUniffi.MlsTransportData
    {
        historySecret.clientId.copyBytes()
    }

}

enum InteropError: String, Error {
    case notInitialised =
        "Unable to perform action since core crypto is not initialised"
    case encodingError = "Failed to encode result"
    case randomBytesError = "Failed to get random bytes"
}

@main
struct InteropClientApp: App {

    @State var coreCrypto: CoreCrypto?

    init() {
        print("Ready")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .onOpenURL(perform: { url in
                    Task {
                        try await handleURL(url: url)
                    }
                })

        }
    }

    /// Generates a random keystore path so we'll start with a new keystore on each launch
    private func generateKeystorePath() throws -> URL {
        let keystorePath = FileManager.default.temporaryDirectory.appending(
            path: "corecrypto/keystore-\(UUID())"
        )

        try FileManager.default.createDirectory(
            at: keystorePath.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        return keystorePath
    }

    private func handleURL(url: URL) async throws {
        let response = await executeURL(url: url)
        let data = try JSONEncoder().encode(response)
        guard let jsonString = String(data: data, encoding: .utf8) else {
            throw EncodingError.invalidValue(
                data,
                EncodingError.Context(codingPath: [], debugDescription: "UTF-8 conversion failed")
            )
        }

        print(jsonString)
    }

    private func executeURL(url: URL) async -> InteropResponse {
        guard let action = InteropAction(url: url) else {
            return .failure(message: "Unknown interop action: \(url)")
        }

        do {
            return .success(value: try await executeAction(action))
        } catch let error {
            return .failure(message: error.localizedDescription)
        }
    }

    private func generateDatabaseKey() throws -> WireCoreCrypto.DatabaseKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        if status != errSecSuccess {
            throw InteropError.randomBytesError
        }
        // swiftlint:disable:next force_try
        return try! WireCoreCrypto.DatabaseKey(bytes: Data(bytes))
    }

    private func genClientId(userId: String = UUID().uuidString) throws -> ClientId {
        let deviceId = String(format: "%016llx", UInt64.random(in: 0...UInt64.max))
        return try ClientId(userId: userId, deviceId: deviceId, domain: "wire.com")
    }

    // swiftlint:disable:next function_body_length cyclomatic_complexity
    private func executeAction(_ action: InteropAction) async throws -> String {
        switch action {
        case .initMLS(let clientIdBytes, let cipherSuite):
            let key = try generateDatabaseKey()
            let keystorePath = try generateKeystorePath()
            let database = try await Database.open(location: keystorePath.path, key: key)
            self.coreCrypto = try CoreCrypto(
                database: database
            )

            let cipherSuite = try cipherSuiteFromU16(discriminant: cipherSuite)
            guard let userId = String(data: clientIdBytes, encoding: .utf8) else {
                throw InteropError.encodingError
            }
            let clientId = try genClientId(userId: userId)
            try await self.coreCrypto?.transaction({ context in
                try await context.mlsInit(
                    clientId: clientId,
                    transport: TransportProvider()
                )
                _ = try await context.addCredential(
                    credential: Credential.basic(cipherSuite: cipherSuite, clientId: clientId))
            })

            return "Initialised MLS with cipherSuite: \(cipherSuite)"

        case .getKeyPackage(let cipherSuite):
            guard let coreCrypto else { throw InteropError.notInitialised }
            let credential = try await coreCrypto.findCredentials(
                cipherSuite: cipherSuiteFromU16(discriminant: cipherSuite),
                credentialType: .basic
            ).first!
            let keyPackage = try await coreCrypto.transaction { ctx in
                return try await ctx.generateKeyPackage(
                    credentialRef: credential,
                    lifetime: nil
                )
            }

            return try keyPackage.serialize().base64EncodedString()

        case .addClient(let conversationId, let cipherSuite, let keyPackage):
            guard let coreCrypto else { throw InteropError.notInitialised }
            let conversationId = ConversationId(bytes: conversationId)
            let cipherSuite = try cipherSuiteFromU16(discriminant: cipherSuite)
            let keyPackage = try KeyPackage(bytes: keyPackage)

            try await coreCrypto.transaction { context in
                let credentialRef = try await coreCrypto.findCredentials(
                    cipherSuite: cipherSuite,
                    credentialType: .basic
                ).first!
                if try await context.conversationExists(
                    conversationId: conversationId) == false
                {
                    try await context.createConversation(
                        conversationId: conversationId,
                        credentialRef: credentialRef, externalSender: nil)
                }
            }

            _ = try await coreCrypto.transaction { ctx in
                try await ctx.addClientsToConversation(
                    conversationId: conversationId,
                    keyPackages: [keyPackage]
                )
            }

            return "added client to conversation"

        case .processWelcome(let welcomePath):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let welcomeMessage = try Welcome(bytes: Data(contentsOf: welcomePath))
            let conversationId = try await coreCrypto.transaction { ctx in
                try await ctx.processWelcomeMessage(
                    welcomeMessage: welcomeMessage
                )
            }

            return conversationId.copyBytes().base64EncodedString()

        case .encryptMessage(let conversationId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }
            let conversationId = ConversationId(bytes: conversationId)

            let encryptedMessage = try await coreCrypto.transaction { ctx in
                try await ctx.encryptMessage(
                    conversationId: conversationId,
                    message: message
                )
            }

            return encryptedMessage.base64EncodedString()

        case .decryptMessage(let conversationId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }
            let conversationId = ConversationId(bytes: conversationId)

            let decryptedMessage = try await coreCrypto.transaction { ctx in
                try await ctx.decryptMessage(
                    conversationId: conversationId,
                    payload: message
                )
            }

            if let plaintext = decryptedMessage.message {
                return plaintext.base64EncodedString()
            } else {
                return "decrypted protocol message"
            }

        case .initProteus:
            if coreCrypto == nil {
                let key = try generateDatabaseKey()
                let database = try await Database.open(
                    location: generateKeystorePath().path, key: key)
                self.coreCrypto = try CoreCrypto(
                    database: database
                )
            }

            try await coreCrypto?.transaction { try await $0.proteusInit() }

            return "Initialised proteus"

        case .getPrekey(let id):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let prekey = try await coreCrypto.transaction { ctx in
                try await ctx.proteusNewPrekey(prekeyId: id)
            }

            return prekey.base64EncodedString()

        case .sessionFromPrekey(let sessionId, let prekey):
            guard let coreCrypto else { throw InteropError.notInitialised }

            try await coreCrypto.transaction { ctx in
                try await ctx.proteusSessionFromPrekey(
                    sessionId: sessionId, prekey: prekey)
            }

            return "Created session from prekey"

        case .sessionFromMessage(let sessionId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let decryptedMessage = try await coreCrypto.transaction { ctx in
                try await ctx.proteusSessionFromMessage(
                    sessionId: sessionId, envelope: message)
            }

            return decryptedMessage.base64EncodedString()

        case .encryptProteusMessage(let sessionId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let encryptedMessage = try await coreCrypto.transaction { ctx in
                try await ctx.proteusEncrypt(
                    sessionId: sessionId, plaintext: message)
            }

            return encryptedMessage.base64EncodedString()

        case .decryptProteusMessage(let sessionId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let decryptedMessasge = try await coreCrypto.transaction { ctx in
                try await ctx.proteusDecrypt(
                    sessionId: sessionId, ciphertext: message)
            }

            return decryptedMessasge.base64EncodedString()

        case .getFingerprint:
            guard let coreCrypto else { throw InteropError.notInitialised }

            let fingerprint = try await coreCrypto.transaction({ ctx in
                try await ctx.proteusFingerprint()
            })

            return fingerprint
        }
    }
}
