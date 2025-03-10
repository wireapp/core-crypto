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

import Foundation
import SwiftUI
import WireCoreCrypto

class TransportProvider: MlsTransport {

    func sendCommitBundle(
        commitBundle: CommitBundle
    ) async -> MlsTransportResponse {
        .success
    }

    func sendMessage(
        mlsMessage: Data
    ) async -> MlsTransportResponse {
        .success
    }

}

enum InteropError: String, Error {
    case notInitialised =
        "Unable to perform action since core crypto is not initialised"
    case encodingError = "Failed to encode result"
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
    private func generateKeystorePath() -> String {
        FileManager.default.temporaryDirectory.appending(
            path: "keystore-\(UUID())",
            directoryHint: .notDirectory
        ).absoluteString
    }

    private func handleURL(url: URL) async throws {
        let response = await executeURL(url: url)
        print(
            String(decoding: try JSONEncoder().encode(response), as: UTF8.self))
    }

    private func executeURL(url: URL) async -> InteropResponse {
        guard let action = InteropAction(url: url) else {
            return .failure(message: "Unknown interop action: \(url)")
        }

        do {
            return .success(value: try await executeAction(action))
        } catch (let error) {
            return .failure(message: error.localizedDescription)
        }
    }

    private func executeAction(_ action: InteropAction) async throws -> String {
        switch action {
        case .initMLS(let clientId, let ciphersuite):
            self.coreCrypto = try await CoreCrypto(
                keystorePath: generateKeystorePath(),
                keystoreSecret: "secret".data(using: .utf8)!
            )

            try await self.coreCrypto?.provideTransport(
                transport: TransportProvider())
            
            try await self.coreCrypto?.transaction({ context in
                try await context.mlsInit(
                    clientId: clientId,
                    ciphersuites: [ciphersuite],
                    nbKeyPackage: nil)
            })

            return "Initialised MLS with ciphersuite: \(ciphersuite)"

        case .getKeyPackage(let ciphersuite):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let keyPackage = try await coreCrypto.transaction {
                try await $0.clientKeypackages(
                    ciphersuite: ciphersuite,
                    credentialType: .basic,
                    amountRequested: 1)
            }

            if let encodedKeyPackage = keyPackage.first.map({
                $0.base64EncodedString()
            }) {
                return encodedKeyPackage
            } else {
                throw InteropError.encodingError
            }

        case .addClient(let conversationId, let ciphersuite, let keyPackage):
            guard let coreCrypto else { throw InteropError.notInitialised }
            
            try await coreCrypto.transaction { context in
                if try await context.conversationExists(
                    conversationId: conversationId) == false {
                    
                    let customConfiguration = CustomConfiguration(
                        keyRotationSpan: nil, wirePolicy: nil)
                    let conversationConfiguration = ConversationConfiguration(
                        ciphersuite: ciphersuite,
                        externalSenders: [],
                        custom: customConfiguration
                    )

                    try await context.createConversation(
                        conversationId: conversationId,
                        creatorCredentialType: .basic,
                        config: conversationConfiguration)
                }
            }

            _ = try await coreCrypto.transaction {
                try await $0.addClientsToConversation(
                    conversationId: conversationId,
                    keyPackages: [keyPackage]
                )
            }

            return "added client to conversation"

        case .removeClient(let conversationId, let clientId):
            guard let coreCrypto else { throw InteropError.notInitialised }

            _ = try await coreCrypto.transaction {
                try await $0.removeClientsFromConversation(
                    conversationId: conversationId,
                    clients: [clientId]
                )
            }

            return "removed client from conversation"

        case .processWelcome(let welcomePath):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let welcomeMessage = try Data(contentsOf: welcomePath)
            let configuration = CustomConfiguration(
                keyRotationSpan: nil, wirePolicy: nil)
            let bundle = try await coreCrypto.transaction {
                try await $0.processWelcomeMessage(
                    welcomeMessage: welcomeMessage,
                    customConfiguration: configuration
                )
            }

            return bundle.id.base64EncodedString()

        case .encryptMessage(let conversationId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let encryptedMessage = try await coreCrypto.transaction {
                try await $0.encryptMessage(
                    conversationId: conversationId,
                    message: message
                )
            }

            return encryptedMessage.base64EncodedString()

        case .decryptMessage(let conversationId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let decryptedMessage = try await coreCrypto.transaction {
                try await $0.decryptMessage(
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
                self.coreCrypto = try await CoreCrypto(
                    keystorePath: generateKeystorePath(),
                    keystoreSecret: "secret".data(using: .utf8)!
                )

                try await self.coreCrypto?.provideTransport(
                    transport: TransportProvider())
            }

            try await coreCrypto?.transaction { try await $0.proteusInit() }

            return "Initialised proteus"

        case .getPrekey(let id):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let prekey = try await coreCrypto.transaction {
                try await $0.proteusNewPrekey(prekeyId: id)
            }

            return prekey.base64EncodedString()

        case .sessionFromPrekey(let sessionId, let prekey):
            guard let coreCrypto else { throw InteropError.notInitialised }

            try await coreCrypto.transaction {
                try await $0.proteusSessionFromPrekey(
                    sessionId: sessionId, prekey: prekey)
            }

            return "Created session from prekey"

        case .sessionFromMessage(let sessionId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let decryptedMessage = try await coreCrypto.transaction {
                try await $0.proteusSessionFromMessage(
                    sessionId: sessionId, envelope: message)
            }

            return decryptedMessage.base64EncodedString()

        case .encryptProteusMessage(let sessionId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let encryptedMessage = try await coreCrypto.transaction {
                try await $0.proteusEncrypt(
                    sessionId: sessionId, plaintext: message)
            }

            return encryptedMessage.base64EncodedString()

        case .decryptProteusMessage(let sessionId, let message):
            guard let coreCrypto else { throw InteropError.notInitialised }

            let decryptedMessasge = try await coreCrypto.transaction {
                try await $0.proteusDecrypt(
                    sessionId: sessionId, ciphertext: message)
            }

            return decryptedMessasge.base64EncodedString()

        case .getFingerprint:
            guard let coreCrypto else { throw InteropError.notInitialised }

            let fingerprint = try await coreCrypto.transaction({
                try await $0.proteusFingerprint()
            })

            return fingerprint
        }
    }
}
