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

import SwiftUI
import Foundation
import WireCoreCrypto

class TransportProvider: MlsTransport {
    
    func sendCommitBundle(
        commitBundle: WireCoreCrypto.CommitBundle
    ) async -> WireCoreCrypto.MlsTransportResponse {
        .success
    }
    
    func sendMessage(
        mlsMessage: Data
    ) async -> WireCoreCrypto.MlsTransportResponse {
        .success
    }
    
}

enum InteropError: String, Error {
    case notInitialised = "Unable to perform action since core crypto is not initialised"
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
        print(String(decoding: try JSONEncoder().encode(response), as: UTF8.self))
    }
    
    private func executeURL(url: URL) async -> InteropResponse{
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
        case .initMLS(clientId: let clientId, ciphersuite: let ciphersuite):
            self.coreCrypto = try await CoreCrypto.init(
                path: generateKeystorePath(),
                key: "secret",
                clientId: clientId,
                ciphersuites: [ciphersuite],
                nbKeyPackage: nil
            )
            
            try await self.coreCrypto?.provideTransport(callbacks: TransportProvider())
            
            return "Initialised MLS with ciphersuite: \(ciphersuite)"
            
        case .getKeyPackage(ciphersuite: let ciphersuite):
            guard let coreCrypto else { throw InteropError.notInitialised }
            
            let keyPackage = try await coreCrypto.clientKeypackages(
                ciphersuite: ciphersuite,
                credentialType: .basic,
                amountRequested: 1
            )
                        
            if let encodedKeyPackage = keyPackage.first.map({ $0.base64EncodedString() }) {
                return encodedKeyPackage
            } else {
                throw InteropError.encodingError
            }
            
        case .addClient(conversationId: let conversationId, let ciphersuite, keyPackage: let keyPackage):
            guard let coreCrypto else { throw InteropError.notInitialised }
            
            if try await coreCrypto.conversationExists(conversationId: conversationId) == false {
                let customConfiguration  = CustomConfiguration(keyRotationSpan: nil, wirePolicy: nil)
                let conversationConfiguration = ConversationConfiguration(
                    ciphersuite: ciphersuite,
                    externalSenders: [],
                    custom: customConfiguration
                )
                
                try await coreCrypto.createConversation(
                    conversationId: conversationId,
                    creatorCredentialType: .basic,
                    config: conversationConfiguration)
            }
            
            _ = try await coreCrypto.addClientsToConversation(
                conversationId: conversationId,
                keyPackages: [keyPackage]
            )
            
            return "added client to conversation"
            
        case .removeClient(conversationId: let conversationId, clientId: let clientId):
            guard let coreCrypto else { throw InteropError.notInitialised }
            
            _ = try await coreCrypto.removeClientsFromConversation(
                conversationId: conversationId,
                clients: [clientId]
            )
            
            return "removed client from conversation"
            
        case .processWelcome(welcomePath: let welcomePath):
            guard let coreCrypto else { throw InteropError.notInitialised }
                        
            let welcomeMessage = try Data(contentsOf: welcomePath)
            let configuration = CustomConfiguration(keyRotationSpan: nil, wirePolicy: nil)
            let bundle = try await coreCrypto.processWelcomeMessage(
                welcomeMessage: welcomeMessage,
                customConfiguration: configuration
            )
            
            return bundle.id.base64EncodedString()
            
        case .encryptMessage(conversationId: let conversationId, message: let message):
            guard let coreCrypto else { throw InteropError.notInitialised }
            
            let encryptedMessage = try await coreCrypto.encryptMessage(
                conversationId: conversationId,
                message: message
            )
            
            return encryptedMessage.base64EncodedString()
            
        case .decryptMessage(conversationId: let conversationId, message: let message):
            guard let coreCrypto else { throw InteropError.notInitialised }
            
            let decryptedMessage = try await coreCrypto.decryptMessage(
                conversationId: conversationId,
                payload: message
            )
            
            if let plaintext = decryptedMessage.message {
                return plaintext.base64EncodedString()
            } else {
                return "decrypted protocol message"
            }
            
        case .initProteus:
            if coreCrypto == nil {
                self.coreCrypto = try await coreCryptoDeferredInit(
                    path: generateKeystorePath(),
                    key: "secret"
                )
                
                try await self.coreCrypto?.provideTransport(callbacks: TransportProvider())
            }
            
            try await coreCrypto?.proteusInit()
            
            return "Initialised proteus"
            
        case .getPrekey(let id):
            guard let coreCrypto  else { throw InteropError.notInitialised }
            
            let prekey = try await coreCrypto.proteusNewPrekey(prekeyId: id)
            
            return prekey.base64EncodedString()
            
        case .sessionFromPrekey(sessionId: let sessionId, prekey: let prekey):
            guard let coreCrypto  else { throw InteropError.notInitialised }
            
            try await coreCrypto.proteusSessionFromPrekey(sessionId: sessionId, prekey: prekey)
            
            return "Created session from prekey"
            
        case .sessionFromMessage(sessionId: let sessionId, message: let message):
            guard let coreCrypto  else { throw InteropError.notInitialised }
            
            let decryptedMessage = try await coreCrypto.proteusSessionFromMessage(sessionId: sessionId, envelope: message)
            
            return decryptedMessage.base64EncodedString()
            
        case .encryptProteusMessage(sessionId: let sessionId, message: let message):
            guard let coreCrypto  else { throw InteropError.notInitialised }
            
            let encryptedMessage = try await coreCrypto.proteusEncrypt(sessionId: sessionId, plaintext: message)
            
            return encryptedMessage.base64EncodedString()
            
        case .decryptProteusMessage(sessionId: let sessionId, message: let message):
            guard let coreCrypto  else { throw InteropError.notInitialised }
            
            let decryptedMessasge = try await coreCrypto.proteusDecrypt(sessionId: sessionId, ciphertext: message)
            
            return decryptedMessasge.base64EncodedString()
            
        case .getFingerprint:
            guard let coreCrypto else { throw InteropError.notInitialised }
            
            let fingerprint = try await coreCrypto.proteusFingerprint()
            
            return fingerprint
        }
    }
}
