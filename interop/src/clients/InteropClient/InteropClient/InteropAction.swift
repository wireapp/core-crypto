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

enum InteropResponse: Codable {
    case success(value: String)
    case failure(message: String)
}

enum InteropAction {
    case initMLS(clientId: Data, ciphersuite: UInt16)
    case getKeyPackage(ciphersuite: UInt16)
    case addClient(conversationId: Data, ciphersuite: UInt16, keyPackage: Data)
    case removeClient(conversationId: Data, clientId: Data)
    case processWelcome(welcomePath: URL)
    case encryptMessage(conversationId: Data, message: Data)
    case decryptMessage(conversationId: Data, message: Data)
    case initProteus
    case getPrekey(id: UInt16)
    case sessionFromPrekey(sessionId: String, prekey: Data)
    case sessionFromMessage(sessionId: String, message: Data)
    case encryptProteusMessage(sessionId: String, message: Data)
    case decryptProteusMessage(sessionId: String, message: Data)
    case getFingerprint
}

extension InteropAction {
    init?(url: URL) {
        switch url.host() {
        case "init-mls":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let clientId = components?.queryItems?.first(where: {
                $0.name == "client"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            let ciphersuite = components?.queryItems?.first(where: {
                $0.name == "ciphersuite"
            })?.value.flatMap {
                UInt16($0)
            }
            
            if let clientId, let ciphersuite {
                self = .initMLS(clientId: clientId, ciphersuite: ciphersuite)
            } else {
                return nil
            }
            
        case "get-key-package":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let ciphersuite = components?.queryItems?.first(where: {
                $0.name == "ciphersuite"
            })?.value.flatMap { UInt16($0) }
            
            if let ciphersuite  {
                self = .getKeyPackage(ciphersuite: ciphersuite)
            } else {
                return nil
            }
            
        case "add-client":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let converationId = components?.queryItems?.first(where: {
                $0.name == "cid"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            let ciphersuite = components?.queryItems?.first(where: {
                $0.name == "ciphersuite"
            })?.value.flatMap {
                UInt16($0)
            }
            let keyPackage = components?.queryItems?.first(where: {
                $0.name == "kp"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let converationId, let ciphersuite, let keyPackage {
                self = .addClient(conversationId: converationId, ciphersuite: ciphersuite, keyPackage: keyPackage)
            } else {
                return nil
            }
            
        case "remove-client":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let converationId = components?.queryItems?.first(where: {
                $0.name == "cid"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            let clientId = components?.queryItems?.first(where: {
                $0.name == "client"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let converationId, let clientId {
                self = .removeClient(conversationId: converationId, clientId: clientId)
            } else {
                return nil
            }
            
        case "process-welcome":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let welcomePath = components?.queryItems?.first(where: {
                $0.name == "welcome_path"
            })?.value.flatMap {
                URL(fileURLWithPath: $0)
            }
            
            if let welcomePath {
                self = .processWelcome(welcomePath: welcomePath)
            } else {
                return nil
            }
            
        case "encrypt-message":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let converationId = components?.queryItems?.first(where: {
                $0.name == "cid"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            let message = components?.queryItems?.first(where: {
                $0.name == "message"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let converationId, let message {
                self = .encryptMessage(conversationId: converationId, message: message)
            } else {
                return nil
            }
            
        case "decrypt-message":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let converationId = components?.queryItems?.first(where: {
                $0.name == "cid"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            let message = components?.queryItems?.first(where: {
                $0.name == "message"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let converationId, let message {
                self = .decryptMessage(conversationId: converationId, message: message)
            } else {
                return nil
            }
            
        case "init-proteus":
            self = .initProteus
            
        case "get-prekey":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let id = components?.queryItems?.first(where: {
                $0.name == "id"
            })?.value.flatMap {
                UInt16($0)
            }
            
            if let id {
                self = .getPrekey(id: id)
            } else {
                return nil
            }
            
        case "session-from-prekey":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let sessionId = components?.queryItems?.first(where: {
                $0.name == "session_id"
            })?.value
            let prekey = components?.queryItems?.first(where: {
                $0.name == "prekey"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let sessionId, let prekey {
                self = .sessionFromPrekey(sessionId: sessionId, prekey: prekey)
            } else {
                return nil
            }
            
        case "session-from-message":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let sessionId = components?.queryItems?.first(where: {
                $0.name == "session_id"
            })?.value
            let message = components?.queryItems?.first(where: {
                $0.name == "message"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let sessionId, let message {
                self = .sessionFromMessage(sessionId: sessionId, message: message)
            } else {
                return nil
            }
            
        case "decrypt-proteus":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let sessionId = components?.queryItems?.first(where: {
                $0.name == "session_id"
            })?.value
            let message = components?.queryItems?.first(where: {
                $0.name == "message"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let sessionId, let message {
                self = .decryptProteusMessage(sessionId: sessionId, message: message)
            } else {
                return nil
            }
            
        case "encrypt-proteus":
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let sessionId = components?.queryItems?.first(where: {
                $0.name == "session_id"
            })?.value
            let message = components?.queryItems?.first(where: {
                $0.name == "message"
            })?.value.flatMap {
                Data(base64Encoded: $0)
            }
            
            if let sessionId, let message {
                self = .encryptProteusMessage(sessionId: sessionId, message: message)
            } else {
                return nil
            }
            
        case "get-fingerprint":
            self = .getFingerprint
            
        default: return nil
        }
    }
}
