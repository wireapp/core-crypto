//
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
//

internal import WireCoreCryptoUniffi

func wrapError<Result>(_ block: () async throws -> Result) async throws -> Result {
    do {
        return try await block()
    } catch (WireCoreCryptoUniffi.CoreCryptoError.Mls(let mlsError)) {
        throw CoreCryptoError.mls(mlsError.lift())
    } catch (WireCoreCryptoUniffi.CoreCryptoError.Proteus(let proteusError)) {
        throw CoreCryptoError.proteus(proteusError.lift())
    } catch (WireCoreCryptoUniffi.CoreCryptoError.E2eiError(let message)) {
        throw CoreCryptoError.e2eiError(message)
    } catch (WireCoreCryptoUniffi.CoreCryptoError.ClientError(let message)) {
        throw CoreCryptoError.clientError(message)
    } catch (WireCoreCryptoUniffi.CoreCryptoError.Other(let message)) {
        throw CoreCryptoError.other(message)
    }
}

func wrapErrorNonAsync<Result>(_ block: () throws -> Result) throws -> Result {
    do {
        return try block()
    } catch (WireCoreCryptoUniffi.CoreCryptoError.Mls(let mlsError)) {
        throw CoreCryptoError.mls(mlsError.lift())
    } catch (WireCoreCryptoUniffi.CoreCryptoError.Proteus(let proteusError)) {
        throw CoreCryptoError.proteus(proteusError.lift())
    } catch (WireCoreCryptoUniffi.CoreCryptoError.E2eiError(let message)) {
        throw CoreCryptoError.e2eiError(message)
    } catch (WireCoreCryptoUniffi.CoreCryptoError.ClientError(let message)) {
        throw CoreCryptoError.clientError(message)
    } catch (WireCoreCryptoUniffi.CoreCryptoError.Other(let message)) {
        throw CoreCryptoError.other(message)
    }
}

public enum CoreCryptoError: Error, Equatable {
    case mls(MlsError)
    case proteus(ProteusError)
    case e2eiError(String)
    case clientError(String)
    case other(String)
}

public enum ProteusError: Equatable {
    case sessionNotFound
    case duplicateMessage
    case remoteIdentityChanged
    case other(UInt16)
}

extension WireCoreCryptoUniffi.ProteusError {
    func lift() -> ProteusError {
        switch self {
        case .SessionNotFound: .sessionNotFound
        case .DuplicateMessage: .duplicateMessage
        case .RemoteIdentityChanged: .remoteIdentityChanged
        case .Other(let errorCode): .other(errorCode)
        }
    }
}

public enum MlsError: Equatable {
    case conversationAlreadyExists(ConversationId)
    case duplicateMessage
    case bufferedFutureMessage
    case wrongEpoch
    case bufferedCommit
    case messageEpochTooOld
    case selfCommitIgnored
    case unmergedPendingGroup
    case staleProposal
    case staleCommit
    /// This happens when the DS cannot flag KeyPackages as claimed or not. It this scenario, a client
    /// requests their old KeyPackages to be deleted but one has already been claimed by another client to create a Welcome.
    /// In that case the only solution is that the client receiving such a Welcome tries to join the group
    /// with an External Commit instead
    ///
    case orphanWelcome
    /// Message rejected by the delivery service
    ///
    case messageRejected(
        /// Why was the message rejected by the delivery service?
        ///
        reason: String
    )
    case other(String)
}

extension WireCoreCryptoUniffi.MlsError {
    func lift() -> MlsError {
        switch self {
        case .ConversationAlreadyExists(let conversationId):
            .conversationAlreadyExists(conversationId)
        case .DuplicateMessage: .duplicateMessage
        case .BufferedFutureMessage: .bufferedFutureMessage
        case .WrongEpoch: .wrongEpoch
        case .BufferedCommit: .bufferedCommit
        case .MessageEpochTooOld: .messageEpochTooOld
        case .SelfCommitIgnored: .selfCommitIgnored
        case .UnmergedPendingGroup: .unmergedPendingGroup
        case .StaleProposal: .staleProposal
        case .StaleCommit: .staleCommit
        case .OrphanWelcome: .orphanWelcome
        case .MessageRejected(let reason): .messageRejected(reason: reason)
        case .Other(let message): .other(message)
        }
    }
}
