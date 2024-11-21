/*
 * Wire
 * Copyright (C) 2023 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 */

package com.wire.crypto

sealed class ProteusException: Exception() {

    class SessionNotFound() : ProteusException() {
        override val message
            get() = ""
    }

    class DuplicateMessage() : ProteusException() {
        override val message
            get() = ""
    }

    class RemoteIdentityChanged() : ProteusException() {
        override val message
            get() = ""
    }

    class Other(val errorCode: UShort) : ProteusException() {
        override val message
            get() = "error_code=${ errorCode }"
    }

    override fun equals(other: Any?): Boolean =
        other is ProteusException && when (other) {
            is SessionNotFound -> this is SessionNotFound
            is DuplicateMessage -> this is DuplicateMessage
            is RemoteIdentityChanged -> this is RemoteIdentityChanged
            is Other -> this is Other && errorCode == other.errorCode
        }

    override fun hashCode(): Int {
        return javaClass.hashCode()
    }
}

sealed class MlsException: Exception() {

    class ConversationAlreadyExists(
        val conversationId: kotlin.ByteArray
    ) : MlsException() {
        override val message
            get() = "conversationId=${conversationId}"
    }

    class DuplicateMessage() : MlsException() {
        override val message
            get() = ""
    }

    class BufferedFutureMessage() : MlsException() {
        override val message
            get() = ""
    }

    class WrongEpoch() : MlsException() {
        override val message
            get() = ""
    }

    class MessageEpochTooOld() : MlsException() {
        override val message
            get() = ""
    }

    class SelfCommitIgnored() : MlsException() {
        override val message
            get() = ""
    }

    class UnmergedPendingGroup() : MlsException() {
        override val message
            get() = ""
    }

    class StaleProposal() : MlsException() {
        override val message
            get() = ""
    }

    class StaleCommit() : MlsException() {
        override val message
            get() = ""
    }

    class Other(override val message: String) : MlsException()
}

sealed class CoreCryptoException: kotlin.Exception() {

    class Mls(val exception: MlsException) : CoreCryptoException() {
        override val message
            get() = "exception=${ exception }"
    }

    class Proteus(val exception: ProteusException) : CoreCryptoException() {
        override val message
            get() = "exception=${ exception }"
    }

    class E2eiException(override val message: String) : CoreCryptoException()

    class ClientException(
        override val message: String
    ) : CoreCryptoException()
}

fun com.wire.crypto.uniffi.CoreCryptoException.lift() =
    when (this) {
        is com.wire.crypto.uniffi.CoreCryptoException.ClientException -> CoreCryptoException.ClientException(this.v1)
        is com.wire.crypto.uniffi.CoreCryptoException.E2eiException -> CoreCryptoException.E2eiException(this.v1)
        is com.wire.crypto.uniffi.CoreCryptoException.Mls -> CoreCryptoException.Mls(this.v1.lift())
        is com.wire.crypto.uniffi.CoreCryptoException.Proteus -> CoreCryptoException.Proteus(this.v1.lift())
    }

fun com.wire.crypto.uniffi.MlsException.lift() =
    when (this) {
        is com.wire.crypto.uniffi.MlsException.BufferedFutureMessage -> MlsException.BufferedFutureMessage()
        is com.wire.crypto.uniffi.MlsException.ConversationAlreadyExists -> MlsException.ConversationAlreadyExists(this.v1)
        is com.wire.crypto.uniffi.MlsException.DuplicateMessage -> MlsException.DuplicateMessage()
        is com.wire.crypto.uniffi.MlsException.MessageEpochTooOld -> MlsException.MessageEpochTooOld()
        is com.wire.crypto.uniffi.MlsException.SelfCommitIgnored -> MlsException.SelfCommitIgnored()
        is com.wire.crypto.uniffi.MlsException.StaleCommit -> MlsException.StaleCommit()
        is com.wire.crypto.uniffi.MlsException.StaleProposal -> MlsException.StaleProposal()
        is com.wire.crypto.uniffi.MlsException.UnmergedPendingGroup -> MlsException.UnmergedPendingGroup()
        is com.wire.crypto.uniffi.MlsException.WrongEpoch -> MlsException.WrongEpoch()
        is com.wire.crypto.uniffi.MlsException.Other -> MlsException.Other(this.v1)
    }

fun com.wire.crypto.uniffi.ProteusException.lift() =
    when (this) {
        is com.wire.crypto.uniffi.ProteusException.DuplicateMessage -> ProteusException.DuplicateMessage()
        is com.wire.crypto.uniffi.ProteusException.RemoteIdentityChanged -> ProteusException.RemoteIdentityChanged()
        is com.wire.crypto.uniffi.ProteusException.SessionNotFound -> ProteusException.SessionNotFound()
        is com.wire.crypto.uniffi.ProteusException.Other -> ProteusException.Other(this.v1)
    }

internal suspend fun <T> wrapException(b: suspend () -> T): T {
    try {
        return b()
    } catch (e: com.wire.crypto.uniffi.CoreCryptoException) {
        throw e.lift()
    }
}
