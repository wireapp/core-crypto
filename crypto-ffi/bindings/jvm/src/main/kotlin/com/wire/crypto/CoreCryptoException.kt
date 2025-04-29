package com.wire.crypto

/** The type representing a Proteus error */
sealed class ProteusException : Exception() {
    /** SessionNotFound */
    class SessionNotFound : ProteusException() {
        override val message
            get() = ""
    }

    /** DuplicateMessage */
    class DuplicateMessage : ProteusException() {
        override val message
            get() = ""
    }

    /** RemoteIdentityChanged */
    class RemoteIdentityChanged : ProteusException() {
        override val message
            get() = ""
    }

    /** @property errorCode */
    class Other(val errorCode: UShort) : ProteusException() {
        override val message
            get() = "error_code=${ errorCode }"
    }

    override fun equals(other: Any?): Boolean =
        other is ProteusException &&
            when (other) {
                is SessionNotFound -> this is SessionNotFound
                is DuplicateMessage -> this is DuplicateMessage
                is RemoteIdentityChanged -> this is RemoteIdentityChanged
                is Other -> this is Other && errorCode == other.errorCode
            }

    override fun hashCode(): Int {
        return javaClass.hashCode()
    }
}

/** The type representing an MLS error */
sealed class MlsException : Exception() {
    /** ConversationAlreadyExists
     * @property conversationId
     */
    class ConversationAlreadyExists(
        val conversationId: kotlin.ByteArray
    ) : MlsException() {
        override val message
            get() = "conversationId=$conversationId"
    }

    /** DuplicateMessage */
    class DuplicateMessage : MlsException() {
        override val message
            get() = ""
    }

    /** BufferedFutureMessage */
    class BufferedFutureMessage : MlsException() {
        override val message
            get() = ""
    }

    /** WrongEpoch */
    class WrongEpoch : MlsException() {
        override val message
            get() = ""
    }

    /** BufferedCommit */
    class BufferedCommit : MlsException() {
        override val message
            get() = ""
    }

    /** MessageEpochTooOld */
    class MessageEpochTooOld : MlsException() {
        override val message
            get() = ""
    }

    /** SelfCommitIgnored */
    class SelfCommitIgnored : MlsException() {
        override val message
            get() = ""
    }

    /** UnmergedPendingGroup */
    class UnmergedPendingGroup : MlsException() {
        override val message
            get() = ""
    }

    /** StaleProposal */
    class StaleProposal : MlsException() {
        override val message
            get() = ""
    }

    /** StaleCommit */
    class StaleCommit : MlsException() {
        override val message
            get() = ""
    }

    /**
     * This happens when the DS cannot flag KeyPackages as claimed or not. In
     * this scenario, a client requests their old KeyPackages to be deleted but
     * one has already been claimed by another client to create a Welcome. In
     * that case the only solution is that the client receiving such a Welcome
     * tries to join the group with an External Commit instead
     */
    class OrphanWelcome : MlsException() {
        override val message
            get() = ""
    }

    /** Message rejected by the delivery service */
    class MessageRejected(
        private val reason: kotlin.String
    ) : MlsException() {
        override val message
            get() = "reason=$reason"
    }

    /** @property message */
    class Other(override val message: String) : MlsException()
}

/** The type representing a CoreCrypto error. */
sealed class CoreCryptoException : kotlin.Exception() {
    /** @property exception */
    class Mls(val exception: MlsException) : CoreCryptoException() {
        override val message
            get() = "exception=${ exception }"
    }

    /** @property exception */
    class Proteus(val exception: ProteusException) : CoreCryptoException() {
        override val message
            get() = "exception=${ exception }"
    }

    /** @property message */
    class E2eiException(override val message: String) : CoreCryptoException()

    /** @property message */
    class ClientException(override val message: String) : CoreCryptoException()

    /** @property message */
    class Other(override val message: String) : CoreCryptoException()
}

private fun com.wire.crypto.uniffi.CoreCryptoException.lift() =
    when (this) {
        is com.wire.crypto.uniffi.CoreCryptoException.Mls -> CoreCryptoException.Mls(this.v1.lift())
        is com.wire.crypto.uniffi.CoreCryptoException.Proteus -> CoreCryptoException.Proteus(this.v1.lift())
        is com.wire.crypto.uniffi.CoreCryptoException.E2ei -> CoreCryptoException.E2eiException(this.v1)
        is com.wire.crypto.uniffi.CoreCryptoException.TransactionFailed -> CoreCryptoException.Other(this.v1)
        is com.wire.crypto.uniffi.CoreCryptoException.Other -> CoreCryptoException.Other(this.v1)
    }

private fun com.wire.crypto.uniffi.MlsException.lift() =
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
        is com.wire.crypto.uniffi.MlsException.BufferedCommit -> MlsException.BufferedCommit()
        is com.wire.crypto.uniffi.MlsException.OrphanWelcome -> MlsException.OrphanWelcome()
        is com.wire.crypto.uniffi.MlsException.MessageRejected -> MlsException.MessageRejected(this.reason)
        is com.wire.crypto.uniffi.MlsException.Other -> MlsException.Other(this.v1)
    }

private fun com.wire.crypto.uniffi.ProteusException.lift() =
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
