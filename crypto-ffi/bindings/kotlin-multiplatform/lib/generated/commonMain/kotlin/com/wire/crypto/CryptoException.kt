package com.wire.crypto


import okio.Buffer


sealed class CryptoException(message: String): Exception(message) {
        class ConversationNotFound(message: String) : CryptoException(message)
        class ClientNotFound(message: String) : CryptoException(message)
        class PendingProposalNotFound(message: String) : CryptoException(message)
        class PendingCommitNotFound(message: String) : CryptoException(message)
        class MalformedIdentifier(message: String) : CryptoException(message)
        class ClientSignatureNotFound(message: String) : CryptoException(message)
        class LockPoisonException(message: String) : CryptoException(message)
        class ImplementationException(message: String) : CryptoException(message)
        class OutOfKeyPackage(message: String) : CryptoException(message)
        class MlsProviderException(message: String) : CryptoException(message)
        class KeyStoreException(message: String) : CryptoException(message)
        class MlsException(message: String) : CryptoException(message)
        class Utf8Exception(message: String) : CryptoException(message)
        class StringUtf8Exception(message: String) : CryptoException(message)
        class ParseIntException(message: String) : CryptoException(message)
        class ConvertIntException(message: String) : CryptoException(message)
        class InvalidByteArrayException(message: String) : CryptoException(message)
        class IoException(message: String) : CryptoException(message)
        class Unauthorized(message: String) : CryptoException(message)
        class CallbacksNotSet(message: String) : CryptoException(message)
        class UnauthorizedExternalAddProposal(message: String) : CryptoException(message)
        class UnauthorizedExternalCommit(message: String) : CryptoException(message)
        class InvalidHashReference(message: String) : CryptoException(message)
        class GenerationOutOfBound(message: String) : CryptoException(message)
        class WrongEpoch(message: String) : CryptoException(message)
        class DecryptionException(message: String) : CryptoException(message)
        class HexDecodeException(message: String) : CryptoException(message)
        class ProteusException(message: String) : CryptoException(message)
        class CryptoboxMigrationException(message: String) : CryptoException(message)
        class ProteusNotInitialized(message: String) : CryptoException(message)
        class ProteusSupportNotEnabled(message: String) : CryptoException(message)
        class MlsNotInitialized(message: String) : CryptoException(message)
        class InvalidKeyPackage(message: String) : CryptoException(message)
        class IdentityAlreadyPresent(message: String) : CryptoException(message)
        class NoProvisionalIdentityFound(message: String) : CryptoException(message)
        class TooManyIdentitiesPresent(message: String) : CryptoException(message)
        class ParentGroupNotFound(message: String) : CryptoException(message)
        class InvalidIdentity(message: String) : CryptoException(message)
        class IdentityInitializationException(message: String) : CryptoException(message)
        class MessageEpochTooOld(message: String) : CryptoException(message)
        

    companion object ErrorHandler : CallStatusErrorHandler<CryptoException> {
        override fun lift(error_buf: RustBuffer): CryptoException = FfiConverterTypeCryptoError.lift(error_buf)
    }
}

object FfiConverterTypeCryptoError : FfiConverterRustBuffer<CryptoException> {
    override fun read(buf: Buffer): CryptoException {
        
            return when(buf.readInt()) {
            1 -> CryptoException.ConversationNotFound(FfiConverterString.read(buf))
            2 -> CryptoException.ClientNotFound(FfiConverterString.read(buf))
            3 -> CryptoException.PendingProposalNotFound(FfiConverterString.read(buf))
            4 -> CryptoException.PendingCommitNotFound(FfiConverterString.read(buf))
            5 -> CryptoException.MalformedIdentifier(FfiConverterString.read(buf))
            6 -> CryptoException.ClientSignatureNotFound(FfiConverterString.read(buf))
            7 -> CryptoException.LockPoisonException(FfiConverterString.read(buf))
            8 -> CryptoException.ImplementationException(FfiConverterString.read(buf))
            9 -> CryptoException.OutOfKeyPackage(FfiConverterString.read(buf))
            10 -> CryptoException.MlsProviderException(FfiConverterString.read(buf))
            11 -> CryptoException.KeyStoreException(FfiConverterString.read(buf))
            12 -> CryptoException.MlsException(FfiConverterString.read(buf))
            13 -> CryptoException.Utf8Exception(FfiConverterString.read(buf))
            14 -> CryptoException.StringUtf8Exception(FfiConverterString.read(buf))
            15 -> CryptoException.ParseIntException(FfiConverterString.read(buf))
            16 -> CryptoException.ConvertIntException(FfiConverterString.read(buf))
            17 -> CryptoException.InvalidByteArrayException(FfiConverterString.read(buf))
            18 -> CryptoException.IoException(FfiConverterString.read(buf))
            19 -> CryptoException.Unauthorized(FfiConverterString.read(buf))
            20 -> CryptoException.CallbacksNotSet(FfiConverterString.read(buf))
            21 -> CryptoException.UnauthorizedExternalAddProposal(FfiConverterString.read(buf))
            22 -> CryptoException.UnauthorizedExternalCommit(FfiConverterString.read(buf))
            23 -> CryptoException.InvalidHashReference(FfiConverterString.read(buf))
            24 -> CryptoException.GenerationOutOfBound(FfiConverterString.read(buf))
            25 -> CryptoException.WrongEpoch(FfiConverterString.read(buf))
            26 -> CryptoException.DecryptionException(FfiConverterString.read(buf))
            27 -> CryptoException.HexDecodeException(FfiConverterString.read(buf))
            28 -> CryptoException.ProteusException(FfiConverterString.read(buf))
            29 -> CryptoException.CryptoboxMigrationException(FfiConverterString.read(buf))
            30 -> CryptoException.ProteusNotInitialized(FfiConverterString.read(buf))
            31 -> CryptoException.ProteusSupportNotEnabled(FfiConverterString.read(buf))
            32 -> CryptoException.MlsNotInitialized(FfiConverterString.read(buf))
            33 -> CryptoException.InvalidKeyPackage(FfiConverterString.read(buf))
            34 -> CryptoException.IdentityAlreadyPresent(FfiConverterString.read(buf))
            35 -> CryptoException.NoProvisionalIdentityFound(FfiConverterString.read(buf))
            36 -> CryptoException.TooManyIdentitiesPresent(FfiConverterString.read(buf))
            37 -> CryptoException.ParentGroupNotFound(FfiConverterString.read(buf))
            38 -> CryptoException.InvalidIdentity(FfiConverterString.read(buf))
            39 -> CryptoException.IdentityInitializationException(FfiConverterString.read(buf))
            40 -> CryptoException.MessageEpochTooOld(FfiConverterString.read(buf))
            else -> throw RuntimeException("invalid error enum value, something is very wrong!!")
        }
        
    }

    override fun allocationSize(value: CryptoException): Int {
        return 4
    }

    override fun write(value: CryptoException, buf: Buffer) {
        when(value) {
            is CryptoException.ConversationNotFound -> {
                buf.writeInt(1)
                Unit
            }
            is CryptoException.ClientNotFound -> {
                buf.writeInt(2)
                Unit
            }
            is CryptoException.PendingProposalNotFound -> {
                buf.writeInt(3)
                Unit
            }
            is CryptoException.PendingCommitNotFound -> {
                buf.writeInt(4)
                Unit
            }
            is CryptoException.MalformedIdentifier -> {
                buf.writeInt(5)
                Unit
            }
            is CryptoException.ClientSignatureNotFound -> {
                buf.writeInt(6)
                Unit
            }
            is CryptoException.LockPoisonException -> {
                buf.writeInt(7)
                Unit
            }
            is CryptoException.ImplementationException -> {
                buf.writeInt(8)
                Unit
            }
            is CryptoException.OutOfKeyPackage -> {
                buf.writeInt(9)
                Unit
            }
            is CryptoException.MlsProviderException -> {
                buf.writeInt(10)
                Unit
            }
            is CryptoException.KeyStoreException -> {
                buf.writeInt(11)
                Unit
            }
            is CryptoException.MlsException -> {
                buf.writeInt(12)
                Unit
            }
            is CryptoException.Utf8Exception -> {
                buf.writeInt(13)
                Unit
            }
            is CryptoException.StringUtf8Exception -> {
                buf.writeInt(14)
                Unit
            }
            is CryptoException.ParseIntException -> {
                buf.writeInt(15)
                Unit
            }
            is CryptoException.ConvertIntException -> {
                buf.writeInt(16)
                Unit
            }
            is CryptoException.InvalidByteArrayException -> {
                buf.writeInt(17)
                Unit
            }
            is CryptoException.IoException -> {
                buf.writeInt(18)
                Unit
            }
            is CryptoException.Unauthorized -> {
                buf.writeInt(19)
                Unit
            }
            is CryptoException.CallbacksNotSet -> {
                buf.writeInt(20)
                Unit
            }
            is CryptoException.UnauthorizedExternalAddProposal -> {
                buf.writeInt(21)
                Unit
            }
            is CryptoException.UnauthorizedExternalCommit -> {
                buf.writeInt(22)
                Unit
            }
            is CryptoException.InvalidHashReference -> {
                buf.writeInt(23)
                Unit
            }
            is CryptoException.GenerationOutOfBound -> {
                buf.writeInt(24)
                Unit
            }
            is CryptoException.WrongEpoch -> {
                buf.writeInt(25)
                Unit
            }
            is CryptoException.DecryptionException -> {
                buf.writeInt(26)
                Unit
            }
            is CryptoException.HexDecodeException -> {
                buf.writeInt(27)
                Unit
            }
            is CryptoException.ProteusException -> {
                buf.writeInt(28)
                Unit
            }
            is CryptoException.CryptoboxMigrationException -> {
                buf.writeInt(29)
                Unit
            }
            is CryptoException.ProteusNotInitialized -> {
                buf.writeInt(30)
                Unit
            }
            is CryptoException.ProteusSupportNotEnabled -> {
                buf.writeInt(31)
                Unit
            }
            is CryptoException.MlsNotInitialized -> {
                buf.writeInt(32)
                Unit
            }
            is CryptoException.InvalidKeyPackage -> {
                buf.writeInt(33)
                Unit
            }
            is CryptoException.IdentityAlreadyPresent -> {
                buf.writeInt(34)
                Unit
            }
            is CryptoException.NoProvisionalIdentityFound -> {
                buf.writeInt(35)
                Unit
            }
            is CryptoException.TooManyIdentitiesPresent -> {
                buf.writeInt(36)
                Unit
            }
            is CryptoException.ParentGroupNotFound -> {
                buf.writeInt(37)
                Unit
            }
            is CryptoException.InvalidIdentity -> {
                buf.writeInt(38)
                Unit
            }
            is CryptoException.IdentityInitializationException -> {
                buf.writeInt(39)
                Unit
            }
            is CryptoException.MessageEpochTooOld -> {
                buf.writeInt(40)
                Unit
            }
        }
    }

}