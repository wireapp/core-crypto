package com.wire.crypto


import okio.Buffer


sealed class E2eIdentityException(message: String): Exception(message) {
        class ImplementationException(message: String) : E2eIdentityException(message)
        class NotYetSupported(message: String) : E2eIdentityException(message)
        class E2eiInvalidDomain(message: String) : E2eIdentityException(message)
        class CryptoException(message: String) : E2eIdentityException(message)
        class IdentityException(message: String) : E2eIdentityException(message)
        class UrlException(message: String) : E2eIdentityException(message)
        class JsonException(message: String) : E2eIdentityException(message)
        class Utf8Exception(message: String) : E2eIdentityException(message)
        class MlsException(message: String) : E2eIdentityException(message)
        class LockPoisonException(message: String) : E2eIdentityException(message)
        

    companion object ErrorHandler : CallStatusErrorHandler<E2eIdentityException> {
        override fun lift(error_buf: RustBuffer): E2eIdentityException = FfiConverterTypeE2eIdentityError.lift(error_buf)
    }
}

object FfiConverterTypeE2eIdentityError : FfiConverterRustBuffer<E2eIdentityException> {
    override fun read(buf: Buffer): E2eIdentityException {
        
            return when(buf.readInt()) {
            1 -> E2eIdentityException.ImplementationException(FfiConverterString.read(buf))
            2 -> E2eIdentityException.NotYetSupported(FfiConverterString.read(buf))
            3 -> E2eIdentityException.E2eiInvalidDomain(FfiConverterString.read(buf))
            4 -> E2eIdentityException.CryptoException(FfiConverterString.read(buf))
            5 -> E2eIdentityException.IdentityException(FfiConverterString.read(buf))
            6 -> E2eIdentityException.UrlException(FfiConverterString.read(buf))
            7 -> E2eIdentityException.JsonException(FfiConverterString.read(buf))
            8 -> E2eIdentityException.Utf8Exception(FfiConverterString.read(buf))
            9 -> E2eIdentityException.MlsException(FfiConverterString.read(buf))
            10 -> E2eIdentityException.LockPoisonException(FfiConverterString.read(buf))
            else -> throw RuntimeException("invalid error enum value, something is very wrong!!")
        }
        
    }

    override fun allocationSize(value: E2eIdentityException): Int {
        return 4
    }

    override fun write(value: E2eIdentityException, buf: Buffer) {
        when(value) {
            is E2eIdentityException.ImplementationException -> {
                buf.writeInt(1)
                Unit
            }
            is E2eIdentityException.NotYetSupported -> {
                buf.writeInt(2)
                Unit
            }
            is E2eIdentityException.E2eiInvalidDomain -> {
                buf.writeInt(3)
                Unit
            }
            is E2eIdentityException.CryptoException -> {
                buf.writeInt(4)
                Unit
            }
            is E2eIdentityException.IdentityException -> {
                buf.writeInt(5)
                Unit
            }
            is E2eIdentityException.UrlException -> {
                buf.writeInt(6)
                Unit
            }
            is E2eIdentityException.JsonException -> {
                buf.writeInt(7)
                Unit
            }
            is E2eIdentityException.Utf8Exception -> {
                buf.writeInt(8)
                Unit
            }
            is E2eIdentityException.MlsException -> {
                buf.writeInt(9)
                Unit
            }
            is E2eIdentityException.LockPoisonException -> {
                buf.writeInt(10)
                Unit
            }
        }
    }

}