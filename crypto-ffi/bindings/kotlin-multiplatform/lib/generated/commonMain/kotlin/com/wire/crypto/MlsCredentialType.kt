package com.wire.crypto


import okio.Buffer

enum class MlsCredentialType {
    BASIC,X509;
}

object FfiConverterTypeMlsCredentialType: FfiConverterRustBuffer<MlsCredentialType> {
    override fun read(buf: Buffer) = try {
        MlsCredentialType.values()[buf.readInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: MlsCredentialType) = 4

    override fun write(value: MlsCredentialType, buf: Buffer) {
        buf.writeInt(value.ordinal + 1)
    }
}

