package com.wire.crypto


import okio.Buffer

enum class MlsPublicGroupStateEncryptionType {
    PLAINTEXT,JWE_ENCRYPTED;
}

object FfiConverterTypeMlsPublicGroupStateEncryptionType: FfiConverterRustBuffer<MlsPublicGroupStateEncryptionType> {
    override fun read(buf: Buffer) = try {
        MlsPublicGroupStateEncryptionType.values()[buf.readInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: MlsPublicGroupStateEncryptionType) = 4

    override fun write(value: MlsPublicGroupStateEncryptionType, buf: Buffer) {
        buf.writeInt(value.ordinal + 1)
    }
}

