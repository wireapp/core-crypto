package com.wire.crypto


import okio.Buffer

enum class MlsGroupInfoEncryptionType {
    PLAINTEXT,JWE_ENCRYPTED;
}

object FfiConverterTypeMlsGroupInfoEncryptionType: FfiConverterRustBuffer<MlsGroupInfoEncryptionType> {
    override fun read(buf: Buffer) = try {
        MlsGroupInfoEncryptionType.values()[buf.readInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: MlsGroupInfoEncryptionType) = 4

    override fun write(value: MlsGroupInfoEncryptionType, buf: Buffer) {
        buf.writeInt(value.ordinal + 1)
    }
}

