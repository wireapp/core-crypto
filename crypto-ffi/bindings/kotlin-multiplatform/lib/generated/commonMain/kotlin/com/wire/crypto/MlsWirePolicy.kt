package com.wire.crypto


import okio.Buffer

enum class MlsWirePolicy {
    PLAINTEXT,CIPHERTEXT;
}

object FfiConverterTypeMlsWirePolicy: FfiConverterRustBuffer<MlsWirePolicy> {
    override fun read(buf: Buffer) = try {
        MlsWirePolicy.values()[buf.readInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: MlsWirePolicy) = 4

    override fun write(value: MlsWirePolicy, buf: Buffer) {
        buf.writeInt(value.ordinal + 1)
    }
}

