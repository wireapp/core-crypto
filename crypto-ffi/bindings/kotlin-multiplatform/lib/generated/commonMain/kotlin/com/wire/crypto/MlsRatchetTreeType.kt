package com.wire.crypto


import okio.Buffer

enum class MlsRatchetTreeType {
    FULL,DELTA,BY_REF;
}

object FfiConverterTypeMlsRatchetTreeType: FfiConverterRustBuffer<MlsRatchetTreeType> {
    override fun read(buf: Buffer) = try {
        MlsRatchetTreeType.values()[buf.readInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: MlsRatchetTreeType) = 4

    override fun write(value: MlsRatchetTreeType, buf: Buffer) {
        buf.writeInt(value.ordinal + 1)
    }
}

