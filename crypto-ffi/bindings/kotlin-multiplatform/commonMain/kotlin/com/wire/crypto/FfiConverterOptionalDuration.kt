package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalDuration: FfiConverterRustBuffer<kotlin.time.Duration?> {
    override fun read(buf: Buffer): kotlin.time.Duration? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterDuration.read(buf)
    }

    override fun allocationSize(value: kotlin.time.Duration?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterDuration.allocationSize(value)
        }
    }

    override fun write(value: kotlin.time.Duration?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterDuration.write(value, buf)
        }
    }
}