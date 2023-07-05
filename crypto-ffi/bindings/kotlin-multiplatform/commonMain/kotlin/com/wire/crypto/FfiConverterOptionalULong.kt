package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalULong: FfiConverterRustBuffer<ULong?> {
    override fun read(buf: Buffer): ULong? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterULong.read(buf)
    }

    override fun allocationSize(value: ULong?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterULong.allocationSize(value)
        }
    }

    override fun write(value: ULong?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterULong.write(value, buf)
        }
    }
}