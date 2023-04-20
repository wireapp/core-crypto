package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalTypeCiphersuiteName: FfiConverterRustBuffer<CiphersuiteName?> {
    override fun read(buf: Buffer): CiphersuiteName? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterTypeCiphersuiteName.read(buf)
    }

    override fun allocationSize(value: CiphersuiteName?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterTypeCiphersuiteName.allocationSize(value)
        }
    }

    override fun write(value: CiphersuiteName?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterTypeCiphersuiteName.write(value, buf)
        }
    }
}