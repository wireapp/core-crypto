package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalTypeAcmeChallenge: FfiConverterRustBuffer<AcmeChallenge?> {
    override fun read(buf: Buffer): AcmeChallenge? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterTypeAcmeChallenge.read(buf)
    }

    override fun allocationSize(value: AcmeChallenge?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterTypeAcmeChallenge.allocationSize(value)
        }
    }

    override fun write(value: AcmeChallenge?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterTypeAcmeChallenge.write(value, buf)
        }
    }
}