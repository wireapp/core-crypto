package com.wire.crypto


import okio.Buffer

enum class CiphersuiteName {
    MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,MLS_128_DHKEMP256_AES128GCM_SHA256_P256,MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,MLS_256_DHKEMX448_AES256GCM_SHA512_ED448,MLS_256_DHKEMP521_AES256GCM_SHA512_P521,MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448,MLS_256_DHKEMP384_AES256GCM_SHA384_P384;
}

object FfiConverterTypeCiphersuiteName: FfiConverterRustBuffer<CiphersuiteName> {
    override fun read(buf: Buffer) = try {
        CiphersuiteName.values()[buf.readInt() - 1]
    } catch (e: IndexOutOfBoundsException) {
        throw RuntimeException("invalid enum value, something is very wrong!!", e)
    }

    override fun allocationSize(value: CiphersuiteName) = 4

    override fun write(value: CiphersuiteName, buf: Buffer) {
        buf.writeInt(value.ordinal + 1)
    }
}

