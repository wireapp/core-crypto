package com.wire.crypto


import okio.Buffer

data class WireIdentity (
    var `clientId`: String, 
    var `handle`: String, 
    var `displayName`: String, 
    var `domain`: String
) {
    
}

object FfiConverterTypeWireIdentity: FfiConverterRustBuffer<WireIdentity> {
    override fun read(buf: Buffer): WireIdentity {
        return WireIdentity(
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
        )
    }

    override fun allocationSize(value: WireIdentity) = (
            FfiConverterString.allocationSize(value.`clientId`) +
            FfiConverterString.allocationSize(value.`handle`) +
            FfiConverterString.allocationSize(value.`displayName`) +
            FfiConverterString.allocationSize(value.`domain`)
    )

    override fun write(value: WireIdentity, buf: Buffer) {
            FfiConverterString.write(value.`clientId`, buf)
            FfiConverterString.write(value.`handle`, buf)
            FfiConverterString.write(value.`displayName`, buf)
            FfiConverterString.write(value.`domain`, buf)
    }
}