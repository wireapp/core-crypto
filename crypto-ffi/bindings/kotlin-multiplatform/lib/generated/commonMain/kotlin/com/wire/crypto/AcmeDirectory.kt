package com.wire.crypto


import okio.Buffer

data class AcmeDirectory (
    var `newNonce`: String, 
    var `newAccount`: String, 
    var `newOrder`: String
) {
    
}

object FfiConverterTypeAcmeDirectory: FfiConverterRustBuffer<AcmeDirectory> {
    override fun read(buf: Buffer): AcmeDirectory {
        return AcmeDirectory(
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
        )
    }

    override fun allocationSize(value: AcmeDirectory) = (
            FfiConverterString.allocationSize(value.`newNonce`) +
            FfiConverterString.allocationSize(value.`newAccount`) +
            FfiConverterString.allocationSize(value.`newOrder`)
    )

    override fun write(value: AcmeDirectory, buf: Buffer) {
            FfiConverterString.write(value.`newNonce`, buf)
            FfiConverterString.write(value.`newAccount`, buf)
            FfiConverterString.write(value.`newOrder`, buf)
    }
}