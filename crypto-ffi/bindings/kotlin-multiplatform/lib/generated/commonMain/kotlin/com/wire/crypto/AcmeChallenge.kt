package com.wire.crypto


import okio.Buffer

data class AcmeChallenge (
    var `delegate`: List<UByte>, 
    var `url`: String, 
    var `target`: String
) {
    
}

object FfiConverterTypeAcmeChallenge: FfiConverterRustBuffer<AcmeChallenge> {
    override fun read(buf: Buffer): AcmeChallenge {
        return AcmeChallenge(
            FfiConverterSequenceUByte.read(buf),
            FfiConverterString.read(buf),
            FfiConverterString.read(buf),
        )
    }

    override fun allocationSize(value: AcmeChallenge) = (
            FfiConverterSequenceUByte.allocationSize(value.`delegate`) +
            FfiConverterString.allocationSize(value.`url`) +
            FfiConverterString.allocationSize(value.`target`)
    )

    override fun write(value: AcmeChallenge, buf: Buffer) {
            FfiConverterSequenceUByte.write(value.`delegate`, buf)
            FfiConverterString.write(value.`url`, buf)
            FfiConverterString.write(value.`target`, buf)
    }
}