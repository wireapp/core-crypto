package com.wire.crypto


import okio.Buffer

data class NewAcmeAuthz (
    var `identifier`: String, 
    var `wireDpopChallenge`: AcmeChallenge?, 
    var `wireOidcChallenge`: AcmeChallenge?
) {
    
}

object FfiConverterTypeNewAcmeAuthz: FfiConverterRustBuffer<NewAcmeAuthz> {
    override fun read(buf: Buffer): NewAcmeAuthz {
        return NewAcmeAuthz(
            FfiConverterString.read(buf),
            FfiConverterOptionalTypeAcmeChallenge.read(buf),
            FfiConverterOptionalTypeAcmeChallenge.read(buf),
        )
    }

    override fun allocationSize(value: NewAcmeAuthz) = (
            FfiConverterString.allocationSize(value.`identifier`) +
            FfiConverterOptionalTypeAcmeChallenge.allocationSize(value.`wireDpopChallenge`) +
            FfiConverterOptionalTypeAcmeChallenge.allocationSize(value.`wireOidcChallenge`)
    )

    override fun write(value: NewAcmeAuthz, buf: Buffer) {
            FfiConverterString.write(value.`identifier`, buf)
            FfiConverterOptionalTypeAcmeChallenge.write(value.`wireDpopChallenge`, buf)
            FfiConverterOptionalTypeAcmeChallenge.write(value.`wireOidcChallenge`, buf)
    }
}