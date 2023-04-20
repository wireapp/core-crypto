package com.wire.crypto


import okio.Buffer

data class PublicGroupStateBundle (
    var `encryptionType`: MlsPublicGroupStateEncryptionType, 
    var `ratchetTreeType`: MlsRatchetTreeType, 
    var `payload`: List<UByte>
) {
    
}

object FfiConverterTypePublicGroupStateBundle: FfiConverterRustBuffer<PublicGroupStateBundle> {
    override fun read(buf: Buffer): PublicGroupStateBundle {
        return PublicGroupStateBundle(
            FfiConverterTypeMlsPublicGroupStateEncryptionType.read(buf),
            FfiConverterTypeMlsRatchetTreeType.read(buf),
            FfiConverterSequenceUByte.read(buf),
        )
    }

    override fun allocationSize(value: PublicGroupStateBundle) = (
            FfiConverterTypeMlsPublicGroupStateEncryptionType.allocationSize(value.`encryptionType`) +
            FfiConverterTypeMlsRatchetTreeType.allocationSize(value.`ratchetTreeType`) +
            FfiConverterSequenceUByte.allocationSize(value.`payload`)
    )

    override fun write(value: PublicGroupStateBundle, buf: Buffer) {
            FfiConverterTypeMlsPublicGroupStateEncryptionType.write(value.`encryptionType`, buf)
            FfiConverterTypeMlsRatchetTreeType.write(value.`ratchetTreeType`, buf)
            FfiConverterSequenceUByte.write(value.`payload`, buf)
    }
}