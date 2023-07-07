package com.wire.crypto


import okio.Buffer

data class GroupInfoBundle (
    var `encryptionType`: MlsGroupInfoEncryptionType, 
    var `ratchetTreeType`: MlsRatchetTreeType, 
    var `payload`: List<UByte>
) {
    
}

object FfiConverterTypeGroupInfoBundle: FfiConverterRustBuffer<GroupInfoBundle> {
    override fun read(buf: Buffer): GroupInfoBundle {
        return GroupInfoBundle(
            FfiConverterTypeMlsGroupInfoEncryptionType.read(buf),
            FfiConverterTypeMlsRatchetTreeType.read(buf),
            FfiConverterSequenceUByte.read(buf),
        )
    }

    override fun allocationSize(value: GroupInfoBundle) = (
            FfiConverterTypeMlsGroupInfoEncryptionType.allocationSize(value.`encryptionType`) +
            FfiConverterTypeMlsRatchetTreeType.allocationSize(value.`ratchetTreeType`) +
            FfiConverterSequenceUByte.allocationSize(value.`payload`)
    )

    override fun write(value: GroupInfoBundle, buf: Buffer) {
            FfiConverterTypeMlsGroupInfoEncryptionType.write(value.`encryptionType`, buf)
            FfiConverterTypeMlsRatchetTreeType.write(value.`ratchetTreeType`, buf)
            FfiConverterSequenceUByte.write(value.`payload`, buf)
    }
}