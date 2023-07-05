package com.wire.crypto


import okio.Buffer

data class DecryptedMessage (
    var `message`: List<UByte>?, 
    var `proposals`: List<ProposalBundle>, 
    var `isActive`: Boolean, 
    var `commitDelay`: ULong?, 
    var `senderClientId`: ClientId?, 
    var `hasEpochChanged`: Boolean
) {
    
}

object FfiConverterTypeDecryptedMessage: FfiConverterRustBuffer<DecryptedMessage> {
    override fun read(buf: Buffer): DecryptedMessage {
        return DecryptedMessage(
            FfiConverterOptionalSequenceUByte.read(buf),
            FfiConverterSequenceTypeProposalBundle.read(buf),
            FfiConverterBoolean.read(buf),
            FfiConverterOptionalULong.read(buf),
            FfiConverterOptionalTypeClientId.read(buf),
            FfiConverterBoolean.read(buf),
        )
    }

    override fun allocationSize(value: DecryptedMessage) = (
            FfiConverterOptionalSequenceUByte.allocationSize(value.`message`) +
            FfiConverterSequenceTypeProposalBundle.allocationSize(value.`proposals`) +
            FfiConverterBoolean.allocationSize(value.`isActive`) +
            FfiConverterOptionalULong.allocationSize(value.`commitDelay`) +
            FfiConverterOptionalTypeClientId.allocationSize(value.`senderClientId`) +
            FfiConverterBoolean.allocationSize(value.`hasEpochChanged`)
    )

    override fun write(value: DecryptedMessage, buf: Buffer) {
            FfiConverterOptionalSequenceUByte.write(value.`message`, buf)
            FfiConverterSequenceTypeProposalBundle.write(value.`proposals`, buf)
            FfiConverterBoolean.write(value.`isActive`, buf)
            FfiConverterOptionalULong.write(value.`commitDelay`, buf)
            FfiConverterOptionalTypeClientId.write(value.`senderClientId`, buf)
            FfiConverterBoolean.write(value.`hasEpochChanged`, buf)
    }
}