package com.wire.crypto


import okio.Buffer

data class NewAcmeOrder (
    var `delegate`: List<UByte>, 
    var `authorizations`: List<String>
) {
    
}

object FfiConverterTypeNewAcmeOrder: FfiConverterRustBuffer<NewAcmeOrder> {
    override fun read(buf: Buffer): NewAcmeOrder {
        return NewAcmeOrder(
            FfiConverterSequenceUByte.read(buf),
            FfiConverterSequenceString.read(buf),
        )
    }

    override fun allocationSize(value: NewAcmeOrder) = (
            FfiConverterSequenceUByte.allocationSize(value.`delegate`) +
            FfiConverterSequenceString.allocationSize(value.`authorizations`)
    )

    override fun write(value: NewAcmeOrder, buf: Buffer) {
            FfiConverterSequenceUByte.write(value.`delegate`, buf)
            FfiConverterSequenceString.write(value.`authorizations`, buf)
    }
}