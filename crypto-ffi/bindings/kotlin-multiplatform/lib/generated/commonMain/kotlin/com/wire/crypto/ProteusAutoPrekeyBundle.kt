package com.wire.crypto


import okio.Buffer

data class ProteusAutoPrekeyBundle (
    var `id`: UShort, 
    var `pkb`: List<UByte>
) {
    
}

object FfiConverterTypeProteusAutoPrekeyBundle: FfiConverterRustBuffer<ProteusAutoPrekeyBundle> {
    override fun read(buf: Buffer): ProteusAutoPrekeyBundle {
        return ProteusAutoPrekeyBundle(
            FfiConverterUShort.read(buf),
            FfiConverterSequenceUByte.read(buf),
        )
    }

    override fun allocationSize(value: ProteusAutoPrekeyBundle) = (
            FfiConverterUShort.allocationSize(value.`id`) +
            FfiConverterSequenceUByte.allocationSize(value.`pkb`)
    )

    override fun write(value: ProteusAutoPrekeyBundle, buf: Buffer) {
            FfiConverterUShort.write(value.`id`, buf)
            FfiConverterSequenceUByte.write(value.`pkb`, buf)
    }
}