package com.wire.crypto


import okio.Buffer

data class Invitee (
    var `id`: ClientId, 
    var `kp`: List<UByte>
) {
    
}

object FfiConverterTypeInvitee: FfiConverterRustBuffer<Invitee> {
    override fun read(buf: Buffer): Invitee {
        return Invitee(
            FfiConverterTypeClientId.read(buf),
            FfiConverterSequenceUByte.read(buf),
        )
    }

    override fun allocationSize(value: Invitee) = (
            FfiConverterTypeClientId.allocationSize(value.`id`) +
            FfiConverterSequenceUByte.allocationSize(value.`kp`)
    )

    override fun write(value: Invitee, buf: Buffer) {
            FfiConverterTypeClientId.write(value.`id`, buf)
            FfiConverterSequenceUByte.write(value.`kp`, buf)
    }
}