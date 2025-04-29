package com.wire.crypto

typealias SessionId = String

/**
 * Prekey
 *
 * @property id the prekey ID
 * @property data the prekey data
 */
data class PreKey(
    val id: UShort,
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PreKey

        if (id != other.id) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}
