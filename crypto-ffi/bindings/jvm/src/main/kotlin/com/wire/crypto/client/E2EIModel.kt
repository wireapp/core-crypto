package com.wire.crypto.client

import com.wire.crypto.client.ClientId

@JvmInline
value class RotateBundle(private val value: com.wire.crypto.RotateBundle) {
    val commits: Map<ClientId, CommitBundle>
        get() = value.commits.asSequence().map { (clientId, commit) -> clientId.toClientId() to commit.lift() }.toMap()
    val newKeyPackages: List<MLSKeyPackage> get() = value.newKeyPackages.map { MLSKeyPackage(it) }
    val keyPackageRefsToRemove: List<MLSKeyPackageRef> get() = value.keyPackageRefsToRemove.map { MLSKeyPackageRef(it) }
}

fun com.wire.crypto.RotateBundle.toRotateBundle() = RotateBundle(this)


/**
 * Supporting struct for CRL registration result
 */
data class CRLRegistration(
    /**
     * Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
     */
    val dirty: Boolean,
    /**
     * Optional expiration timestamp
     */
    val expiration: Long?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CRLRegistration

        if (dirty != other.dirty) return false
        if (expiration != other.expiration) return false

        return true
    }

    override fun hashCode(): Int {
        var result = dirty.hashCode() ?: 0
        result = 31 * result + (expiration?.hashCode() ?: 0)
        return result
    }
}

fun com.wire.crypto.CrlRegistration.lift() = CRLRegistration(dirty, expiration?.toLong())
