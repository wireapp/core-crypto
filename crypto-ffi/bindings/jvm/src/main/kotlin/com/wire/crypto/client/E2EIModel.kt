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