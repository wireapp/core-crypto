package com.wire.crypto.testutils

import com.wire.crypto.DatabaseKey

fun genDatabaseKey(): DatabaseKey {
    val bytes = ByteArray(32)
    val random = java.security.SecureRandom()
    random.nextBytes(bytes)
    return DatabaseKey(bytes)
}
