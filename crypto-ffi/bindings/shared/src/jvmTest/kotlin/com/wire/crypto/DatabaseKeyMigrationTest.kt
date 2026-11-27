package com.wire.crypto

import kotlinx.coroutines.test.runTest
import testutils.genDatabaseKey
import kotlin.io.path.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.copyTo
import kotlin.io.path.createTempDirectory
import kotlin.io.path.div
import kotlin.io.path.name
import kotlin.test.Test

/** Only on the JVM, where the database to migrate is a resource on the classpath. */
class DatabaseKeyMigrationTest {
    @Test
    fun migrating_key_type_to_bytes_works() = runTest {
        val oldKey = "secret"
        val tmpdir = createTempDirectory("cc-test-")
        var path = Path(object {}.javaClass.getResource("/db-v10002003.sqlite")!!.getPath())
        path = path.copyTo(tmpdir / path.name)

        val newKey = genDatabaseKey()
        migrateDatabaseKeyTypeToBytes(path.absolutePathString(), oldKey, newKey)
        val db = openDatabase(path.absolutePathString(), newKey)

        CoreCrypto(db)

        tmpdir.toFile().deleteRecursively()
    }
}
