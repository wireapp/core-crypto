package com.wire.crypto

import com.wire.crypto.testutils.genDatabaseKey
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import kotlin.test.*
import java.nio.file.Files
import kotlin.io.path.*

import com.wire.crypto.uniffi.version
import com.wire.crypto.uniffi.buildMetadata

class GeneralTest {
    @Test
    fun get_version() = runTest {
        val version = version()

        assertThat(version).isNotNull()
        assertThat(version).isNotEmpty()
    }

    @Test
    fun get_build_metadata() = runTest {
        val build_metadata = buildMetadata()

        assertThat(build_metadata).isNotNull()
        assertThat(build_metadata.gitDescribe).isNotNull()
        assertThat(build_metadata.gitDescribe).isNotEmpty()
    }
}

class DatabaseKeyTest {
    @Test
    fun invalid_length() = runTest {
        val path = Files.createTempFile("keystore-", null).toString()
        val key = DatabaseKey(ByteArray(48))
        val exc = assertFailsWith<CoreCryptoException.Other> { wrapException { CoreCrypto(path, key) } }
        assertEquals("Invalid database key size, expected 32, got 48", exc.message)
    }

    @Test
    fun migrating_key_type_to_bytes_works() = runTest {
        val oldKey = "secret"
        val tmpdir = createTempDirectory("cc-test-")
        var path = Path(object {}.javaClass.getResource("/db-v10002003.sqlite")!!.getPath())
        path = path.copyTo(tmpdir / path.name)

        val newKey = genDatabaseKey()
        migrateDatabaseKeyTypeToBytes(path.absolutePathString(), oldKey, newKey)

        CoreCrypto(path.absolutePathString(), newKey)

        tmpdir.toFile().deleteRecursively()
    }
}
