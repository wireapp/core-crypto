package com.wire.crypto

import com.wire.crypto.testutils.genDatabaseKey
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import kotlin.test.*
import java.nio.file.Files

import com.wire.crypto.DatabaseKey
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
}
