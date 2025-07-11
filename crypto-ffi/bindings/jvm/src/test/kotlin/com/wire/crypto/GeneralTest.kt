@file:Suppress("ktlint:standard:no-wildcard-imports")

package com.wire.crypto

import com.wire.crypto.testutils.genDatabaseKey
import com.wire.crypto.uniffi.buildMetadata
import com.wire.crypto.uniffi.version
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import java.nio.file.Files
import kotlin.io.path.*
import kotlin.test.*

class GeneralTest {
    @Test
    fun get_version() = runTest {
        val version = version()

        assertThat(version).isNotNull()
        assertThat(version).isNotEmpty()
    }

    @Test
    fun get_build_metadata() = runTest {
        val metadata = buildMetadata()

        assertThat(metadata).isNotNull()
        assertThat(metadata.gitDescribe).isNotNull()
        assertThat(metadata.gitDescribe).isNotEmpty()
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
        // Skip this test on Android.
        if (System.getProperty("java.vm.name") == "Dalvik") {
            return@runTest
        }

        val oldKey = "secret"
        val tmpdir = createTempDirectory("cc-test-")
        var path = Path(object {}.javaClass.getResource("/db-v10002003.sqlite")!!.getPath())
        path = path.copyTo(tmpdir / path.name)

        val newKey = genDatabaseKey()
        migrateDatabaseKeyTypeToBytes(path.absolutePathString(), oldKey, newKey)

        CoreCrypto(path.absolutePathString(), newKey)

        tmpdir.toFile().deleteRecursively()
    }

    @Test
    fun update_database_key_works() = runTest {
        val tmpdir = createTempDirectory("cc-test-")
        val keyStore = tmpdir / "keystore"
        val oldKey = genDatabaseKey()
        val clientId = "alice".toClientId()
        var cc = CoreCrypto(keyStore.toString(), oldKey)
        val pubkey1 = cc.transaction {
            it.mlsInit(id = clientId, nbKeyPackage = 1u)
            it.getPublicKey()
        }
        cc.close()

        val newKey = genDatabaseKey()
        assertNotEquals(oldKey, newKey)

        updateDatabaseKey(keyStore.toString(), oldKey, newKey)
        cc = CoreCrypto(keyStore.toString(), newKey)
        val pubkey2 = cc.transaction {
            it.mlsInit(id = clientId, nbKeyPackage = 0u)
            it.getPublicKey()
        }
        cc.close()
        assertContentEquals(pubkey1, pubkey2)

        tmpdir.toFile().deleteRecursively()
    }
}
