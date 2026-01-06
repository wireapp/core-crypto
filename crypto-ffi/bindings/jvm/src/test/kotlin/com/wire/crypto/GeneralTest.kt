@file:Suppress("ktlint:standard:no-wildcard-imports")

package com.wire.crypto

import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import testutils.MockMlsTransportSuccessProvider
import testutils.genDatabaseKey
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

class DatabaseTest {
    @Test
    fun givenDatabase_whenUsingSameNameAndKey_thenOpenShouldSucceed() = runTest {
        val tmpdir = createTempDirectory("cc-test-")
        val path = tmpdir / "keystore"
        val key = genDatabaseKey()
        val db = openDatabase(path.absolutePathString(), key)
        db.close()

        openDatabase(path.toString(), key)

        tmpdir.toFile().deleteRecursively()
    }

    @Test
    fun givenDatabase_whenUsingWrongKey_thenOpenShouldFail() = runTest {
        val tmpdir = createTempDirectory("cc-test-")
        val path = tmpdir / "keystore"
        val key = genDatabaseKey()
        openDatabase(path.absolutePathString(), key)

        val key2 = genDatabaseKey()
        assertFailsWith<CoreCryptoException.Other> { openDatabase(path.toString(), key2) }
            .also { assertEquals("msg=file is not a database", it.message) }

        tmpdir.toFile().deleteRecursively()
    }
}

class DatabaseKeyTest {
    @Test
    fun invalid_length() = runTest {
        val exc = assertFailsWith<CoreCryptoException.Other> { DatabaseKey(ByteArray(48)) }
        assertThat(exc.msg.contains("Invalid database key size, expected 32, got 48")).isTrue
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
        val db = openDatabase(path.absolutePathString(), newKey)

        CoreCrypto(db)

        tmpdir.toFile().deleteRecursively()
    }

    @Test
    fun update_database_key_works() = runTest {
        val tmpdir = createTempDirectory("cc-test-")
        val path = tmpdir / "keystore"
        val oldKey = genDatabaseKey()
        val clientId = "alice".toClientId()
        val db = openDatabase(path.absolutePathString(), oldKey)
        var cc = CoreCrypto(db)
        var transport = MockMlsTransportSuccessProvider()
        val pubkey1 = cc.transaction {
            it.mlsInit(clientId = clientId, ciphersuites = CIPHERSUITES_DEFAULT, transport)
            it.addCredential(Credential.basic(CIPHERSUITE_DEFAULT, clientId))
            it.clientPublicKey(CIPHERSUITE_DEFAULT, CREDENTIAL_TYPE_DEFAULT)
        }
        cc.close()

        val newKey = genDatabaseKey()
        assertNotEquals(oldKey, newKey)

        updateDatabaseKey(path.absolutePathString(), oldKey, newKey)
        val newDb = openDatabase(path.absolutePathString(), newKey)
        cc = CoreCrypto(newDb)
        val pubkey2 = cc.transaction {
            it.mlsInit(clientId = clientId, ciphersuites = CIPHERSUITES_DEFAULT, transport)
            it.clientPublicKey(CIPHERSUITE_DEFAULT, CREDENTIAL_TYPE_DEFAULT)
        }
        cc.close()
        assertContentEquals(pubkey1, pubkey2)

        tmpdir.toFile().deleteRecursively()
    }
}
