@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.crypto

import kotlinx.coroutines.test.runTest
import testutils.MockMlsTransportSuccessProvider
import testutils.genClientId
import testutils.genDatabaseKey
import java.nio.file.Path
import kotlin.io.path.*
import kotlin.test.*
import kotlin.uuid.Uuid as KotlinUuid

class GeneralTest {
    @Test
    fun uuid_to_string() = runTest {
        val rawUuid = KotlinUuid.random().toString()
        val uuid = Uuid(rawUuid)

        assertEquals(rawUuid, uuid.toString())
    }

    @Test
    fun get_version() = runTest {
        val version = version()

        assertTrue(version.isNotEmpty())
    }

    @Test
    fun get_build_metadata() = runTest {
        val metadata = buildMetadata()

        assertTrue(metadata.gitDescribe.isNotEmpty())
    }
}

class DatabaseTest {
    suspend fun <T> withDatabase(block: suspend (Path, DatabaseKey) -> T): T {
        val tmpdir = createTempDirectory("cc-test-")
        val path = tmpdir / "keystore"
        val key = genDatabaseKey()
        return try {
            block(path, key)
        } finally {
            tmpdir.toFile().deleteRecursively()
        }
    }

    @Test
    fun givenDatabase_getLocation_shouldSucceed() = runTest {
        withDatabase { path, key ->
            val pathStr = path.absolutePathString()
            val db = Database.open(pathStr, key)
            val location = db.getLocation()
            assertNotNull(location)
            assertEquals(path.toRealPath(), Path(location).toRealPath())
            db.close()
        }
    }

    @Test
    fun givenDatabase_whenUsingSameNameAndKey_thenOpenShouldSucceed() = runTest {
        withDatabase { path, key ->
            val db = Database.open(path.absolutePathString(), key)
            db.close()

            openDatabase(path.toString(), key)
        }
    }

    @Test
    fun givenDatabase_whenUsingWrongKey_thenOpenShouldFail() = runTest {
        withDatabase { path, key ->
            Database.open(path.absolutePathString(), key)

            val key2 = genDatabaseKey()
            assertFailsWith<CoreCryptoException.Other> { Database.open(path.toString(), key2) }
                .also { assertEquals("msg=file is not a database", it.message) }
        }
    }
}

class DatabaseKeyTest {
    @Test
    fun invalid_length() = runTest {
        val exc = assertFailsWith<CoreCryptoException.Other> { DatabaseKey(ByteArray(48)) }
        assertTrue(exc.msg.contains("Invalid database key size, expected 32, got 48"))
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
        val clientId = genClientId()
        val db = openDatabase(path.absolutePathString(), oldKey)
        var cc = CoreCrypto(db)
        val transport = MockMlsTransportSuccessProvider()
        cc.transaction { ctx ->
            ctx.mlsInit(clientId = clientId, transport)
            ctx.addCredential(Credential.basic(CIPHERSUITE_DEFAULT, clientId))
        }
        val credentialRef1 = cc.findCredentials(clientId = clientId).first()
        cc.close()

        val newKey = genDatabaseKey()
        assertNotEquals(oldKey, newKey)

        db.updateKey(newKey)
        cc = CoreCrypto(db)
        cc.transaction { ctx ->
            ctx.mlsInit(clientId = clientId, transport)
        }
        val credentialRef2 = cc.findCredentials(clientId = clientId).first()
        cc.close()
        assertContentEquals(credentialRef1.publicKeyHash(), credentialRef2.publicKeyHash())

        tmpdir.toFile().deleteRecursively()
    }
}
