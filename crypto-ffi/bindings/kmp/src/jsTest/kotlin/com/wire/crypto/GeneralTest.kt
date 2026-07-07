package com.wire.crypto

import kotlinx.atomicfu.locks.synchronized
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi

class GeneralTest {

    fun genDatabaseKey(): DatabaseKey {
        val bytes = ByteArray(32)
        val random = Random.Default
        random.nextBytes(bytes)
        return DatabaseKey(bytes)
    }

    @OptIn(ExperimentalUuidApi::class)
    private fun uuidBytes(): ByteArray {
        val uuid = kotlin.uuid.Uuid.random()
        return uuid.toByteArray()
    }

    @OptIn(ExperimentalUuidApi::class)
    fun genClientId(): ClientId {
        val deviceId = Random.nextLong().toULong()
        val clientId = kotlin.uuid.Uuid.random().toString()
        return ClientId(
            userId = Uuid(clientId),
            deviceId = DeviceId(deviceId),
            domain = "wire.com"
        )
    }

    fun genConversationId(): ConversationId {
        return ConversationId(uuidBytes())
    }

    interface MockDeliveryService : MlsTransport {
        suspend fun getLatestCommitBundle(): CommitBundle

        suspend fun getLatestWelcome(): Welcome

        suspend fun getLatestCommit(): ByteArray
    }

    // We use a singleton to easily access the mocked provider
    class MockMlsTransportSuccessProvider : MockDeliveryService {
        companion object {
            private var instance: MockMlsTransportSuccessProvider? = null

            fun getInstance() =
                instance ?: synchronized(this) {
                    instance ?: MockMlsTransportSuccessProvider().also { instance = it }
                }
        }

        private var latestCommitBundle: CommitBundle? = null

        override suspend fun sendCommitBundle(commitBundle: CommitBundle) {
            latestCommitBundle = commitBundle
        }

        override suspend fun prepareForTransport(historySecret: HistorySecret): MlsTransportData {
            return "secret".encodeToByteArray()
        }

        override suspend fun getLatestCommitBundle(): CommitBundle = latestCommitBundle!!

        override suspend fun getLatestWelcome(): Welcome = getLatestCommitBundle().welcome!!

        override suspend fun getLatestCommit(): ByteArray = getLatestCommitBundle().commit
    }

    class MockPkiEnvironmentHooks : PkiEnvironmentHooks {
        override suspend fun httpRequest(
            method: HttpMethod,
            url: String,
            headers: List<HttpHeader>,
            body: ByteArray
        ): HttpResponse {
            return HttpResponse(
                status = 200u,
                headers = emptyList(),
                body = ByteArray(0)
            )
        }

        override suspend fun authenticate(
            idp: String,
            keyAuth: String,
            acmeAud: String,
            acquisitionSnapshot: ByteArray
        ): String {
            return "mock-id-token"
        }

        override suspend fun getBackendNonce(): String {
            return "mock-backend-nonce"
        }

        override suspend fun fetchBackendAccessToken(
            dpop: String
        ): String {
            return "mock-backend-access-token"
        }
    }

    data class CcInitOptions(
        val mode: Mode = Mode.WithBasicCredential(),
        val clientId: ClientId? = null,
        val database: Database? = null,
        val withPkiEnvironment: Boolean = false,
    ) {
        sealed interface Mode {
            data object WithoutBasicCredential : Mode

            data class WithBasicCredential(
                val cipherSuite: CipherSuite = CIPHERSUITE_DEFAULT
            ) : Mode
        }
    }

    suspend fun ccInit(
        options: CcInitOptions = CcInitOptions()
    ): CoreCrypto {
        val db = options.database ?: newDatabase()
        val cc = CoreCrypto(db)

        val clientId = options.clientId ?: genClientId()

        if (options.withPkiEnvironment) {
            val pkiEnvironment = PkiEnvironment.new(MockPkiEnvironmentHooks(), db)
            cc.setPkiEnvironment(pkiEnvironment)
        }

        cc.transaction { ctx ->
            ctx.mlsInit(
                clientId,
                MockMlsTransportSuccessProvider.getInstance()
            )

            when (val mode = options.mode) {
                is CcInitOptions.Mode.WithBasicCredential -> {
                    ctx.addCredential(
                        Credential.basic(
                            mode.cipherSuite,
                            clientId
                        )
                    )
                }

                CcInitOptions.Mode.WithoutBasicCredential -> {
                    // nothing
                }
            }
        }

        return cc
    }

    suspend fun newDatabase(): Database {
        val key = genDatabaseKey()
        return Database.open(key)
    }

    @Test
    fun get_build_metadata() = runTest {
        // webpack resolves the WASM as an asset/resource and returns its URL.
        // We pass that URL (minus the filename) as the location for initWasmModule.
        @Suppress("UNCHECKED_CAST")
        initCoreCryptoWasm("/index_bg.wasm")

        val metadata = buildMetadata()

        assertNotNull(metadata)
        assertNotNull(metadata.gitDescribe)
        println(metadata.toString())
        assertTrue(metadata.gitDescribe.isNotEmpty(), "gitDescribe should not be empty")

        assertEquals(
            CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
            cipherSuiteDefault()
        )
        assertTrue(version().isNotEmpty(), "version should not be empty")
    }

    @Test
    fun open_database() = runTest {
        initCoreCryptoWasm("/index_bg.wasm")

        val key = DatabaseKey(ByteArray(32) { it.toByte() })
        val database = openDatabase("kmp-js-wrapper-test", key)

        assertNotNull(database)
        assertEquals("kmp-js-wrapper-test", database.getLocation())

        val newKey = DatabaseKey(ByteArray(32) { (31 - it).toByte() })
        database.updateKey(newKey)

        val coreCrypto = coreCryptoNew(database)
        assertNotNull(coreCrypto)

        coreCrypto.destroy()
        database.destroy()
        newKey.destroy()
        key.destroy()
    }

    @Test
    fun register_logger_callback() = runTest {
        initCoreCryptoWasm("/index_bg.wasm")

        setLogger(object : CoreCryptoLogger {
            override fun log(level: CoreCryptoLogLevel, message: String, context: String?) {
                assertNotNull(level)
                assertNotNull(message)
            }
        })
        setMaxLogLevel(CoreCryptoLogLevel.OFF)
    }

    @Test
    fun calling_generateKeyPackages_should_return_expected_number() = runTest {
        val alice = ccInit()

        // by default, no key packages are generated
        assertEquals(
            0,
            alice.transaction { ctx ->
                ctx.getKeyPackages().size
            }
        )
        assertEquals(
            200,
            alice.transaction { ctx ->

                val credentialRef = alice.getCredentials().last()

                List(200U.toInt()) { _ -> ctx.generateKeyPackage(credentialRef) }.size
            }
        )
        assertEquals(
            200,
            alice.transaction { ctx ->
                ctx.getKeyPackages().size
            }
        )
    }
}
