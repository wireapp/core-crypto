@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package testutils

import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import java.nio.ByteBuffer
import java.nio.file.Files
import java.security.SecureRandom
import java.util.UUID
import kotlin.random.Random
import kotlin.test.*

fun genDatabaseKey(): DatabaseKey {
    val bytes = ByteArray(32)
    val random = SecureRandom()
    random.nextBytes(bytes)
    return DatabaseKey(bytes)
}

private fun uuidBytes(): ByteArray {
    val uuid = UUID.randomUUID()
    return ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()
}

fun genClientId(): ClientId {
    return ClientId(uuidBytes())
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
        @Volatile
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

sealed interface CcInitOptions {
    val clientId: ClientId?
    val database: Database?

    data class WithoutBasicCredential(
        override val clientId: ClientId? = null,
        override val database: Database? = null,
    ) : CcInitOptions

    data class WithBasicCredential(
        val cipherSuite: CipherSuite = CIPHERSUITE_DEFAULT,
        override val clientId: ClientId? = null,
        override val database: Database? = null,
    ) : CcInitOptions
}

suspend fun ccInit(
    options: CcInitOptions = CcInitOptions.WithBasicCredential()
): CoreCrypto {
    val db = options.database ?: newDatabase()
    val cc = CoreCrypto(db)

    val clientId = options.clientId ?: genClientId()

    cc.transaction { ctx ->
        ctx.mlsInit(clientId, MockMlsTransportSuccessProvider.getInstance())

        when (options) {
            is CcInitOptions.WithBasicCredential -> {
                ctx.addCredential(
                    Credential.basic(
                        options.cipherSuite,
                        clientId
                    )
                )
            }

            is CcInitOptions.WithoutBasicCredential -> {
                // nothing
            }
        }
    }
    return cc
}

suspend fun newDatabase(): Database {
    val root = Files.createTempDirectory("mls").toFile()
    val path = root.resolve("keystore-${randomIdentifier()}")
    val key = genDatabaseKey()
    return openDatabase(path.absolutePath, key)
}

suspend fun createConversation(cc: CoreCrypto): ConversationId {
    val conversationId = genConversationId()
    val credentialRef = cc.getCredentials().last()
    cc.transaction { ctx ->
        ctx.createConversation(conversationId, credentialRef)
    }
    return conversationId
}

suspend fun invite(cc1: CoreCrypto, cc2: CoreCrypto, conversationId: ConversationId): ConversationId {
    val kp = generateKeyPackage(cc2)
    cc1.transaction {
        it.addClientsToConversation(conversationId, listOf(kp))
    }
    val welcome = MockMlsTransportSuccessProvider.getInstance().getLatestWelcome()
    return cc2.transaction { ctx -> ctx.processWelcomeMessage(welcome) }
}

suspend fun generateKeyPackage(cc: CoreCrypto): KeyPackage {
    val credentialRef = cc.getCredentials().last()
    return cc.transaction { ctx ->
        ctx.generateKeyPackage(credentialRef)
    }
}

fun randomIdentifier(n: Int = 12): String {
    val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    return (1..n)
        .map { Random.nextInt(0, charPool.size).let { index -> charPool[index] } }
        .joinToString("")
}
