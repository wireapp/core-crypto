@file:Suppress("ktlint:standard:no-wildcard-imports")

package testutils

import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import java.nio.ByteBuffer
import java.nio.file.Files
import java.util.UUID
import kotlin.test.*

fun genDatabaseKey(): DatabaseKey {
    val bytes = ByteArray(32)
    val random = java.security.SecureRandom()
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

class MockMlsTransportSuccessProvider : MockDeliveryService {
    private var latestCommitBundle: CommitBundle? = null

    override suspend fun sendMessage(mlsMessage: ByteArray): MlsTransportResponse =
        MlsTransportResponse.Success

    override suspend fun sendCommitBundle(commitBundle: CommitBundle): MlsTransportResponse {
        latestCommitBundle = commitBundle
        return MlsTransportResponse.Success
    }

    override suspend fun prepareForTransport(historySecret: HistorySecret): MlsTransportData {
        return "secret".encodeToByteArray()
    }

    override suspend fun getLatestCommitBundle(): CommitBundle = latestCommitBundle!!

    override suspend fun getLatestWelcome(): Welcome = getLatestCommitBundle().welcome!!

    override suspend fun getLatestCommit(): ByteArray = getLatestCommitBundle().commit
}

abstract class HasMockDeliveryService {
    companion object {
        internal lateinit var mockDeliveryService: MockDeliveryService
    }

    fun setupMocks() {
        mockDeliveryService = MockMlsTransportSuccessProvider()
    }
}

fun newClients(instance: HasMockDeliveryService, vararg clientIds: ClientId) = runBlocking {
    clientIds.map { clientID ->
        val cc = initCc(instance)
        cc.transaction { ctx -> ctx.mlsInitShort(clientID) }
        cc
    }
}

fun initCc(_instance: HasMockDeliveryService): CoreCryptoClient = runBlocking {
    val root = Files.createTempDirectory("mls").toFile()
    val keyStore = root.resolve("keystore-${randomIdentifier()}")
    val key = genDatabaseKey()
    val cc = CoreCrypto(keyStore.absolutePath, key)
    cc.provideTransport(HasMockDeliveryService.mockDeliveryService)
    cc
}

fun randomIdentifier(n: Int = 12): String {
    val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    return (1..n)
        .map { kotlin.random.Random.nextInt(0, charPool.size).let { charPool[it] } }
        .joinToString("")
}

/** Shorthand for initializing MLS with only a client id */
suspend fun CoreCryptoContext.mlsInitShort(clientId: ClientId) = mlsInit(clientId, CIPHERSUITES_DEFAULT, 1U)

/** Shorthand for creating a conversation with defaults */
suspend fun CoreCryptoContext.createConversationShort(
    id: ConversationId
) = createConversation(id, CREDENTIAL_TYPE_DEFAULT, CONVERSATION_CONFIGURATION_DEFAULT)

/** Shorthand for getting keypackages with defaults */
suspend fun CoreCryptoContext.clientKeypackagesShort(amount: UInt) = clientKeypackages(CIPHERSUITE_DEFAULT, CREDENTIAL_TYPE_DEFAULT, amount)
