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
        cc.transaction { ctx ->
            ctx.mlsInitShort(clientID)
            ctx.addCredential(Credential.basic(CIPHERSUITE_DEFAULT, clientID))
        }
        cc
    }
}

fun initCc(_instance: HasMockDeliveryService): CoreCrypto = runBlocking {
    val root = Files.createTempDirectory("mls").toFile()
    val path = root.resolve("keystore-${randomIdentifier()}")
    val key = genDatabaseKey()
    val db = openDatabase(path.absolutePath, key)
    val cc = CoreCrypto(db)
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
suspend fun CoreCryptoContext.mlsInitShort(clientId: ClientId) = mlsInit(clientId, CIPHERSUITES_DEFAULT)

/** Shorthand for creating a conversation with defaults */
suspend fun CoreCryptoContext.createConversationShort(
    id: ConversationId
) = createConversation(id, CREDENTIAL_TYPE_DEFAULT, CONVERSATION_CONFIGURATION_DEFAULT)

/** Shorthand for generating keypackages with defaults */
suspend fun CoreCryptoContext.clientKeypackagesShort(amount: UInt): List<Keypackage> {
    val credentials = findCredentials(
        clientId = null,
        publicKey = null,
        ciphersuite = CIPHERSUITE_DEFAULT,
        credentialType = CREDENTIAL_TYPE_DEFAULT,
        earliestValidity = null
    )
    val credential = credentials.last()

    return List(amount.toInt()) { _ ->
        // cycle through credentials if amount > credentials.size
        generateKeypackage(credential)
    }
}
