@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.collections.MutableList

// This benchmark measures throughput of encrypting messages in a transaction and committing these.
// It includes the database interaction, because want to be able to answer to a user how long creating messages takes.
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Thread)
open class ProcessMessage {
    @Param(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519",
        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
        "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519",
        "MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
        "MLS_256_DHKEMP384_AES256GCM_SHA384_P384"
    )
    var cipherSuite: String = ""

    @Param("1", "10", "100")
    var messageCount: Int = 0

    @Param("16", "1024", "65536")
    var messageSize: Int = 0

    private lateinit var encryptedMessages: List<ByteArray>
    private lateinit var conversationId: ConversationId

    private lateinit var bobCc: CoreCrypto

    @Setup(Level.Invocation)
    fun setup() = runBlocking {
        val aliceId = genClientId()
        conversationId = genConversationId()
        val aliceCc = initCc()
        val mockTransportProvider = MockMlsTransportSuccessProvider()
        aliceCc.transaction { ctx ->
            ctx.mlsInit(aliceId, mockTransportProvider)
            val credentialRef = ctx.addCredential(Credential.basic(CipherSuite.valueOf(cipherSuite), aliceId))
            ctx.createConversation(conversationId, credentialRef, null)
        }

        val bobId = genClientId()
        bobCc = initCc()
        val kp = bobCc.transaction { ctx ->
            ctx.mlsInit(bobId, mockTransportProvider)
            val credentialRef = ctx.addCredential(Credential.basic(CipherSuite.valueOf(cipherSuite), bobId))
            ctx.generateKeyPackage(credentialRef)
        }

        aliceCc.transaction {
            it.addClientsToConversation(conversationId, keyPackages = listOf(kp))
        }

        val welcome = mockTransportProvider.getLatestWelcome()
        bobCc.transaction {
            it.processWelcomeMessage(welcome)
        }

        val messages = List(messageCount) {
            ByteArray(messageSize) { 'A'.code.toByte() }
        }

        aliceCc.transaction { ctx ->
            val tempList = mutableListOf<ByteArray>()
            messages.forEach { msg ->
                tempList += ctx.encryptMessage(conversationId, msg)
            }
            encryptedMessages = tempList
        }
    }

    @Benchmark
    fun bench() = runBlocking {
        bobCc.transaction { ctx ->
            for (msg in encryptedMessages) {
                ctx.decryptMessage(conversationId, msg)
            }
        }
    }
}
