@file:Suppress("ktlint:standard:no-wildcard-imports")

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
        aliceCc.transaction {
            it.mlsInit(aliceId, mockTransportProvider)
            val credentialRef = it.addCredential(Credential.basic(CipherSuite.valueOf(cipherSuite), aliceId))
            it.createConversation(conversationId, credentialRef, null)
        }

        val bobId = genClientId()
        bobCc = initCc()
        val kp = bobCc.transaction {
            it.mlsInit(bobId, mockTransportProvider)
            val credentialRef = it.addCredential(Credential.basic(CipherSuite.valueOf(cipherSuite), bobId))
            it.generateKeyPackage(credentialRef)
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

        aliceCc.transaction {
            val tempList = mutableListOf<ByteArray>()
            messages.forEach { msg ->
                tempList += it.encryptMessage(conversationId, msg)
            }
            encryptedMessages = tempList
        }
    }

    @Benchmark
    fun processMessages() = runBlocking {
        bobCc.transaction {
            for (msg in encryptedMessages) {
                it.decryptMessage(conversationId, msg)
            }
        }
    }
}
