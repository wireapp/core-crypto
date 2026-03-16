@file:Suppress("ktlint:standard:no-wildcard-imports")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files
import java.util.concurrent.TimeUnit

// This benchmark measures throughput of encrypting messages in a transaction and committing these.
// It includes the database interaction, because want to be able to answer to a user how long creating messages takes.
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
open class CreateMessage {
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

    private lateinit var messages: List<ByteArray>
    private lateinit var conversationId: ConversationId
    private lateinit var cc: CoreCrypto

    @Setup(Level.Iteration)
    fun setup() = runBlocking {
        val aliceId = genClientId()
        conversationId = genConversationId()
        cc = initCc()
        cc.transaction {
            it.mlsInit(aliceId, MockMlsTransportSuccessProvider())
            val credentialRef = it.addCredential(Credential.basic(Ciphersuite.valueOf(cipherSuite), aliceId))
            it.createConversation(conversationId, credentialRef, null)
        }
        messages = List(messageCount) {
            ByteArray(messageSize) { 'A'.code.toByte() }
        }
    }

    @Benchmark
    fun createMessages() = runBlocking {
        cc.transaction {
            for (msg in messages) {
                it.encryptMessage(conversationId, msg)
            }
        }
    }
}
