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
        "1",
        "2",
        "3",
        "5",
        "7"
    )
    var cipherSuite: Int = 1

    @Param("1", "10", "100")
    var messageCount: Int = 0

    @Param("16", "1024", "65536")
    var messageSize: Int = 0

    private lateinit var encryptedMessages: List<ByteArray>
    private lateinit var conversationId: ConversationId

    private lateinit var bobCc: CoreCrypto

    @Setup(Level.Invocation)
    fun setup() = runBlocking {
        val cipherSuite = CipherSuite.entries.first { it.value.toInt() == cipherSuite }
        val options = CcInitOptions.Mode.WithBasicCredential(cipherSuite)
        val aliceCc = ccInit(CcInitOptions(options))
        conversationId = createConversation(aliceCc)

        bobCc = ccInit(CcInitOptions(options))
        invite(aliceCc, bobCc, conversationId)

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
