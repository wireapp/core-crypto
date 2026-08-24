@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

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
        "1",
        "2",
        "3",
        "5",
        "7"
    )
    var cipherSuite: UShort = 1u

    @Param("1", "10", "100")
    var messageCount: Int = 0

    @Param("16", "1024", "65536")
    var messageSize: Int = 0

    private lateinit var messages: List<ByteArray>
    private lateinit var conversationId: ConversationId
    private lateinit var cc: CoreCrypto

    @Setup(Level.Iteration)
    fun setup() = runBlocking {
        val cipherSuite = CipherSuite.entries.first { it.value == cipherSuite }
        cc = ccInit(CcInitOptions(CcInitOptions.Mode.WithBasicCredential(cipherSuite)))
        conversationId = createConversation(cc)
        messages = List(messageCount) {
            ByteArray(messageSize) { 'A'.code.toByte() }
        }
    }

    @Benchmark
    fun bench() = runBlocking {
        cc.transaction { ctx ->
            for (msg in messages) {
                ctx.encryptMessage(conversationId, msg)
            }
        }
    }
}
