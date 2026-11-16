@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files

// Throughput of encrypting messages in one transaction, including the database writes a user waits for.
@State(Scope.Benchmark)
open class CreateMessage : MessageBenchmark() {
    private lateinit var messages: List<ByteArray>
    private lateinit var conversationId: ConversationId
    private lateinit var cc: CoreCrypto

    @Setup(Level.Iteration)
    fun setup() = runBlocking {
        cc = ccInit(CcInitOptions(CcInitOptions.Mode.WithBasicCredential(selectedCipherSuite)))
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
