@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files
import kotlin.collections.MutableList

// Throughput of decrypting messages in one transaction, including the database writes a user waits for.
@State(Scope.Thread)
open class ProcessMessage : MessageBenchmark() {
    private lateinit var encryptedMessages: List<ByteArray>
    private lateinit var conversationId: ConversationId

    private lateinit var bobCc: CoreCrypto

    @Setup(Level.Invocation)
    fun setup() = runBlocking {
        val options = CcInitOptions.Mode.WithBasicCredential(selectedCipherSuite)
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
