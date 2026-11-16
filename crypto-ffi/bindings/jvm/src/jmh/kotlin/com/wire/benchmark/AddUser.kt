@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files

// This benchmark measures throughput of encrypting messages in a transaction and committing these.
// It includes the database interaction, because want to be able to answer to a user how long creating messages takes.
@State(Scope.Thread)
open class AddUser : UserBenchmark() {
    private lateinit var aliceCc: CoreCrypto
    private lateinit var conversationId: ConversationId
    private lateinit var keyPackages: List<KeyPackage>

    @Setup(Level.Invocation)
    fun setup() {
        runBlocking {
            aliceCc = ccInit(CcInitOptions(CcInitOptions.Mode.WithBasicCredential(selectedCipherSuite)))
            conversationId = createConversation(aliceCc)
            keyPackages = users.map { generateKeyPackage(it.cc) }
        }
    }

    @Benchmark
    fun bench() = runBlocking {
        aliceCc.transaction {
            it.addClientsToConversation(conversationId, keyPackages)
        }
    }
}
