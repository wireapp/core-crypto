@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files

// Throughput of removing users from a conversation, including the database writes a user waits for.
@State(Scope.Thread)
open class RemoveUser : UserBenchmark() {
    private lateinit var aliceCc: CoreCrypto
    private lateinit var conversationId: ConversationId
    private lateinit var clientIdsToRemove: List<ClientId>

    @Setup(Level.Invocation)
    fun setup() {
        runBlocking {
            aliceCc = ccInit(CcInitOptions(CcInitOptions.Mode.WithBasicCredential(selectedCipherSuite)))
            conversationId = createConversation(aliceCc)

            val keyPackages = users.map { generateKeyPackage(it.cc) }
            clientIdsToRemove = users.map { it.id }

            aliceCc.transaction {
                it.addClientsToConversation(conversationId, keyPackages)
            }
        }
    }

    @Benchmark
    fun bench() = runBlocking {
        aliceCc.transaction {
            it.removeClientsFromConversation(conversationId, clientIdsToRemove)
        }
    }
}
