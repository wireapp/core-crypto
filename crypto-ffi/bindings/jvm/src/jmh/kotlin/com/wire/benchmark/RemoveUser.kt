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
@State(Scope.Thread)
open class RemoveUser {
    @Param(
        "1",
        "2",
        "3",
        "5",
        "7"
    )
    var cipherSuite: UShort = 1u

    @Param("1", "10", "100")
    var userCount: Int = 0

    private lateinit var aliceCc: CoreCrypto
    private lateinit var conversationId: ConversationId
    private lateinit var clientIdsToRemove: List<ClientId>

    @Setup(Level.Invocation)
    fun setup() {
        runBlocking {
            val cipherSuite = CipherSuite.entries.first { it.value == cipherSuite }
            aliceCc = ccInit(CcInitOptions(CcInitOptions.Mode.WithBasicCredential(cipherSuite)))
            conversationId = createConversation(aliceCc)

            val keyPackages = mutableListOf<KeyPackage>()
            clientIdsToRemove = buildList {
                repeat(userCount) {
                    val bobId = genClientId()
                    val bobCc =
                        ccInit(
                            CcInitOptions(
                                mode = CcInitOptions.Mode.WithBasicCredential(cipherSuite),
                                clientId = bobId
                            )
                        )
                    val kp = generateKeyPackage(bobCc)
                    keyPackages.add(kp)
                    this.add(bobId)
                }
            }

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
