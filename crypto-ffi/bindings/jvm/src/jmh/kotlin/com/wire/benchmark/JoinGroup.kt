@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.benchmark
import com.wire.crypto.*
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.*
import testutils.*
import java.nio.file.Files
import java.util.concurrent.TimeUnit

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Thread)
open class JoinGroup : UserBenchmark() {
    private lateinit var charlieCc: CoreCrypto
    private lateinit var conversationId: ConversationId
    private lateinit var welcome: Welcome

    @Setup(Level.Invocation)
    fun setup() {
        runBlocking {
            val options = CcInitOptions(CcInitOptions.Mode.WithBasicCredential(selectedCipherSuite))
            val aliceCc = ccInit(options)
            conversationId = createConversation(aliceCc)

            if (userCount > 1) {
                val keyPackages = users.map { generateKeyPackage(it.cc) }
                aliceCc.transaction {
                    it.addClientsToConversation(conversationId, keyPackages)
                }
            }

            charlieCc = ccInit(options)
            val kp = generateKeyPackage(charlieCc)

            aliceCc.transaction {
                it.addClientsToConversation(conversationId, listOf(kp))
            }
            welcome = MockMlsTransportSuccessProvider.getInstance().getLatestWelcome()
        }
    }

    @Benchmark
    fun bench() = runBlocking {
        charlieCc.transaction { ctx ->
            ctx.processWelcomeMessage(welcome)
        }
    }
}
