package com.wire.benchmark

import com.wire.crypto.ClientId
import com.wire.crypto.CoreCrypto
import kotlinx.coroutines.runBlocking
import org.openjdk.jmh.annotations.Level
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import testutils.CcInitOptions
import testutils.ccInit
import testutils.genClientId

@State(Scope.Thread)
open class UserBenchmark : CipherSuiteBenchmark() {
    @Param("1", "10", "100")
    var userCount: Int = 0

    // Users only provide key packages, so they're set up once per trial, and each invocation
    // takes fresh key packages from them.
    protected lateinit var users: List<User>

    @Setup(Level.Trial)
    fun createUsers() {
        runBlocking {
            users = List(userCount) {
                val id = genClientId()
                val options = CcInitOptions(CcInitOptions.Mode.WithBasicCredential(selectedCipherSuite), clientId = id)
                User(id, ccInit(options))
            }
        }
    }

    protected class User(val id: ClientId, val cc: CoreCrypto)
}
