package com.wire.benchmark

import com.wire.crypto.CipherSuite
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.State

@State(Scope.Thread)
open class CipherSuiteBenchmark {
    @Param(
        "1",
        "2",
        "3",
        "5",
        "7"
    )
    var cipherSuite: UShort = 1u

    protected val selectedCipherSuite: CipherSuite
        get() = CipherSuite.entries.first { it.value == cipherSuite }
}
