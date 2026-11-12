package com.wire.benchmark

import com.wire.crypto.CipherSuite
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.State

@State(Scope.Thread)
open class CipherSuiteBenchmark {
    @Param(
        "0x0001",
        "0x0002",
        "0x0003",
        "0xF001",
        "0xF003",
        "0xF006"
    )
    var cipherSuite: String = "1"

    protected val selectedCipherSuite: CipherSuite
        get() = CipherSuite.entries.first { it.value.toInt() == Integer.decode(cipherSuite) }
}
