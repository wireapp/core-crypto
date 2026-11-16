package com.wire.benchmark

import com.wire.crypto.CipherSuite
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Level
import org.openjdk.jmh.annotations.Measurement
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.TearDown
import org.openjdk.jmh.annotations.Warmup
import testutils.deleteDatabases
import java.util.concurrent.TimeUnit

// JMH applies these to every benchmark that extends this class.
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
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

    // A trial runs one combination of parameters, so nothing uses its databases once it's over.
    @TearDown(Level.Trial)
    fun deleteTrialDatabases() = deleteDatabases()
}
