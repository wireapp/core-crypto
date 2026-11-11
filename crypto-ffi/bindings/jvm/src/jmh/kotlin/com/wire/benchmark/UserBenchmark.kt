package com.wire.benchmark

import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.State

@State(Scope.Thread)
open class UserBenchmark : CipherSuiteBenchmark() {
    @Param("1", "10", "100")
    var userCount: Int = 0
}
