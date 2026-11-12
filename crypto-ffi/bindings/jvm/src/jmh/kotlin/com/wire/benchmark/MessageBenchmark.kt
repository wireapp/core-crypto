package com.wire.benchmark

import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.State

@State(Scope.Thread)
open class MessageBenchmark : CipherSuiteBenchmark() {
    @Param("1", "10")
    var messageCount: Int = 0

    @Param("16", "1024", "65536")
    var messageSize: Int = 0
}
