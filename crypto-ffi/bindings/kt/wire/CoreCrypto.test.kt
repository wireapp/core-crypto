package wire;

import com.wire.crypto;

import org.junit.Test

import org.junit.Assert.*

class BasicUnitTest {
    @Test
    fun version_Works() {
        assertEquals(com.wire.core.version(), "0.3.0")
    }
}
