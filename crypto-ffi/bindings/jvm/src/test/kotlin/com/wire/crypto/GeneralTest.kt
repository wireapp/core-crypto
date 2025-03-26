package com.wire.crypto

import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import kotlin.test.Test
import com.wire.crypto.uniffi.version
import com.wire.crypto.uniffi.buildMetadata

class GeneralTest {
    @Test
    fun get_version() = runTest {
        val version = version()

        assertThat(version).isNotNull()
        assertThat(version).isNotEmpty()
    }

    @Test
    fun get_build_metadata() = runTest {
        val build_metadata = buildMetadata()

        assertThat(build_metadata).isNotNull()
        assertThat(build_metadata.gitDescribe).isNotNull()
        assertThat(build_metadata.gitDescribe).isNotEmpty()
    }
}
