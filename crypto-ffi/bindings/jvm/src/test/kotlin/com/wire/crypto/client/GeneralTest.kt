/*
 * Wire
 * Copyright (C) 2023 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 */

package com.wire.crypto.client

import com.wire.crypto.CoreCryptoException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThatNoException
import uniffi.core_crypto.CryptoError
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import com.wire.crypto.version
import com.wire.crypto.buildMetadata

class GeneralTest {
    @Test
    fun get_version() = runTest {
        val version = version()

        assertThat(version).isNotNull()
        assertThat(version).isNotEmpty()
    }

    @Test
    fun get_build_metadata() = runTest {
        val build_metadata = buildMetadata();

        assertThat(build_metadata).isNotNull()
        assertThat(build_metadata.gitDescribe).isNotNull()
        assertThat(build_metadata.gitDescribe).isNotEmpty()
    }
}
