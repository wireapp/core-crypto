/*
 * Wire
 * Copyright (C) 2025 Wire Swiss GmbH
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
package com.wire.crypto

import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue

class TransactionTest {
    @Test
    fun givenTransactionRunsSuccessfully_thenShouldBeAbleToFinishOtherTransactions() = runTest {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-Potato")
        val coreCrypto = CoreCrypto(
            keystore = keyStore.absolutePath,
            databaseKey = DatabaseKey("someKeysomeKeysomeKeysomeKey1234".toByteArray())
        )
        val someWork = Job()
        val firstTransactionJob = launch {
            coreCrypto.transaction {
                someWork.complete()
            }
        }
        firstTransactionJob.join()

        var didRun = false
        val secondTransactionJob = launch {
            coreCrypto.transaction {
                didRun = true
            }
        }
        secondTransactionJob.join()
        assertTrue { didRun }
    }

    @Test
    fun givenTransactionIsCancelled_thenShouldBeAbleToFinishOtherTransactions() = runTest {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-Potato")
        val coreCrypto = CoreCrypto(
            keystore = keyStore.absolutePath,
            databaseKey = DatabaseKey("someKeysomeKeysomeKeysomeKey1234".toByteArray())
        )

        val firstTransactionJob = launch {
            coreCrypto.transaction {
                this@launch.cancel()
            }
        }
        firstTransactionJob.join()

        var didRun = false
        val secondTransactionJob = launch {
            coreCrypto.transaction {
                didRun = true
            }
        }
        secondTransactionJob.join()
        assertTrue { didRun }
    }
}
