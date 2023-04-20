package com.wire.crypto.client

import java.nio.file.Files

actual open class BaseCoreCryptoCentralTest {
    actual suspend fun createCoreCryptoCentral(id: String): CoreCryptoCentral {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-$id").also { it.mkdirs() }
        return CoreCryptoCentral(keyStore.absolutePath, "secret")
    }

}
