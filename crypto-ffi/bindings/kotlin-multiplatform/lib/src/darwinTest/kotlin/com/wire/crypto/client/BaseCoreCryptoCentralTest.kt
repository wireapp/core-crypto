package com.wire.crypto.client

import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSURL
import platform.Foundation.NSUUID

actual open class BaseCoreCryptoCentralTest {
    actual suspend fun createCoreCryptoCentral(id: String): CoreCryptoCentral {
        val rootDir = NSURL.fileURLWithPath(
            path = NSTemporaryDirectory() + "core-crypto-central-${NSUUID().UUIDString}",
            isDirectory = true
        )
        NSFileManager.defaultManager.createDirectoryAtURL(rootDir, true, null, null)
        return CoreCryptoCentral(rootDir.path!!, "secret")
    }

}
