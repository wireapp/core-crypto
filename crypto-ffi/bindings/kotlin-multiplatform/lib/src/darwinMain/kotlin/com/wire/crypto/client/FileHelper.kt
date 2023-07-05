package com.wire.crypto.client

import platform.Foundation.NSFileManager

actual object FileHelper {
    actual fun fileExistsAtPath(path: String): Boolean {
        return NSFileManager.defaultManager.fileExistsAtPath(path)
    }

    actual fun deleteFilesAtPath(path: String): Boolean {
        return NSFileManager.defaultManager.removeItemAtPath(path, null)
    }

}
