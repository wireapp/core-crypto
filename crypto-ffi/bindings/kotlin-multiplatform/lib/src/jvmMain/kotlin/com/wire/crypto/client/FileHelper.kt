package com.wire.crypto.client

import java.io.File

actual object FileHelper {
    actual fun fileExistsAtPath(path: String): Boolean {
        return File(path).exists()
    }

    actual fun deleteFilesAtPath(path: String): Boolean {
        return File(path).deleteRecursively()
    }

}
