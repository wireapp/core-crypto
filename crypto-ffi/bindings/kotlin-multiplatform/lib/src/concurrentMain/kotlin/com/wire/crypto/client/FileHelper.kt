package com.wire.crypto.client

expect object FileHelper {

    fun fileExistsAtPath(path: String): Boolean

    fun deleteFilesAtPath(path: String): Boolean

}
