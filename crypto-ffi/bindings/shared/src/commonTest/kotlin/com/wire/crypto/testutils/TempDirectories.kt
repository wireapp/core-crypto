package testutils

import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory

/** Creates a new, empty directory in the system's temporary directory, named [prefix] and a random suffix. */
fun newTempDirectory(prefix: String): Path {
    val directory = Path(SystemTemporaryDirectory, prefix + randomIdentifier())
    SystemFileSystem.createDirectories(directory, mustCreate = true)
    return directory
}

/** Deletes [path] and, if it is a directory, everything in it. */
fun deleteRecursively(path: Path) {
    if (SystemFileSystem.metadataOrNull(path)?.isDirectory == true) {
        SystemFileSystem.list(path).forEach(::deleteRecursively)
    }
    SystemFileSystem.delete(path, mustExist = false)
}
