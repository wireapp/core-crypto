import System

extension FilePath {

    /// Turn a relative path into an absolute path. If the path is already absolute `self` is returned.
    func absolutePath() -> FilePath {
        if isRelative {
            FilePath(FileManager.default.currentDirectoryPath).pushing(self)
        } else {
            self
        }
    }
}
