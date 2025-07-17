//
// Wire
// Copyright (C) 2025 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
//

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
