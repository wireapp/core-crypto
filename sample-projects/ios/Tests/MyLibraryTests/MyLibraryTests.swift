import XCTest
@testable import MyLibrary

final class MyLibraryTests: XCTestCase {
    func testExample() throws {
        XCTAssertEqual(MyLibrary.version(), "0.1.0")
    }
}
