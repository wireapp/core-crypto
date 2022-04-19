import XCTest
@testable import CoreCryptoSwift

class CoreCryptoTests: XCTestCase {
    func testVersion() throws {
        XCTAssertEqual(CoreCryptoSwift.version(), "0.2.0")
    }
}
