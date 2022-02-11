import XCTest
@testable import CoreCrypto

class CoreCryptoTests: XCTestCase {
    func testVersion() throws {
        XCTAssertEqual(CoreCrypto.version(), "0.1.0")
    }
}
