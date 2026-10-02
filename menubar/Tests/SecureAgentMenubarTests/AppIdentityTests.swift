import XCTest
@testable import SecureAgentMenubar

final class AppIdentityTests: XCTestCase {
    func testAppHasOneIdentity() {
        XCTAssertEqual(AppIdentity.bundleIdentifier, "com.cavi-ai.secure-agent",
                       "The file-telemetry helper is registered under this identity; no variant can manage it")
    }
}
