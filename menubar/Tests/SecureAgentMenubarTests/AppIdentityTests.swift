import XCTest
@testable import SecureAgentMenubar

final class AppIdentityTests: XCTestCase {
    func testAppHasOneIdentity() {
        XCTAssertEqual(AppIdentity.bundleIdentifier, "com.cavi-ai.secure-agent",
                       "The file-telemetry helper is registered under this identity; no variant can manage it")
    }

    @MainActor
    func testPreferencesAreTheStandardDomain() {
        XCTAssertTrue(AppPreferences.shared === UserDefaults.standard,
                      "A suite named after the app's own bundle identifier is nil in the app")
        let key = "AppIdentityTests.\(UUID().uuidString)"
        UserDefaults.standard.set(true, forKey: key)
        defer { UserDefaults.standard.removeObject(forKey: key) }
        XCTAssertTrue(AppPreferences.shared.bool(forKey: key))
    }
}
