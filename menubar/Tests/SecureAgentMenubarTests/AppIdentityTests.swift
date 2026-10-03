import XCTest
@testable import SecureAgentMenubar

final class AppIdentityTests: XCTestCase {
    func testAppHasOneIdentity() {
        XCTAssertEqual(AppIdentity.bundleIdentifier, "com.cavi-ai.secure-agent",
                       "The file-telemetry helper is registered under this identity; no variant can manage it")
    }

    func testOnlyTheApplicationsCopyIsTheInstalledCopy() throws {
        XCTAssertTrue(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Secure Agent.app")))
        XCTAssertTrue(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Secure Agent.app/", isDirectory: true)))
        XCTAssertFalse(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Users/dev/secure-agent/dist/Secure Agent.app")),
                       "the build output in dist/ never manages the helper")
        XCTAssertFalse(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Secure Agent 2.app")))
        XCTAssertFalse(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Utilities/Secure Agent.app")))

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("AppIdentityTests.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let toApplications = dir.appendingPathComponent("Secure Agent.app")
        try FileManager.default.createSymbolicLink(atPath: toApplications.path,
                                                   withDestinationPath: "/Applications/Secure Agent.app")
        XCTAssertTrue(AppIdentity.isInstalledCopy(toApplications), "a symlink to the /Applications copy resolves to it")

        let dist = dir.appendingPathComponent("dist/Secure Agent.app")
        try FileManager.default.createDirectory(at: dist, withIntermediateDirectories: true)
        let toDist = dir.appendingPathComponent("Linked.app")
        try FileManager.default.createSymbolicLink(atPath: toDist.path, withDestinationPath: dist.path)
        XCTAssertFalse(AppIdentity.isInstalledCopy(toDist), "a symlink to dist/ resolves to dist/")
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
