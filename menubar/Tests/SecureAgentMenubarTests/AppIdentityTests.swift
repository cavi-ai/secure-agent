import XCTest
@testable import SecureAgentMenubar

final class AppIdentityTests: XCTestCase {
    func testAppHasOneIdentity() {
        XCTAssertEqual(AppIdentity.bundleIdentifier, "com.cavi-ai.secure-agent",
                       "The file-telemetry helper is registered under this identity; no variant can manage it")
    }

    func testOnlyTheApplicationsCopyIsTheInstalledCopy() {
        XCTAssertTrue(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Secure Agent.app")))
        XCTAssertTrue(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Secure Agent.app/", isDirectory: true)))
        XCTAssertFalse(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Users/dev/secure-agent/dist/Secure Agent.app")),
                       "the build output in dist/ never manages the helper")
        XCTAssertFalse(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Secure Agent 2.app")))
        XCTAssertFalse(AppIdentity.isInstalledCopy(URL(fileURLWithPath: "/Applications/Utilities/Secure Agent.app")))
    }

    /// Symlinks against a temp stand-in for the installed copy: the test never
    /// depends on what this Mac has in /Applications.
    func testSymlinksResolveBeforeTheLocationCheck() throws {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("AppIdentityTests.\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        let installed = dir.appendingPathComponent("Applications/Secure Agent.app")
        try fm.createDirectory(at: installed, withIntermediateDirectories: true)
        // /var and /private/var name the same directory; compare resolved paths.
        let installedPath = installed.resolvingSymlinksInPath().standardizedFileURL.path

        XCTAssertTrue(AppIdentity.isInstalledCopy(installed, installedPath: installedPath))

        let toInstalled = dir.appendingPathComponent("Secure Agent.app")
        try fm.createSymbolicLink(atPath: toInstalled.path, withDestinationPath: installed.path)
        XCTAssertTrue(AppIdentity.isInstalledCopy(toInstalled, installedPath: installedPath),
                      "a symlink to the installed copy resolves to it")

        let dist = dir.appendingPathComponent("dist/Secure Agent.app")
        try fm.createDirectory(at: dist, withIntermediateDirectories: true)
        let toDist = dir.appendingPathComponent("Linked.app")
        try fm.createSymbolicLink(atPath: toDist.path, withDestinationPath: dist.path)
        XCTAssertFalse(AppIdentity.isInstalledCopy(toDist, installedPath: installedPath),
                       "a symlink to dist/ resolves to dist/")
        XCTAssertFalse(AppIdentity.isInstalledCopy(dist, installedPath: installedPath))
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
