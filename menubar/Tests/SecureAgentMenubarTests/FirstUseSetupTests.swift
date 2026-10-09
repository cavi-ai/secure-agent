import AppKit
import ServiceManagement
import SwiftUI
import XCTest
@testable import SecureAgentMenubar

final class FirstUseSetupTests: XCTestCase {
    func testSelectedInstallationLeavesOtherHarnessesAndUserHooksUntouched() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("bundled")
        let home = root.appendingPathComponent("home with spaces")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".claude"), withIntermediateDirectories: true)
        try "inert fixture".write(to: source.appendingPathComponent("secret_guard.py"), atomically: true, encoding: .utf8)
        for name in ["activity_log.py", "injection_scan.py", "guard-rules.json"] {
            try "inert fixture".write(to: source.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
        try #"{"env":{"KEEP":"fixture"},"hooks":{"PreToolUse":[{"hooks":[{"command":"user-hook"}]}]}}"#
            .write(to: home.appendingPathComponent(".claude/settings.json"), atomically: true, encoding: .utf8)
        try SetupManager.installSelectedHooks(harness: "claude", bundledDir: source.path, home: home.path)
        XCTAssertTrue(FileManager.default.fileExists(atPath: home.appendingPathComponent(".claude/hooks/secret_guard.py").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".cursor").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".config/opencode").path))
        let settings = try String(contentsOf: home.appendingPathComponent(".claude/settings.json"), encoding: .utf8)
        XCTAssertTrue(settings.contains("user-hook"))
        XCTAssertTrue(settings.contains("KEEP"))
        XCTAssertTrue(SetupManager.claudeHooksRegistered(at: home.appendingPathComponent(".claude/settings.json").path))
        XCTAssertTrue(SetupManager.selectedHooksInstalled(harness: "claude", home: home.path))
        let backup = home.appendingPathComponent(".claude/settings.json.bak-secure-agent")
        let original = try Data(contentsOf: backup)
        try SetupManager.installSelectedHooks(harness: "claude", bundledDir: source.path, home: home.path)
        XCTAssertEqual(try Data(contentsOf: backup), original, "Repeated install must preserve the original user settings backup")
        try FileManager.default.removeItem(at: home.appendingPathComponent(".claude/hooks/activity_log.py"))
        XCTAssertFalse(SetupManager.selectedHooksInstalled(harness: "claude", home: home.path))
        try SetupManager.installSelectedHooks(harness: "cursor", bundledDir: source.path, home: home.path)
        XCTAssertTrue(SetupManager.selectedHooksInstalled(harness: "cursor", home: home.path))
        XCTAssertThrowsError(try SetupManager.installSelectedHooks(harness: "codex", bundledDir: source.path, home: home.path))
    }

    func testUnrelatedOrDisabledHookRegistrationCannotCountAsSelectedInstallation() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let dir = root.appendingPathComponent(".claude/hooks")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for name in ["secret_guard.py", "activity_log.py", "injection_scan.py", "guard-rules.json"] {
            try "inert fixture".write(to: dir.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
        let settings = root.appendingPathComponent(".claude/settings.json")
        let unrelated = "python3 /unrelated/.claude/hooks/secret_guard.py"
        try SetupManager.registerClaudeHooks(at: settings.path, command: unrelated)
        XCTAssertFalse(SetupManager.selectedHooksInstalled(harness: "claude", home: root.path))
        try SetupManager.registerClaudeHooks(at: settings.path, command: SetupManager.selectedHookCommand(harness: "claude", home: root.path))
        XCTAssertTrue(SetupManager.selectedHooksInstalled(harness: "claude", home: root.path))
        var data = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: settings)) as? [String: Any])
        data["disableAllHooks"] = true
        try JSONSerialization.data(withJSONObject: data).write(to: settings)
        XCTAssertFalse(SetupManager.selectedHooksInstalled(harness: "claude", home: root.path))
    }

    func testInvalidRegistrationDoesNotReplaceInstalledScripts() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("bundled")
        let home = root.appendingPathComponent("home")
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".claude/hooks"), withIntermediateDirectories: true)
        try "new fixture".write(to: source.appendingPathComponent("secret_guard.py"), atomically: true, encoding: .utf8)
        try "old fixture".write(to: home.appendingPathComponent(".claude/hooks/secret_guard.py"), atomically: true, encoding: .utf8)
        let settings = home.appendingPathComponent(".claude/settings.json")
        for invalid in ["invalid JSON", #"{"hooks":"user data"}"#, #"{"hooks":{"PreToolUse":"user data"}}"#,
                        #"{"hooks":{"PreToolUse":[{"hooks":"user data"}]}}"#, #"{"disableAllHooks":true}"#] {
            try invalid.write(to: settings, atomically: true, encoding: .utf8)
            XCTAssertThrowsError(try SetupManager.installSelectedHooks(harness: "claude", bundledDir: source.path, home: home.path))
            XCTAssertEqual(try String(contentsOf: home.appendingPathComponent(".claude/hooks/secret_guard.py"), encoding: .utf8), "old fixture")
            XCTAssertEqual(try String(contentsOf: settings, encoding: .utf8), invalid)
        }
    }

    func testResultCannotUseAnotherHarnessOrUnavailableStatusAsProof() {
        let receipt = CoverageProbeReceiptModel(harness: "cursor", hookPath: "/fixture/cursor", checkedAt: "fixture", state: "passed", detail: "fixture receipt")
        var state = FirstUseSetupState(daemonAvailable: true, installedHarnesses: ["claude"], probes: [receipt])
        XCTAssertEqual(state.result(for: "claude").title, "Hook check not run")
        state.probes = [CoverageProbeReceiptModel(harness: "claude", hookPath: "/fixture/claude", checkedAt: "fixture", state: "passed", detail: "Manual check only")]
        XCTAssertEqual(state.result(for: "claude").title, "Installed hook check passed")
        state.daemonAvailable = false
        XCTAssertEqual(state.result(for: "claude").title, "Monitor status unavailable")
        state.daemonAvailable = true
        state.installedHarnesses = []
        XCTAssertEqual(state.result(for: "claude").title, "Hooks not installed")
        XCTAssertEqual(state.result(for: "codex").title, "Observation path selected")
    }

    func testChangedAndExpiredReceiptsRequireAnotherCheck() {
        for value in ["changed", "expired", "failed", "unknown-future-state"] {
            let state = FirstUseSetupState(daemonAvailable: true, installedHarnesses: ["claude"], probes: [CoverageProbeReceiptModel(harness: "claude", hookPath: "/fixture", checkedAt: "fixture", state: value, detail: "Check again")])
            XCTAssertFalse(state.result(for: "claude").passed)
            XCTAssertNotEqual(state.result(for: "claude").title, "Installed hook check passed")
        }
    }

    @MainActor func testFirstUseDefersOptionalTelemetryUntilExplicitEnable() throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "FirstUseSetupTests.\(UUID().uuidString)"))
        let service = FakeESService()
        var panes: [ESSettingsPane] = []
        let setup = SetupManager(esService: service, defaults: defaults, plistPresent: { true },
                                 openPane: { panes.append($0) }, appURL: URL(fileURLWithPath: AppIdentity.installedAppPath),
                                 deferAutomaticTelemetry: true)
        setup.refreshESState()
        XCTAssertEqual(service.registerCount, 0)
        XCTAssertTrue(panes.isEmpty)
        try setup.installESCollector()
        XCTAssertEqual(service.registerCount, 1)
        XCTAssertFalse(defaults.bool(forKey: SetupManager.firstUseTelemetryConsentKey))
    }
}
