import XCTest
@testable import SecureAgentMenubar

final class NativeHookRegistrationTests: XCTestCase {
    func testCodexPreservesUserHooksBackupAndIsIdempotent() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("hooks.json").path
        let original = Data(#"{"description":"keep","hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"user-hook"}]}],"Stop":[]}}"#.utf8)
        try original.write(to: URL(fileURLWithPath: path))
        let command = "python3 '/tmp/home with spaces/.codex/hooks/harness_guard.py' codex"
        try HookRegistry.Codex.register(at: path, command: command)
        let first = try Data(contentsOf: URL(fileURLWithPath: path))
        try HookRegistry.Codex.register(at: path, command: command)
        XCTAssertEqual(first, try Data(contentsOf: URL(fileURLWithPath: path)))
        XCTAssertEqual(original, try Data(contentsOf: URL(fileURLWithPath: path + ".bak-secure-agent")))
        XCTAssertTrue(HookRegistry.Codex.registered(at: path, command: command))
        try HookRegistry.Codex.unregister(at: path, command: command)
        let after = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertTrue(after.contains("user-hook"))
        XCTAssertTrue(after.contains("keep"))
        XCTAssertFalse(HookRegistry.Codex.registered(at: path, command: command))
    }

    func testNativeHarnessChoicesAndActivationGuidance() {
        for harness in ["codex", "openclaw"] {
            XCTAssertTrue(FirstUseSetupState.supportsHook(harness))
            let state = FirstUseSetupState(daemonAvailable: true, installedHarnesses: [harness])
            XCTAssertFalse(state.result(for: harness).passed)
            XCTAssertNotEqual(state.result(for: harness).title, "Observation path selected")
        }
    }

    func testNativeInstallationsAreSelectedAndRejectInvalidConfiguration() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("native home '\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("plugin/hooks")
        try HookRegistry.installSelectedHooks(harness: "codex", bundledDir: source.path, home: home.path)
        XCTAssertTrue(HookRegistry.selectedHooksInstalled(harness: "codex", home: home.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".claude").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".openclaw").path))
        let settings = home.appendingPathComponent(".codex/hooks.json")
        let script = home.appendingPathComponent(".codex/hooks/harness_guard.py")
        try "previous script".write(to: script, atomically: true, encoding: .utf8)
        for invalid in ["invalid JSON", #"{"hooks":[]}"#, #"{"hooks":{"PreToolUse":[{"hooks":"keep"}]}}"#] {
            try invalid.write(to: settings, atomically: true, encoding: .utf8)
            XCTAssertThrowsError(try HookRegistry.installSelectedHooks(harness: "codex", bundledDir: source.path, home: home.path))
            XCTAssertEqual(try String(contentsOf: script, encoding: .utf8), "previous script")
            XCTAssertEqual(try String(contentsOf: settings, encoding: .utf8), invalid)
        }
        try HookRegistry.installSelectedHooks(harness: "openclaw", bundledDir: source.path, home: home.path)
        XCTAssertTrue(HookRegistry.selectedHooksInstalled(harness: "openclaw", home: home.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".openclaw/openclaw.json").path), "Only OpenClaw's CLI may update its config")
        let package = home.appendingPathComponent(".openclaw/extensions/secure-agent/package.json")
        try #"{"name":"user-plugin"}"#.write(to: package, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try HookRegistry.installSelectedHooks(harness: "openclaw", bundledDir: source.path, home: home.path))
        XCTAssertTrue(try String(contentsOf: package, encoding: .utf8).contains("user-plugin"))
    }

    @MainActor
    func testOpenClawRegistrationUsesItsCLIAndPropagatesRejection() async throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "NativeHookRegistrationTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, plistPresent: { false }, openPane: { _ in }, deferAutomaticTelemetry: true)
        setup.runProcess = { bin, args in
            XCTAssertEqual(bin, "/usr/bin/env")
            if args.last == "--json" {
                let source = HookRegistry.hookDirectory(harness: "openclaw", home: NSHomeDirectory()) + "/index.mjs"
                let report: [String: Any] = ["plugin": ["id": "secure-agent", "source": source]]
                return (0, String(data: try! JSONSerialization.data(withJSONObject: report), encoding: .utf8)!, "")
            }
            XCTAssertEqual(Array(args.suffix(4)), ["openclaw", "plugins", "enable", "secure-agent"])
            XCTAssertFalse(args.contains("--force"))
            XCTAssertFalse(args.contains("--accept-capabilities"))
            return (1, "", "policy rejected")
        }
        do {
            try await setup.registerOpenClawHooks()
            XCTFail("A rejected registration cannot succeed")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("could not enable"))
        }
    }

    @MainActor
    func testOpenClawRegistrationRejectsAnotherPluginWithTheSameID() async throws {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "NativeHookRegistrationTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, plistPresent: { false }, openPane: { _ in }, deferAutomaticTelemetry: true)
        setup.runProcess = { _, args in
            XCTAssertEqual(Array(args.suffix(5)), ["openclaw", "plugins", "info", "secure-agent", "--json"])
            return (0, #"{"plugin":{"id":"secure-agent","source":"/another/plugin/index.mjs"}}"#, "")
        }
        do {
            try await setup.registerOpenClawHooks()
            XCTFail("An unrelated plugin must not be enabled")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("different plugin"))
        }
    }
}
