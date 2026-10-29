import XCTest
@testable import SecureAgentMenubar

final class AdditionalHookRegistrationTests: XCTestCase {
    private var home: URL!
    private var source: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("plugin/hooks")
    }
    override func setUpWithError() throws {
        home = FileManager.default.temporaryDirectory.appendingPathComponent("more native '\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: home) }

    func testSelectedInstallationsAndIdempotence() throws {
        for harness in ["antigravity", "hermes", "opencode"] {
            XCTAssertTrue(FirstUseSetupState.supportsHook(harness))
            try HookRegistry.installSelectedHooks(harness: harness, bundledDir: source.path, home: home.path)
            XCTAssertTrue(HookRegistry.selectedHooksInstalled(harness: harness, home: home.path), harness)
            try HookRegistry.installSelectedHooks(harness: harness, bundledDir: source.path, home: home.path)
            XCTAssertTrue(HookRegistry.selectedHooksInstalled(harness: harness, home: home.path), harness)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".claude").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".codex").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: home.appendingPathComponent(".config/opencode/opencode.json").path))
    }

    func testAntigravityPreservesNamedHooksAndFirstBackup() throws {
        let path = home.appendingPathComponent(".gemini/config/hooks.json")
        try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = Data(#"{"user-hook":{"PreToolUse":[{"hooks":[{"command":"keep"}]}]}}"#.utf8)
        try original.write(to: path)
        try HookRegistry.installSelectedHooks(harness: "antigravity", bundledDir: source.path, home: home.path)
        let first = try Data(contentsOf: path)
        try HookRegistry.installSelectedHooks(harness: "antigravity", bundledDir: source.path, home: home.path)
        XCTAssertEqual(first, try Data(contentsOf: path))
        XCTAssertEqual(original, try Data(contentsOf: URL(fileURLWithPath: path.path + ".bak-secure-agent")))
        XCTAssertTrue(String(decoding: first, as: UTF8.self).contains("keep"))
        try HookRegistry.Antigravity.unregister(at: path.path, command: HookRegistry.selectedHookCommand(harness: "antigravity", home: home.path))
        XCTAssertFalse(HookRegistry.selectedHooksInstalled(harness: "antigravity", home: home.path))
        XCTAssertTrue(try String(contentsOf: path, encoding: .utf8).contains("user-hook"))
        try HookRegistry.installSelectedHooks(harness: "antigravity", bundledDir: source.path, home: home.path)
        var root = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
        var own = root["secure-agent"] as! [String: Any]
        var groups = own["PreToolUse"] as! [[String: Any]]
        groups.append(["hooks": "unsupported user data"])
        own["PreToolUse"] = groups; root["secure-agent"] = own
        let invalid = try JSONSerialization.data(withJSONObject: root)
        try invalid.write(to: path)
        XCTAssertThrowsError(try HookRegistry.installSelectedHooks(harness: "antigravity", bundledDir: source.path, home: home.path))
        XCTAssertEqual(invalid, try Data(contentsOf: path))
    }

    func testHermesPreservesPluginListsAndRejectsUnsupportedYAML() throws {
        let path = home.appendingPathComponent(".hermes/config.yaml")
        try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = "# keep comment\nmodel: keep-model\nplugins:\n  enabled: [user-plugin]\n  disabled: [other-plugin]\n"
        try original.write(to: path, atomically: true, encoding: .utf8)
        try HookRegistry.installSelectedHooks(harness: "hermes", bundledDir: source.path, home: home.path)
        let config = ConfigDocument(try String(contentsOf: path, encoding: .utf8))
        XCTAssertEqual(try config.list("enabled", in: "plugins"), ["user-plugin", "secure-agent"])
        XCTAssertEqual(try config.list("disabled", in: "plugins"), ["other-plugin"])
        XCTAssertTrue(config.text.hasPrefix("# keep comment\nmodel: keep-model"))
        try "plugins: {enabled: [user-plugin]}\n".write(to: path, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try HookRegistry.installSelectedHooks(harness: "hermes", bundledDir: source.path, home: home.path))
        XCTAssertEqual(try String(contentsOf: path, encoding: .utf8), "plugins: {enabled: [user-plugin]}\n")
        try "plugins:\n  enabled: [secure-agent]\n  disabled: {unsupported: true}\n".write(to: path, atomically: true, encoding: .utf8)
        XCTAssertFalse(HookRegistry.selectedHooksInstalled(harness: "hermes", home: home.path))
    }

    func testRefreshDoesNotReenableHermesAndUninstallPreservesUserFiles() throws {
        try HookRegistry.installSelectedHooks(harness: "hermes", bundledDir: source.path, home: home.path)
        let config = home.appendingPathComponent(".hermes/config.yaml")
        try HookRegistry.Hermes.unregister(at: config.path)
        let disabled = try Data(contentsOf: config)
        try HookRegistry.installAdditionalHooks(harness: "hermes", bundledDir: source.path, home: home.path, register: false)
        XCTAssertEqual(disabled, try Data(contentsOf: config))
        XCTAssertFalse(HookRegistry.selectedHooksInstalled(harness: "hermes", home: home.path))
        for harness in ["hermes", "opencode"] {
            try HookRegistry.installSelectedHooks(harness: harness, bundledDir: source.path, home: home.path)
            let userFile = URL(fileURLWithPath: HookRegistry.hookDirectory(harness: harness, home: home.path)).appendingPathComponent("user.txt")
            try "keep".write(to: userFile, atomically: true, encoding: .utf8)
            try HookRegistry.uninstallAdditionalPlugin(harness: harness, home: home.path)
            XCTAssertFalse(HookRegistry.selectedHooksInstalled(harness: harness, home: home.path))
            XCTAssertEqual(try String(contentsOf: userFile, encoding: .utf8), "keep")
        }
    }

    func testOpenCodeJSONCRegistrationPreservesEntriesAndBackup() throws {
        let path = home.appendingPathComponent(".config/opencode/opencode.jsonc")
        try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = "// user configuration\n{\"plugins\":[\"user-plugin\",{\"package\":\"other-plugin\",\"options\":{\"keep\":true}},],\"shell\":\"/bin/sh\",}"
        try original.write(to: path, atomically: true, encoding: .utf8)
        try HookRegistry.installSelectedHooks(harness: "opencode", bundledDir: source.path, home: home.path)
        let first = try Data(contentsOf: path)
        try HookRegistry.installSelectedHooks(harness: "opencode", bundledDir: source.path, home: home.path)
        XCTAssertEqual(first, try Data(contentsOf: path))
        XCTAssertEqual(Data(original.utf8), try Data(contentsOf: URL(fileURLWithPath: path.path + ".bak-secure-agent")))
        let root = try JSONSerialization.jsonObject(with: first) as! [String: Any]
        XCTAssertEqual(root["shell"] as? String, "/bin/sh")
        XCTAssertEqual((root["plugins"] as? [Any])?.count, 3)
        try HookRegistry.uninstallAdditionalPlugin(harness: "opencode", home: home.path)
        let after = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
        XCTAssertEqual((after["plugins"] as? [Any])?.count, 2)
    }
}
