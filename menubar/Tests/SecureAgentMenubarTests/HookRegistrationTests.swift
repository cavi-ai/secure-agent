import XCTest
@testable import SecureAgentMenubar

/// Hook install must REGISTER with the harness, then be verifiable — the
/// audited gap was files copied into ~/.claude/hooks with no settings.json
/// entry, so Claude Code never ran the guard while the UI said "installed".
final class HookRegistrationTests: XCTestCase {
    private var dir: String!
    private var settingsPath: String!
    private let command = "python3 /tmp/x/.claude/hooks/secret_guard.py"

    override func setUp() {
        super.setUp()
        dir = NSTemporaryDirectory() + "/hook-reg-\(UUID().uuidString)"
        settingsPath = dir + "/settings.json"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: dir)
        super.tearDown()
    }

    private func readSettings() throws -> [String: Any] {
        let data = FileManager.default.contents(atPath: settingsPath)!
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func testRegisterCreatesSettingsFromScratch() throws {
        try SetupManager.registerClaudeHooks(at: settingsPath, command: command)
        XCTAssertTrue(SetupManager.claudeHooksRegistered(at: settingsPath))
        let root = try readSettings()
        let hooks = root["hooks"] as? [String: Any]
        XCTAssertNotNil(hooks?["PreToolUse"])
        XCTAssertNotNil(hooks?["PostToolUse"])
    }

    func testRegisterMergesWithoutClobberingExistingSettings() throws {
        let existing = """
        {
          "model": "opus",
          "hooks": {
            "PreToolUse": [
              { "matcher": "Bash", "hooks": [ { "type": "command", "command": "my-own-hook" } ] }
            ]
          }
        }
        """
        try existing.write(toFile: settingsPath, atomically: true, encoding: .utf8)

        try SetupManager.registerClaudeHooks(at: settingsPath, command: command)

        let root = try readSettings()
        XCTAssertEqual(root["model"] as? String, "opus", "unrelated settings must survive")
        let pre = (root["hooks"] as! [String: Any])["PreToolUse"] as! [[String: Any]]
        XCTAssertEqual(pre.count, 2, "existing hook group must survive alongside ours")
        // A backup of the pre-mutation file exists.
        XCTAssertTrue(FileManager.default.fileExists(atPath: settingsPath + ".bak-secure-agent"))
    }

    func testRegisterIsIdempotent() throws {
        try SetupManager.registerClaudeHooks(at: settingsPath, command: command)
        try SetupManager.registerClaudeHooks(at: settingsPath, command: command)
        let root = try readSettings()
        let pre = (root["hooks"] as! [String: Any])["PreToolUse"] as! [[String: Any]]
        XCTAssertEqual(pre.count, 1, "re-registering must not duplicate the entry")
    }

    func testRegisterRefusesCorruptSettings() throws {
        try "not json {".write(toFile: settingsPath, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try SetupManager.registerClaudeHooks(at: settingsPath, command: command))
        // The corrupt file is untouched — never clobbered.
        let contents = try String(contentsOfFile: settingsPath, encoding: .utf8)
        XCTAssertEqual(contents, "not json {")
    }

    func testUnregisterRemovesOnlyOurs() throws {
        try SetupManager.registerClaudeHooks(at: settingsPath, command: command)
        XCTAssertTrue(SetupManager.claudeHooksRegistered(at: settingsPath))

        SetupManager.unregisterClaudeHooks(at: settingsPath)
        XCTAssertFalse(SetupManager.claudeHooksRegistered(at: settingsPath))

        let root = try readSettings()
        let pre = (root["hooks"] as! [String: Any])["PreToolUse"] as! [[String: Any]]
        XCTAssertTrue(pre.isEmpty, "our group must be gone")
    }
}
