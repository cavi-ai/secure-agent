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

/// Installed hook copies must track the bundled ones: a stale copy keeps
/// running while settings.json points at it.
final class HookRefreshTests: XCTestCase {
    private var root: String!
    private var bundled: String!
    private var installed: String!
    private let fm = FileManager.default

    override func setUp() {
        super.setUp()
        root = NSTemporaryDirectory() + "/hook-refresh-\(UUID().uuidString)"
        bundled = root + "/bundled"
        installed = root + "/installed"
        try? fm.createDirectory(atPath: bundled, withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: installed, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? fm.removeItem(atPath: root)
        super.tearDown()
    }

    private func write(_ path: String, _ text: String) {
        fm.createFile(atPath: path, contents: Data(text.utf8))
    }

    private func read(_ path: String) -> String? {
        fm.contents(atPath: path).map { String(decoding: $0, as: UTF8.self) }
    }

    func testRefreshReplacesDifferingCreatesMissingAndLeavesIdentical() throws {
        write(bundled + "/secret_guard.py", "new guard")
        write(bundled + "/same.py", "same")
        write(bundled + "/added.py", "added")
        write(bundled + "/test_secret_guard.py", "tests are not installed")
        write(installed + "/secret_guard.py", "old guard")
        write(installed + "/same.py", "same")
        let past = Date(timeIntervalSince1970: 1_000_000)
        try fm.setAttributes([.modificationDate: past], ofItemAtPath: installed + "/same.py")

        let refreshed = try SetupManager.refreshInstalledHooks(bundledDir: bundled, installedDir: installed)

        XCTAssertEqual(refreshed, ["added.py", "secret_guard.py"])
        XCTAssertEqual(read(installed + "/secret_guard.py"), "new guard")
        XCTAssertEqual(read(installed + "/added.py"), "added")
        XCTAssertEqual(read(installed + "/same.py"), "same")
        let mtime = try fm.attributesOfItem(atPath: installed + "/same.py")[.modificationDate] as? Date
        XCTAssertEqual(mtime, past, "an identical installed hook must not be rewritten")
        XCTAssertFalse(fm.fileExists(atPath: installed + "/test_secret_guard.py"))
    }

    func testRefreshNeverTouchesSettings() throws {
        write(bundled + "/secret_guard.py", "new guard")
        write(installed + "/settings.json", "{}")
        try SetupManager.refreshInstalledHooks(bundledDir: bundled, installedDir: installed)
        XCTAssertEqual(read(installed + "/settings.json"), "{}")
    }
}

/// A helper install that swaps in a different build loses the Full Disk
/// Access grant, which is bound to the previous build.
final class ESRegrantTests: XCTestCase {
    func testNeedsRegrantOnlyWhenAPreviousBuildDiffers() {
        XCTAssertTrue(SetupManager.needsRegrant(previousHash: "aaa", newHash: "bbb"))
        XCTAssertFalse(SetupManager.needsRegrant(previousHash: "aaa", newHash: "aaa"))
        XCTAssertFalse(SetupManager.needsRegrant(previousHash: nil, newHash: "bbb"), "first install is a first grant, not a re-grant")
        XCTAssertFalse(SetupManager.needsRegrant(previousHash: "", newHash: "bbb"))
        XCTAssertFalse(SetupManager.needsRegrant(previousHash: "aaa", newHash: nil))
    }

    func testRegrantResolvedWhenSpoolAdvances() {
        let installed = Date(timeIntervalSince1970: 1_000)
        XCTAssertFalse(SetupManager.regrantResolved(installSpoolMtime: installed, currentSpoolMtime: installed))
        XCTAssertTrue(SetupManager.regrantResolved(installSpoolMtime: installed, currentSpoolMtime: installed.addingTimeInterval(1)))
        XCTAssertFalse(SetupManager.regrantResolved(installSpoolMtime: installed, currentSpoolMtime: nil))
        XCTAssertTrue(SetupManager.regrantResolved(installSpoolMtime: nil, currentSpoolMtime: installed))
    }
}
