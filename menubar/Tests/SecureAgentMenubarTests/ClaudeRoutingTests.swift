import XCTest
@testable import SecureAgentMenubar

/// Routing writes into the user's own Claude Code settings: it must merge,
/// never replace a value the user set, and take back exactly what it added.
final class ClaudeRoutingTests: XCTestCase {
    private var dir: String!
    private var settingsPath: String!
    private let snippet = "/Users/x/.config/secure-agent/agent-env.sh"

    override func setUp() {
        super.setUp()
        dir = NSTemporaryDirectory() + "/claude-routing-\(UUID().uuidString)"
        settingsPath = dir + "/settings.json"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(atPath: dir)
        super.tearDown()
    }

    private func info(port: Int = 8443, token: String = "t1") -> RoutingInfo {
        let proxy = "http://inspect:\(token)@127.0.0.1:\(port)"
        return RoutingInfo(ready: true, reason: nil, env: [
            "HTTPS_PROXY": proxy, "https_proxy": proxy, "HTTP_PROXY": proxy, "http_proxy": proxy,
            "NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
            "NODE_EXTRA_CA_CERTS": "/Users/x/.config/secure-agent/ca.crt",
        ], bashEnvPath: snippet)
    }

    private func write(_ json: String) {
        FileManager.default.createFile(atPath: settingsPath, contents: Data(json.utf8))
    }

    private func readSettings() throws -> [String: Any] {
        let data = try XCTUnwrap(FileManager.default.contents(atPath: settingsPath))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func sessionStartCommands(_ root: [String: Any]) -> [String] {
        let groups = (root["hooks"] as? [String: Any])?["SessionStart"] as? [[String: Any]] ?? []
        return groups.flatMap { ($0["hooks"] as? [[String: Any]] ?? []).compactMap { $0["command"] as? String } }
    }

    func testApplyWritesEnvAndOneSessionStartHook() throws {
        try ClaudeRouting.apply(at: settingsPath, info: info())
        try ClaudeRouting.apply(at: settingsPath, info: info())
        let root = try readSettings()
        let env = try XCTUnwrap(root["env"] as? [String: String])
        XCTAssertEqual(env["HTTPS_PROXY"], "http://inspect:t1@127.0.0.1:8443")
        XCTAssertEqual(env["NODE_EXTRA_CA_CERTS"], "/Users/x/.config/secure-agent/ca.crt")
        XCTAssertEqual(env[ClaudeRouting.markerKey]?.split(separator: ",").count, 7)
        let commands = sessionStartCommands(root)
        XCTAssertEqual(commands.count, 1, "re-applying must not stack hooks")
        XCTAssertEqual(commands.first, ClaudeRouting.hookCommand(bashEnvPath: snippet))
        XCTAssertTrue(ClaudeRouting.isApplied(at: settingsPath))
    }

    /// The hook appends the snippet when Claude Code names an env file, and
    /// never fails the session start when it does not.
    func testHookCommandAppendsTheSnippet() throws {
        let snippetPath = dir + "/agent env.sh"
        FileManager.default.createFile(atPath: snippetPath, contents: Data("export HTTPS_PROXY='http://tunnel:t@127.0.0.1:8443'\n".utf8))
        let envFile = dir + "/claude-env"
        for withFile in [true, false] {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = ["-c", ClaudeRouting.hookCommand(bashEnvPath: snippetPath)]
            p.environment = withFile ? ["CLAUDE_ENV_FILE": envFile] : [:]
            try p.run()
            p.waitUntilExit()
            XCTAssertEqual(p.terminationStatus, 0)
        }
        let appended = try String(contentsOfFile: envFile, encoding: .utf8)
        XCTAssertEqual(appended, "export HTTPS_PROXY='http://tunnel:t@127.0.0.1:8443'\n")
    }

    func testReapplyReplacesOurOwnValues() throws {
        try ClaudeRouting.apply(at: settingsPath, info: info(port: 8443, token: "t1"))
        try ClaudeRouting.apply(at: settingsPath, info: info(port: 9443, token: "t2"))
        let env = try XCTUnwrap(try readSettings()["env"] as? [String: String])
        XCTAssertEqual(env["HTTPS_PROXY"], "http://inspect:t2@127.0.0.1:9443")
    }

    func testApplyRefusesToReplaceTheUsersOwnProxy() throws {
        write(#"{"env": {"HTTPS_PROXY": "http://corp.example.com:3128"}, "model": "opus"}"#)
        XCTAssertThrowsError(try ClaudeRouting.apply(at: settingsPath, info: info())) { error in
            XCTAssertEqual(error as? ClaudeRouting.RoutingError, .conflict("HTTPS_PROXY"))
        }
        let root = try readSettings()
        XCTAssertEqual((root["env"] as? [String: String])?["HTTPS_PROXY"], "http://corp.example.com:3128")
        XCTAssertFalse(ClaudeRouting.isApplied(at: settingsPath))
    }

    func testApplyRefusesWhenNotReady() {
        let notReady = RoutingInfo(ready: false, reason: "the proxy is off", env: nil, bashEnvPath: nil)
        XCTAssertThrowsError(try ClaudeRouting.apply(at: settingsPath, info: notReady)) { error in
            XCTAssertEqual(error as? ClaudeRouting.RoutingError, .notReady("the proxy is off"))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: settingsPath))
    }

    func testApplyRefusesInvalidJSON() {
        write("{not json")
        XCTAssertThrowsError(try ClaudeRouting.apply(at: settingsPath, info: info())) { error in
            XCTAssertEqual(error as? ClaudeRouting.RoutingError, .invalidJSON)
        }
    }

    /// Removal takes back our keys and hook only: the user's env keys, other
    /// SessionStart hooks and other settings stay as they were.
    func testRemoveTakesBackOnlyWhatRoutingAdded() throws {
        write(#"""
        {"env": {"FOO": "bar"},
         "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}],
                   "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "guard"}]}]},
         "model": "opus"}
        """#)
        try ClaudeRouting.apply(at: settingsPath, info: info())
        try ClaudeRouting.remove(at: settingsPath)
        let root = try readSettings()
        XCTAssertEqual(root["env"] as? [String: String], ["FOO": "bar"])
        XCTAssertEqual(sessionStartCommands(root), ["echo hi"])
        XCTAssertNotNil((root["hooks"] as? [String: Any])?["PreToolUse"])
        XCTAssertEqual(root["model"] as? String, "opus")
        XCTAssertFalse(ClaudeRouting.isApplied(at: settingsPath))
    }

    func testRemoveFromScratchLeavesNoEmptyEnv() throws {
        try ClaudeRouting.apply(at: settingsPath, info: info())
        try ClaudeRouting.remove(at: settingsPath)
        let root = try readSettings()
        XCTAssertNil(root["env"])
        XCTAssertEqual(sessionStartCommands(root), [])
    }

    func testRemoveWithoutRoutingLeavesTheFileUntouched() throws {
        let original = #"{"env": {"HTTPS_PROXY": "http://corp.example.com:3128"}}"#
        write(original)
        try ClaudeRouting.remove(at: settingsPath)
        XCTAssertEqual(String(data: FileManager.default.contents(atPath: settingsPath)!, encoding: .utf8), original)
        try ClaudeRouting.remove(at: dir + "/missing.json")
    }
}
