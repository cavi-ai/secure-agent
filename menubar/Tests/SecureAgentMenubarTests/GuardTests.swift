import XCTest
@testable import SecureAgentMenubar

final class GuardTests: XCTestCase {
    func testDecodePending() throws {
        let json = #"[{"id":"p1","agent":"claude","tool":"Read","path":"/Users/x/.aws/credentials","rule_id":"cloud-creds","ts":"2026-09-01T00:00:00Z"}]"#
        let items = try JSONDecoder().decode([GuardPending].self, from: Data(json.utf8))
        XCTAssertEqual(items.first?.ruleID, "cloud-creds")
        XCTAssertEqual(items.first?.agent, "claude")
    }

    func testResolveRequestEncodesScope() throws {
        let data = try JSONEncoder().encode(GuardResolveRequest(id: "p1", verdict: "allow", scope: "always"))
        let s = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(s.contains("\"scope\":\"always\""))
        XCTAssertTrue(s.contains("\"verdict\":\"allow\""))
    }

    func testClassicsAreFourPromptRules() {
        XCTAssertEqual(SetupManager.guardClassics.map { $0.ruleID }.sorted(),
                       ["cloud-creds", "harness-config", "keychain", "ssh-keys"])
        XCTAssertTrue(SetupManager.guardClassics.allSatisfy { $0.mode == "prompt" })
    }

    // MARK: - advisor config YAML helpers

    func testAdvisorConfigEnableAppendsBlockWhenAbsent() {
        let out = SetupManager.advisorConfigUpdating("proxy_enabled: true\n", enabled: true)
        XCTAssertTrue(SetupManager.advisorConfigIsEnabled(out))
        XCTAssertTrue(out.contains("proxy_enabled: true")) // untouched
        XCTAssertTrue(out.contains("endpoint: \"http://127.0.0.1:8080\""))
    }

    func testAdvisorConfigFlipsEnabledLineOnly() {
        let yaml = "proxy_enabled: true\nadvisor:\n  enabled: false\n  endpoint: \"http://127.0.0.1:8080\"\n  model: \"qwen\"\n"
        let out = SetupManager.advisorConfigUpdating(yaml, enabled: true)
        XCTAssertTrue(SetupManager.advisorConfigIsEnabled(out))
        XCTAssertTrue(out.contains("model: \"qwen\"")) // other keys preserved
        // and flipping back works
        let off = SetupManager.advisorConfigUpdating(out, enabled: false)
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled(off))
    }

    func testAdvisorConfigMissingFileIsDisabled() {
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled(""))
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled("proxy_enabled: true\n"))
    }

    func testAdvisorConfigIgnoresKeysOutsideBlock() {
        // An `enabled:` line in another section must not count.
        let yaml = "firewall:\n  enabled: true\nadvisor:\n  enabled: false\n"
        XCTAssertFalse(SetupManager.advisorConfigIsEnabled(yaml))
    }
}
